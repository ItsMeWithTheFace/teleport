package auth

import (
	"context"
	"crypto/subtle"
	"fmt"

	"golang.org/x/crypto/bcrypt"

	"github.com/gravitational/trace"
	"github.com/gravitational/trace/trail"
	"github.com/sirupsen/logrus"

	"github.com/gravitational/teleport"
	"github.com/gravitational/teleport/api/client/proto"
	"github.com/gravitational/teleport/api/constants"
	"github.com/gravitational/teleport/api/types"
	apievents "github.com/gravitational/teleport/api/types/events"
	apiutils "github.com/gravitational/teleport/api/utils"
	"github.com/gravitational/teleport/lib/auth/u2f"
	"github.com/gravitational/teleport/lib/defaults"
	"github.com/gravitational/teleport/lib/events"
	"github.com/gravitational/teleport/lib/services"
	"github.com/gravitational/teleport/lib/utils"

	"github.com/pquerna/otp"
	"github.com/pquerna/otp/totp"
)

// This is bcrypt hash for password "barbaz".
var fakePasswordHash = []byte(`$2a$10$Yy.e6BmS2SrGbBDsyDLVkOANZmvjjMR890nUGSXFJHBXWzxe7T44m`)

// fakeAccountRecoveryTokenHash is bcrypt hash for "elet-barbaz x 8"
var fakeAccountRecoveryTokenHash = []byte(`$2a$10$VEiyiSIvBeoZttIi5y9cjeYRNXGrt9L46K3F1a1FZjM.U2SlfSVYq`)

// ChangePasswordWithTokenRequest defines a request to change user password
type ChangePasswordWithTokenRequest struct {
	// SecondFactorToken is 2nd factor token value
	SecondFactorToken string `json:"second_factor_token"`
	// TokenID is this token ID
	TokenID string `json:"token"`
	// Password is user password
	Password []byte `json:"password"`
	// U2FRegisterResponse is U2F registration challenge response.
	U2FRegisterResponse *u2f.RegisterChallengeResponse `json:"u2f_register_response,omitempty"`
}

// ChangePasswordWithToken changes password with a password reset token.
func (s *Server) ChangePasswordWithToken(ctx context.Context, req *proto.ChangePasswordWithTokenRequest) (*proto.ChangePasswordWithTokenResponse, error) {
	user, err := s.changePasswordWithToken(ctx, req)
	if err != nil {
		return nil, trace.Wrap(err)
	}

	cap, err := s.GetAuthPreference()
	if err != nil {
		return nil, trace.Wrap(err)
	}

	// Only local accounts with 2nd factor's gets recovery tokens.
	var recoveryTokens []string
	if cap.GetSecondFactor() != constants.SecondFactorOff && (req.SecondFactorToken != "" || req.U2FRegisterResponse != nil) {
		recoveryTokens, err = s.generateAndUpsertRecoveryTokens(ctx, user.GetName())
		if err != nil {
			return nil, trace.Wrap(err)
		}
	}

	sess, err := s.createUserWebSession(ctx, user)
	if err != nil {
		return nil, trace.Wrap(err)
	}

	// Cast WebSession interface to its struct.
	ws, ok := sess.(*types.WebSessionV2)
	if !ok {
		err := trace.BadParameter("unexpected WebSession type %T", sess)
		return nil, trail.ToGRPC(err)
	}

	return &proto.ChangePasswordWithTokenResponse{
		WebSession:     ws,
		RecoveryTokens: recoveryTokens,
	}, nil
}

// ResetPassword securely generates a new random password and assigns it to user.
// This method is used to invalidate existing user password during password
// reset process.
func (s *Server) ResetPassword(username string) (string, error) {
	user, err := s.GetUser(username, false)
	if err != nil {
		return "", trace.Wrap(err)
	}

	password, err := utils.CryptoRandomHex(defaults.ResetPasswordLength)
	if err != nil {
		return "", trace.Wrap(err)
	}

	err = s.UpsertPassword(user.GetName(), []byte(password))
	if err != nil {
		return "", trace.Wrap(err)
	}

	return password, nil
}

// ChangePassword updates users password based on the old password.
func (s *Server) ChangePassword(req services.ChangePasswordReq) error {
	ctx := context.TODO()
	// validate new password
	if err := services.VerifyPassword(req.NewPassword); err != nil {
		return trace.Wrap(err)

	}

	authPreference, err := s.GetAuthPreference()
	if err != nil {
		return trace.Wrap(err)
	}

	userID := req.User
	fn := func() error {
		secondFactor := authPreference.GetSecondFactor()
		switch secondFactor {
		case constants.SecondFactorOff:
			return s.checkPasswordWOToken(userID, req.OldPassword)
		case constants.SecondFactorOTP:
			_, err := s.checkPassword(userID, req.OldPassword, req.SecondFactorToken)
			return trace.Wrap(err)
		case constants.SecondFactorU2F:
			if req.U2FSignResponse == nil {
				return trace.AccessDenied("missing U2F sign response")
			}

			_, err := s.CheckU2FSignResponse(ctx, userID, req.U2FSignResponse)
			return trace.Wrap(err)
		case constants.SecondFactorOn:
			if req.SecondFactorToken != "" {
				_, err := s.checkPassword(userID, req.OldPassword, req.SecondFactorToken)
				return trace.Wrap(err)
			}
			if req.U2FSignResponse != nil {
				_, err := s.CheckU2FSignResponse(ctx, userID, req.U2FSignResponse)
				return trace.Wrap(err)
			}
			return trace.AccessDenied("missing second factor authentication")
		case constants.SecondFactorOptional:
			if req.SecondFactorToken != "" {
				_, err := s.checkPassword(userID, req.OldPassword, req.SecondFactorToken)
				return trace.Wrap(err)
			}
			if req.U2FSignResponse != nil {
				_, err := s.CheckU2FSignResponse(ctx, userID, req.U2FSignResponse)
				return trace.Wrap(err)
			}
			// Check that a user has no MFA devices registered.
			devs, err := s.GetMFADevices(ctx, userID)
			if err != nil && !trace.IsNotFound(err) {
				return trace.Wrap(err)
			}
			if len(devs) != 0 {
				// MFA devices registered but no MFA fields set in request.
				log.Warningf("MFA bypass attempt by user %q, access denied.", userID)
				return trace.AccessDenied("missing second factor authentication")
			}
			return nil
		}

		return trace.BadParameter("unsupported second factor method: %q", secondFactor)
	}

	if err := s.WithUserLock(userID, fn); err != nil {
		return trace.Wrap(err)
	}

	if err := s.UpsertPassword(userID, req.NewPassword); err != nil {
		return trace.Wrap(err)
	}

	if err := s.emitter.EmitAuditEvent(s.closeCtx, &apievents.UserPasswordChange{
		Metadata: apievents.Metadata{
			Type: events.UserPasswordChangeEvent,
			Code: events.UserPasswordChangeCode,
		},
		UserMetadata: apievents.UserMetadata{
			User: userID,
		},
	}); err != nil {
		log.WithError(err).Warn("Failed to emit password change event.")
	}
	return nil
}

// checkPasswordWOToken checks just password without checking OTP tokens
// used in case of SSH authentication, when token has been validated.
func (s *Server) checkPasswordWOToken(user string, password []byte) error {
	const errMsg = "invalid username or password"

	err := services.VerifyPassword(password)
	if err != nil {
		return trace.BadParameter(errMsg)
	}

	hash, err := s.GetPasswordHash(user)
	if err != nil && !trace.IsNotFound(err) {
		return trace.Wrap(err)
	}
	userFound := true
	if trace.IsNotFound(err) {
		userFound = false
		log.Debugf("Username %q not found, using fake hash to mitigate timing attacks.", user)
		hash = fakePasswordHash
	}

	if err = bcrypt.CompareHashAndPassword(hash, password); err != nil {
		log.Debugf("Password for %q does not match", user)
		return trace.BadParameter(errMsg)
	}

	// Careful! The bcrypt check above may succeed for an unknown user when the
	// provided password is "barbaz", which is what fakePasswordHash hashes to.
	if !userFound {
		return trace.BadParameter(errMsg)
	}

	return nil
}

type checkPasswordResult struct {
	mfaDev *types.MFADevice
}

// checkPassword checks the password and OTP token. Called by tsh or lib/web/*.
func (s *Server) checkPassword(user string, password []byte, otpToken string) (*checkPasswordResult, error) {
	err := s.checkPasswordWOToken(user, password)
	if err != nil {
		return nil, trace.Wrap(err)
	}

	mfaDev, err := s.checkOTP(user, otpToken)
	if err != nil {
		return nil, trace.Wrap(err)
	}
	return &checkPasswordResult{mfaDev: mfaDev}, nil
}

// checkOTP determines the type of OTP token used (for legacy HOTP support), fetches the
// appropriate type from the backend, and checks if the token is valid.
func (s *Server) checkOTP(user string, otpToken string) (*types.MFADevice, error) {
	var err error

	otpType, err := s.getOTPType(user)
	if err != nil {
		return nil, trace.Wrap(err)
	}

	switch otpType {
	case teleport.HOTP:
		otp, err := s.GetHOTP(user)
		if err != nil {
			return nil, trace.Wrap(err)
		}

		// look ahead n tokens to see if we can find a matching token
		if !otp.Scan(otpToken, defaults.HOTPFirstTokensRange) {
			return nil, trace.BadParameter("bad one time token")
		}

		// we need to upsert the hotp state again because the
		// counter was incremented
		if err := s.UpsertHOTP(user, otp); err != nil {
			return nil, trace.Wrap(err)
		}
	case teleport.TOTP:
		ctx := context.TODO()

		// get the previously used token to mitigate token replay attacks
		usedToken, err := s.GetUsedTOTPToken(user)
		if err != nil {
			return nil, trace.Wrap(err)
		}
		// we use a constant time compare function to mitigate timing attacks
		if subtle.ConstantTimeCompare([]byte(otpToken), []byte(usedToken)) == 1 {
			return nil, trace.BadParameter("previously used totp token")
		}

		devs, err := s.GetMFADevices(ctx, user)
		if err != nil {
			return nil, trace.Wrap(err)
		}

		for _, dev := range devs {
			totpDev := dev.GetTotp()
			if totpDev == nil {
				continue
			}

			if err := s.checkTOTP(ctx, user, otpToken, dev); err != nil {
				log.WithError(err).Errorf("Using TOTP device %q", dev.GetName())
				continue
			}
			return dev, nil
		}
		return nil, trace.AccessDenied("invalid totp token")
	}

	return nil, nil
}

// checkTOTP checks if the TOTP token is valid.
func (s *Server) checkTOTP(ctx context.Context, user, otpToken string, dev *types.MFADevice) error {
	if dev.GetTotp() == nil {
		return trace.BadParameter("checkTOTP called with non-TOTP MFADevice %T", dev.Device)
	}
	// we use totp.ValidateCustom over totp.Validate so we can use
	// a fake clock in tests to get reliable results
	valid, err := totp.ValidateCustom(otpToken, dev.GetTotp().Key, s.clock.Now(), totp.ValidateOpts{
		Period:    teleport.TOTPValidityPeriod,
		Skew:      teleport.TOTPSkew,
		Digits:    otp.DigitsSix,
		Algorithm: otp.AlgorithmSHA1,
	})
	if err != nil {
		return trace.AccessDenied("failed to validate TOTP code: %v", err)
	}
	if !valid {
		return trace.AccessDenied("TOTP code not valid")
	}
	// if we have a valid token, update the previously used token
	if err := s.UpsertUsedTOTPToken(user, otpToken); err != nil {
		return trace.Wrap(err)
	}

	// Update LastUsed timestamp on the device.
	dev.LastUsed = s.clock.Now()
	if err := s.UpsertMFADevice(ctx, user, dev); err != nil {
		return trace.Wrap(err)
	}
	return nil
}

// CreateSignupU2FRegisterRequest initiates registration for a new U2F token.
// The returned challenge should be sent to the client to sign.
func (s *Server) CreateSignupU2FRegisterRequest(tokenID string) (*u2f.RegisterChallenge, error) {
	cap, err := s.GetAuthPreference()
	if err != nil {
		return nil, trace.Wrap(err)
	}

	u2fConfig, err := cap.GetU2F()
	if err != nil {
		return nil, trace.Wrap(err)
	}

	_, err = s.GetResetPasswordToken(context.TODO(), tokenID)
	if err != nil {
		return nil, trace.Wrap(err)
	}

	return u2f.RegisterInit(u2f.RegisterInitParams{
		StorageKey: tokenID,
		AppConfig:  *u2fConfig,
		Storage:    s.Identity,
	})
}

// getOTPType returns the type of OTP token used, HOTP or TOTP.
// Deprecated: Remove this method once HOTP support has been removed from Gravity.
func (s *Server) getOTPType(user string) (teleport.OTPType, error) {
	_, err := s.GetHOTP(user)
	if err != nil {
		if trace.IsNotFound(err) {
			return teleport.TOTP, nil
		}
		return "", trace.Wrap(err)
	}
	return teleport.HOTP, nil
}

func (s *Server) changePasswordWithToken(ctx context.Context, req *proto.ChangePasswordWithTokenRequest) (types.User, error) {
	// Get cluster configuration and check if local auth is allowed.
	authPref, err := s.GetAuthPreference()
	if err != nil {
		return nil, trace.Wrap(err)
	}
	if !authPref.GetAllowLocalAuth() {
		return nil, trace.AccessDenied(noLocalAuth)
	}

	err = services.VerifyPassword(req.Password)
	if err != nil {
		return nil, trace.Wrap(err)
	}

	// Check if token exists.
	token, err := s.GetResetPasswordToken(ctx, req.TokenID)
	if err != nil {
		return nil, trace.Wrap(err)
	}

	if token.Expiry().Before(s.clock.Now().UTC()) {
		return nil, trace.BadParameter("expired token")
	}

	err = s.changeUserSecondFactor(req, token)
	if err != nil {
		return nil, trace.Wrap(err)
	}

	username := token.GetUser()
	// Delete this token first to minimize the chances
	// of partially updated user with still valid token.
	err = s.deleteResetPasswordTokens(ctx, username)
	if err != nil {
		return nil, trace.Wrap(err)
	}

	// Set a new password.
	err = s.UpsertPassword(username, req.Password)
	if err != nil {
		return nil, trace.Wrap(err)
	}

	user, err := s.GetUser(username, false)
	if err != nil {
		return nil, trace.Wrap(err)
	}

	return user, nil
}

func (s *Server) generateAndUpsertRecoveryTokens(ctx context.Context, username string) ([]string, error) {
	// TODO lisa, make as receive func?
	tokens, err := types.GenerateRecoveryTokens()
	if err != nil {
		return nil, trace.Wrap(err)
	}

	hashedTokens := make([]types.AccountRecoveryToken, len(tokens))
	for i, token := range tokens {
		hashedToken, err := bcrypt.GenerateFromPassword([]byte(token), bcrypt.DefaultCost)
		if err != nil {
			return nil, trace.Wrap(err)
		}

		hashedTokens[i].Value = hashedToken
	}

	// TODO lisa, does it have to be a  pointer?
	rc := types.NewRecoveryTokens(hashedTokens)
	rc.Created = s.GetClock().Now().UTC()

	if err := s.UpsertRecoveryTokens(ctx, username, *rc); err != nil {
		return nil, trace.Wrap(err)
	}

	if err := s.emitter.EmitAuditEvent(s.closeCtx, &apievents.RecoveryTokenGenerate{
		Metadata: apievents.Metadata{
			Type: events.RecoveryTokenGeneratedEvent,
			Code: events.RecoveryTokenGeneratedCode,
		},
		UserMetadata: apievents.UserMetadata{
			User: username,
		},
	}); err != nil {
		log.WithError(err).WithFields(logrus.Fields{"user": username}).Warn("Failed to emit recovery tokens generate event.")
	}

	return tokens, nil
}

func (s *Server) changeUserSecondFactor(req *proto.ChangePasswordWithTokenRequest, token types.ResetPasswordToken) error {
	username := token.GetUser()
	cap, err := s.GetAuthPreference()
	if err != nil {
		return trace.Wrap(err)
	}

	ctx := context.TODO()
	secondFactor := cap.GetSecondFactor()
	if secondFactor == constants.SecondFactorOff {
		return nil
	}
	if req.SecondFactorToken != "" {
		if secondFactor == constants.SecondFactorU2F {
			return trace.BadParameter("user %q sent an OTP token during password reset but cluster only allows U2F for second factor", username)
		}
		secrets, err := s.Identity.GetResetPasswordTokenSecrets(ctx, req.TokenID)
		if err != nil {
			return trace.Wrap(err)
		}

		dev, err := services.NewTOTPDevice("otp", secrets.GetOTPKey(), s.clock.Now())
		if err != nil {
			return trace.Wrap(err)
		}
		if err := s.checkTOTP(ctx, username, req.SecondFactorToken, dev); err != nil {
			return trace.Wrap(err)
		}
		if err := s.UpsertMFADevice(ctx, username, dev); err != nil {
			return trace.Wrap(err)
		}

		return nil
	}
	if req.U2FRegisterResponse != nil {
		if secondFactor == constants.SecondFactorOTP {
			return trace.BadParameter("user %q sent a U2F registration during password reset but cluster only allows OTP for second factor", username)
		}
		cfg, err := cap.GetU2F()
		if err != nil {
			return trace.Wrap(err)
		}

		_, err = u2f.RegisterVerify(ctx, u2f.RegisterVerifyParams{
			DevName:                "u2f",
			ChallengeStorageKey:    req.TokenID,
			RegistrationStorageKey: username,
			Resp: u2f.RegisterChallengeResponse{
				RegistrationData: req.GetU2FRegisterResponse().GetRegistrationData(),
				ClientData:       req.GetU2FRegisterResponse().GetClientData(),
			},
			Storage:        s.Identity,
			Clock:          s.GetClock(),
			AttestationCAs: cfg.DeviceAttestationCAs,
		})
		return trace.Wrap(err)
	}

	if secondFactor != constants.SecondFactorOptional {
		return trace.BadParameter("no second factor sent during user %q password reset", username)
	}
	return nil
}

// VerifyAccountRecoveryToken verifies a given recovery token with a user's auth creds.
func (s *Server) VerifyAccountRecoveryToken(ctx context.Context, req *proto.VerifyRecoveryTokenRequest) (types.ResetPasswordToken, error) {
	if req.GetUsername() == "" || req.GetRecoveryToken() == nil {
		return nil, trace.BadParameter("missing username or recovery token")
	}

	if req.GetPassword() == nil && req.GetSecondFactorToken() == "" && req.U2FSignResponse == nil {
		return nil, trace.BadParameter("at least one authentication method is required")
	}

	if err := s.isAccountRecoveryAllowed(); err != nil {
		return nil, trace.Wrap(err)
	}

	var authErr error
	switch {
	case len(req.Password) > 0:
		authErr = s.withAccountRecoveryLock(ctx, req.GetRecoveryToken(), req.GetUsername(), func() error {
			return s.checkPasswordWOToken(req.Username, req.Password)
		})
	case req.U2FSignResponse != nil:
		authErr = s.withAccountRecoveryLock(ctx, req.GetRecoveryToken(), req.GetUsername(), func() error {
			_, err := s.CheckU2FSignResponse(ctx, req.Username, &u2f.AuthenticateChallengeResponse{
				KeyHandle:     req.U2FSignResponse.GetKeyHandle(),
				SignatureData: req.U2FSignResponse.GetSignature(),
				ClientData:    req.U2FSignResponse.GetClientData(),
			})

			return err
		})
	case req.GetSecondFactorToken() != "":
		authErr = s.withAccountRecoveryLock(ctx, req.GetRecoveryToken(), req.GetUsername(), func() error {
			_, err := s.checkOTP(req.GetUsername(), req.GetSecondFactorToken())
			return err
		})
	}

	if authErr != nil {
		return nil, trace.Wrap(authErr)
	}

	// Create a reset password token for auth when user re-sets their creds as next step.
	tokenRequest := CreateResetPasswordTokenRequest{Name: req.Username, Type: ResetPasswordTokenTypeRecovery}
	if err := tokenRequest.CheckAndSetDefaults(); err != nil {
		return nil, trace.Wrap(err)
	}

	// Create a token for auth when user re-sets their password as next step in recovery flow.
	// Setting the subkind allows us to differentiate a reset password token from a reset password token for account recovery.
	token, err := s.newResetPasswordToken(tokenRequest)
	token.SetSubKind(types.KindRecoveryToken)

	// Remove any other existing tokens for this user.
	if err = s.deleteResetPasswordTokens(ctx, req.Username); err != nil {
		return nil, trace.Wrap(err)
	}

	if _, err := s.Identity.CreateResetPasswordToken(ctx, token); err != nil {
		return nil, trace.Wrap(err)
	}

	if err := s.emitter.EmitAuditEvent(ctx, &apievents.ResetPasswordTokenCreate{
		Metadata: apievents.Metadata{
			Type: events.ResetPasswordTokenCreateEvent,
			Code: events.ResetPasswordTokenCreateCode,
		},
		UserMetadata: apievents.UserMetadata{
			User: ClientUsername(ctx),
		},
		ResourceMetadata: apievents.ResourceMetadata{
			Name:    tokenRequest.Name,
			TTL:     tokenRequest.TTL.String(),
			Expires: s.GetClock().Now().UTC().Add(tokenRequest.TTL),
		},
	}); err != nil {
		log.WithError(err).Warn("Failed to emit create reset password token for account recovery event.")
	}

	return s.GetResetPasswordToken(ctx, token.GetName())
}

func (s *Server) verifyAccountRecoveryToken(ctx context.Context, user string, givenToken []byte, authenticateFn func() error) error {
	authErr := authenticateFn()
	if authErr != nil {
		log.WithError(authErr).Debugf("Failed to authenticate user %q for account recovery.", user)
	}

	// TODO lisa: if a username and recovery token is valid, but wrong password, should the valid token be marked used?
	// Currently what it's doing.
	rt, err := s.GetRecoveryTokens(ctx, user)
	if err != nil && !trace.IsNotFound(err) {
		return trace.Wrap(err)
	}

	var hashedTokens []types.AccountRecoveryToken
	if err == nil {
		hashedTokens = rt.GetTokens()
	}

	userFound := true
	if trace.IsNotFound(err) {
		userFound = false
		log.Debugf("Account recovery tokens for user %q not found, using fake hashes to mitigate timing attacks.", user)
		hashedTokens = []types.AccountRecoveryToken{{Value: fakeAccountRecoveryTokenHash}, {Value: fakeAccountRecoveryTokenHash}, {Value: fakeAccountRecoveryTokenHash}}
	}

	tokenMatch := false
	for i, token := range hashedTokens {
		if err = bcrypt.CompareHashAndPassword(token.Value, givenToken); err == nil {
			if !token.IsUsed && userFound {
				tokenMatch = true
				// Mark matched token as used in backend so it can't be used again.
				rt.Tokens[i].IsUsed = true
				if err := s.UpsertRecoveryTokens(ctx, user, *rt); err != nil {
					return trace.Wrap(err)
				}
			}
		}
	}

	event := &apievents.RecoveryTokenUsed{
		Metadata: apievents.Metadata{
			Type: events.RecoveryTokenUsedEvent,
			Code: events.RecoveryTokenUsedCode,
		},
		UserMetadata: apievents.UserMetadata{
			User: user,
		},
		Status: apievents.Status{
			Success: true,
		},
	}

	if !tokenMatch || !userFound || authErr != nil {
		event.Status.Success = false
		var traceErr trace.Error

		if !tokenMatch && userFound {
			traceErr = trace.BadParameter("account recovery tokens did not match")
			event.Status.Error = traceErr.Error()
			event.Status.UserMessage = traceErr.Error()
		}

		if !userFound {
			traceErr = trace.BadParameter("bad auth credentials")
			event.Status.Error = traceErr.Error()
			event.Status.UserMessage = traceErr.Error()
		}

		if authErr != nil {
			traceErr = trace.Wrap(authErr)
			event.Status.Error = trace.Unwrap(authErr).Error()
			event.Status.UserMessage = authErr.Error()
		}

		if err := s.emitter.EmitAuditEvent(s.closeCtx, event); err != nil {
			log.WithFields(logrus.Fields{"user": user}).Warn("Failed to emit account recovery token used failed event.")
		}

		return traceErr
	}

	if err := s.emitter.EmitAuditEvent(s.closeCtx, event); err != nil {
		log.WithFields(logrus.Fields{"user": user}).Warn("Failed to emit account recovery token used event.")
	}

	return nil
}

// withAccountRecoveryLock is a replica of WithUserLock but for account recovery attempts.
func (a *Server) withAccountRecoveryLock(ctx context.Context, recoveryToken []byte, username string, authenticateFn func() error) error {
	user, err := a.GetUser(username, false)
	if err != nil {
		if trace.IsNotFound(err) {
			// If user is not found, still call authenticateFn.
			// It should always return an error. This prevents username oracles and timing attacks.
			return a.verifyAccountRecoveryToken(ctx, username, recoveryToken, authenticateFn)
		}
		return trace.Wrap(err)
	}

	status := user.GetAccountRecoveryStatus()
	if status.IsLocked && status.LockExpires.After(a.clock.Now().UTC()) {
		return trace.AccessDenied("%v exceeds %v failed account recovery attempts, locked until %v",
			user.GetName(), types.MaxAccountRecoveryAttempts, apiutils.HumanTimeFormat(status.LockExpires))
	}

	fnErr := a.verifyAccountRecoveryToken(ctx, username, recoveryToken, authenticateFn)
	if fnErr == nil {
		// Upon successful verifying recovery token, reset the failed attempt counter.
		err = a.DeleteAccountRecoveryAttempts(username)
		if !trace.IsNotFound(err) {
			return trace.Wrap(err)
		}

		return nil
	}

	// do not lock user in case if DB is flaky or down
	if trace.IsConnectionProblem(err) {
		return trace.Wrap(fnErr)
	}

	// log failed attempt and possibly lock user
	attempt := types.RecoveryAttempt{Time: a.clock.Now().UTC(), Success: false}
	if err := a.AddAccountRecoveryAttempt(username, attempt, defaults.AttemptTTL); err != nil {
		log.Error(trace.DebugReport(err))
		return trace.Wrap(fnErr)
	}

	recoveryAttempts, err := a.GetAccountRecoveryAttempts(username)
	if err != nil {
		log.Error(trace.DebugReport(err))
		return trace.Wrap(fnErr)
	}

	if !types.LastFailed(types.MaxAccountRecoveryAttempts, recoveryAttempts) {
		log.Debugf("%v user has less than %v failed account recovery attempts", username, types.MaxAccountRecoveryAttempts)
		return trace.Wrap(fnErr)
	}

	lockedAt := a.clock.Now().UTC()
	lockUntil := lockedAt.Add(defaults.AccountLockInterval)
	message := fmt.Sprintf("%v exceeds %v failed account recovery attempts, locked until %v",
		username, types.MaxAccountRecoveryAttempts, apiutils.HumanTimeFormat(status.LockExpires))

	log.Debug(message)
	user.SetAccountRecoveryLocked(lockedAt, lockUntil, "user has exceeded maximum failed account recovery attempts")

	if err := a.Identity.UpsertUser(user); err != nil {
		log.Error(trace.DebugReport(err))
		return trace.Wrap(fnErr)
	}

	return trace.AccessDenied(message)
}

// RecoverPasswordOrSecondFactor TODO
func (s *Server) RecoverPasswordOrSecondFactor(ctx context.Context, req *proto.ChangePasswordWithTokenRequest) (*proto.ChangePasswordWithTokenResponse, error) {
	if req.GetTokenID() == "" {
		return nil, trace.BadParameter("invalid token")
	}

	if req.GetPassword() == nil && req.GetSecondFactorToken() == "" && req.GetU2FRegisterResponse() == nil {
		return nil, trace.BadParameter("no authentication creds to re-set")
	}

	token, err := s.GetResetPasswordToken(ctx, req.GetTokenID())
	if err != nil {
		return nil, trace.Wrap(err)
	}

	if token.GetSubKind() != types.KindRecoveryToken {
		return nil, trace.BadParameter("invalid token")
	}

	if token.Expiry().Before(s.clock.Now().UTC()) {
		return nil, trace.BadParameter("expired token")
	}

	username := token.GetUser()

	// Delete this token first to minimize the chances
	// of partially updated user with still valid token.
	err = s.deleteResetPasswordTokens(ctx, username)
	if err != nil {
		return nil, trace.Wrap(err)
	}

	if req.GetPassword() != nil {
		// Set a new password.
		if err := s.UpsertPassword(username, req.Password); err != nil {
			return nil, trace.Wrap(err)
		}
	} else {
		// Delete all mfa devices.
		if err := s.resetMFA(ctx, username); err != nil {
			return nil, trace.Wrap(err)
		}

		// Set the new second factor.
		if err := s.changeUserSecondFactor(req, token); err != nil {
			return nil, trace.Wrap(err)
		}
	}

	recoveryTokens, err := s.generateAndUpsertRecoveryTokens(ctx, username)
	if err != nil {
		return nil, trace.Wrap(err)
	}

	return &proto.ChangePasswordWithTokenResponse{
		RecoveryTokens: recoveryTokens,
	}, nil
}

// isAccountRecoveryAllowed gets cluster auth configuration and check if local auth
// and second factor is allowed, which are required for account recovery.
func (s *Server) isAccountRecoveryAllowed() error {
	authPref, err := s.GetAuthPreference()
	if err != nil {
		return trace.Wrap(err)
	}

	if !authPref.GetAllowLocalAuth() {
		return trace.AccessDenied(noLocalAuth)
	}

	if authPref.GetSecondFactor() == constants.SecondFactorOff {
		return trace.AccessDenied("second factor disabled")
	}

	return nil
}
