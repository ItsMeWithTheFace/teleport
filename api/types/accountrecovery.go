/**
 * Copyright 2021 Gravitational, Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package types

import (
	"bytes"
	"strings"
	"time"

	"github.com/gogo/protobuf/jsonpb"
	"github.com/gravitational/trace"
	"github.com/sethvargo/go-diceware/diceware"
)

const NumOfRecoveryTokens = 3
const MaxAccountRecoveryAttempts = 3
const MaxAccountRecoveryTokenTTL = 1 * time.Hour
const numWordsInRecoveryToken = 8

// NewRecoveryTokens creates a new AccountRecovery with the given tokens.
// Caller must set the Created field.
func NewRecoveryTokens(tokens []AccountRecoveryToken) *AccountRecovery {
	return &AccountRecovery{
		Kind:    KindRecoveryToken,
		Version: V1,
		Tokens:  tokens,
	}
}

// CheckAndSetDefaults validates RecoveryTokens fields and populates empty fields
// with default values.
func (t *AccountRecovery) CheckAndSetDefaults() error {
	if t.Kind == "" {
		return trace.BadParameter("RecoveryTokens missing Kind field")
	}

	if t.Version == "" {
		t.Version = V1
	}

	if t.Tokens == nil || len(t.Tokens) < NumOfRecoveryTokens {
		return trace.BadParameter("RecoveryTokens is either missing Tokens field or there are incorrect amount of tokens.")
	}

	if t.Created.IsZero() {
		return trace.BadParameter("RecoveryTokens missing Created field")
	}

	return nil
}

func (t *AccountRecovery) GetKind() string                   { return t.Kind }
func (t *AccountRecovery) GetVersion() string                { return t.Version }
func (t *AccountRecovery) GetTokens() []AccountRecoveryToken { return t.Tokens }
func (t *AccountRecovery) SetCreation(created time.Time)     { t.Created = created }

func (t *AccountRecovery) MarshalJSON() ([]byte, error) {
	buf := new(bytes.Buffer)
	err := (&jsonpb.Marshaler{}).Marshal(buf, t)

	return buf.Bytes(), trace.Wrap(err)
}

func (t *AccountRecovery) UnmarshalJSON(buf []byte) error {
	return jsonpb.Unmarshal(bytes.NewReader(buf), t)
}

func GenerateRecoveryTokens() ([]string, error) {
	gen, err := diceware.NewGenerator(nil)
	if err != nil {
		return nil, trace.Wrap(err)
	}

	tokenList := make([]string, NumOfRecoveryTokens)
	for i := 0; i < NumOfRecoveryTokens; i++ {
		list, err := gen.Generate(numWordsInRecoveryToken)
		if err != nil {
			return nil, trace.Wrap(err)
		}

		tokenList[i] = "tele-" + strings.Join(list, "-")
	}

	return tokenList, nil
}

// RecoveryAttempt represents successful or unsuccessful attempt for user's account recovery.
type RecoveryAttempt struct {
	// Time is time of the attempt.
	Time time.Time `json:"time"`
	// Success indicates whether attempt was successful.
	Success bool `json:"success"`
}

// SortedRecoveryAttempts sorts recovery attempts by time.
type SortedRecoveryAttempts []RecoveryAttempt

// Len returns the length of recovery attempt list.
func (s SortedRecoveryAttempts) Len() int {
	return len(s)
}

// Less stacks latest attempts to the end of the list.
func (s SortedRecoveryAttempts) Less(i, j int) bool {
	return s[i].Time.Before(s[j].Time)
}

// Swap swaps two attempts.
func (s SortedRecoveryAttempts) Swap(i, j int) {
	s[i], s[j] = s[j], s[i]
}

// LastFailed calculates last x successive attempts are failed.
func LastFailed(x int, attempts []RecoveryAttempt) bool {
	var failed int
	for i := len(attempts) - 1; i >= 0; i-- {
		if !attempts[i].Success {
			failed++
		} else {
			return false
		}
		if failed >= x {
			return true
		}
	}
	return false
}
