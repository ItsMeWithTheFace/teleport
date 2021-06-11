---
authors: Andrej Tokarčík (andrej@goteleport.com)
state: draft
---

# RFD XX - Session Locking

## What

This RFD provides a locking mechanism to restrict access to a Teleport
environment.  When such a session lock is in force:
+ any existing sessions matching the lock's conditions are terminated, and
+ creation of new sessions matching the lock's conditions is prevented.

## Why

Security teams require greater control over a session once it's started in
order to be able to:
+ lock out the team during maintenance windows,
+ terminate access for a user prior to hitting the Teleport certificate's TTL,
+ achieve FedRAMP/NIST compliance.

## Details

### `SessionLock` resource

A new resource named `SessionLock` with the following specification is introduced:

```proto
message SessionLockSpecV2 {
    // Target describes the set of sessions to which the session lock applies once effective.
    SessionLockTarget Target = 1 [ (gogoproto.nullable) = false, (gogoproto.jsontag) = "target" ];
    // Message is the message displayed to locked-out users.
    string Message = 2 [ (gogoproto.jsontag) = "message,omitempty" ];
    // EffectiveFrom is the time point at which the session lock comes into force.
    // If left unset, the lock is effective immediately.
    google.protobuf.Timestamp EffectiveFrom = 3 [
        (gogoproto.stdtime) = true,
        (gogoproto.nullable) = true,
        (gogoproto.jsontag) = "effective_from,omitempty"
    ];
}

// SessionLockTarget lists the attributes of a session all of which (when set)
// must match for the lock to apply to the session.
// The attributes are interpreted/matched qua simple names, with no support for
// wildcards of regular expressions.
message SessionLockTarget {
    // User specifies the name of a Teleport user.
    string User = 1 [ (gogoproto.jsontag) = "user,omitempty" ];
    // Role specifies the name of a RBAC role.
    string Role = 2 [ (gogoproto.jsontag) = "role,omitempty" ];
    // Cluster specifies the name of a Teleport cluster.
    string Cluster = 3 [ (gogoproto.jsontag) = "cluster,omitempty" ];
    // Login specifies the name of a local UNIX user.
    string Login = 4 [ (gogoproto.jsontag) = "login,omitempty" ];
}
```

This approach allows to specify locks for entities that are only yet to exist
or exist merely transiently (such as SSO user objects).  It could also help
with alleviating the load associated with caching/replicating `User` resources.

#### Expiration & audit

There is no explicit expiry field in `SessionLockSpecV2`.  The common `Metadata.Expires`
field is used instead.

Since the `Metadata.Expires` field is also used by the backends to delete stale
data, this automatically guarantees no expired `SessionLocks` will be returned
by methods like `GetSessionLocks`, which in turn implies only unexpired locks
can ever be presented to the user in summary outputs.

Historical records related to the `SessionLock` records can thus be
reconstructed only from the audit log. Every `SessionLock` create/update/delete
should emit an audit event.

#### Multiplicity

`SessionLock` is not a singleton resource: when there are multiple
`SessionLock`s stored (and in force), it suffices for a session to be matched
by any one of the locks to be terminated/disabled.

If the conditions encoded by a set of `SessionLock`s was to be expressed in a
single logical formula, the conditions within `SessionLockTarget` would be connected
with logical conjunction while those of multiple `SessionLock`s would be connected
with logical disjunction.  This is similar to the notion of _disjunctive normal form_
of propositional logic.

#### `tctl` support

`SessionLock` resources can be managed using `tctl {get,create,rm}`.  In this
way, it is possible to update (e.g. delay) or remove a session lock after it
has been created.

There will be a special `tctl sessions lock` helper provided, to facilitate
supplying time information when creating new `SessionLock`s, see Scenarios below.

#### Status of `User.Status`

Related to user locking, there already exists a `Status` field of the `User` resource
that is used in connection with failed Web UI login attempts.

This field (and its `LoginStatus` definition) is superseded by `SessionLock`.
All of its use cases should be converted to `SessionLock`.

### Disabling new certificates

In `srv.AuthHandlers`, after the certificate has been validated, the relevant
existing `SessionLock`s are checked. If any of them applies, the connection
will be terminated.

### Terminating existing sessions

Terminating an existing session due to a (newly introduced) session lock is
similar to terminating an existing session due to certificate expiry.  The
support for the latter is covered by `srv.Monitor` and its `Start` routine.

In order to make `srv.Monitor` keep track of all the `SessionLock`s without
periodically polling the backend, two new fields are added to `srv.MonitorConfig`:
+ `StoredSessionLocks`: a slice of `SessionLock`s known at the time of calling
  `srv.NewMonitor`;
+ `SessionLockWatcher`: a `types.Watcher` detecting additional puts or deletes
  of `SessionLock`s pertaining to the current session.

The developed logic should work with all the proxies that already refer to
`DisconnectExpiredCert`, i.e. SSH, k8s and DB.

### Replicating to trusted clusters

`SessionLock` resources are replicated from the root cluster to leaf clusters
in a similar manner to how CAs are shared between trusted clusters.

The goal should be achieved by introducing a routine similar to
`periodicUpdateCertAuthorities`. However instead of polling the backend (with
the default period of 10 minutes defined in `defaults.LowResPollingPeriod`)
`types.Watcher`-based logic should be preferred.

To be able to distinguish a session lock provided from an external source
(i.e. the root cluster in this context), an indication should be stored in the
`Metadata.Description` field of the `SessionLock` being sent.

### Scenarios

#### Permanent locking

```
$ tctl sessions lock --user=foo@example.com --message="Suspicious activity."
Created lock with ID "dc7cee9d-fe5e-4534-a90d-db770f0234a1".
```

This locks out `foo@example.com` without automatic expiration.
The lock can be lifted by `tctl rm lock/dc7cee9d-fe5e-4534-a90d-db770f0234a1`.

The locking command above would be equivalent to:
```
$ tctl create <<EOF
kind: session_lock
metadata:
  name: dc7cee9d-fe5e-4534-a90d-db770f0234a1
spec:
  message: "Suspicious activity."
  target:
    user: foo@example.com
version: v2
EOF
```

The showed YAML would also correspond to the output of `tctl get lock/dc7cee9d-fe5e-4534-a90d-db770f0234a1`.
