---------------------------- MODULE CognitoSafety ----------------------------
\* TLA+ specification for the same state machine the Python runner
\* `temporal_check.py` enumerates. Boolean configuration knobs;
\* each step flips one. Safety invariants checked at every reachable
\* state.
\*
\* Run with TLC:
\*   curl -fsSL -o tla2tools.jar \
\*     https://github.com/tlaplus/tlaplus/releases/latest/download/tla2tools.jar
\*   java -cp tla2tools.jar tlc2.TLC CognitoSafety.tla -config CognitoSafety.cfg
\*
\* The Python runner is the foundational path for the example; this
\* spec is here for organisations that want temporal-property
\* verification (eventually-safe, infinitely-often-detected, etc.)
\* on top of the boolean state-space search.

EXTENDS Naturals

VARIABLES
    unauth_enabled,
    self_reg_open,
    auth_role_broad,
    unauth_role_broad,
    data_logging,
    scp_applied,
    mfa_required

vars == <<unauth_enabled, self_reg_open, auth_role_broad,
          unauth_role_broad, data_logging, scp_applied, mfa_required>>

\* Initial state matches the Cognito writeup-config fixture:
\* unauthenticated open, self-registration open, auth role broad,
\* logging off, no SCP, no MFA.
Init ==
    /\ unauth_enabled = TRUE
    /\ self_reg_open = TRUE
    /\ auth_role_broad = TRUE
    /\ unauth_role_broad = FALSE
    /\ data_logging = FALSE
    /\ scp_applied = FALSE
    /\ mfa_required = FALSE

\* One-knob toggles.
ToggleUnauth ==
    /\ unauth_enabled' = ~unauth_enabled
    /\ UNCHANGED <<self_reg_open, auth_role_broad, unauth_role_broad,
                   data_logging, scp_applied, mfa_required>>

ToggleSelfReg ==
    /\ self_reg_open' = ~self_reg_open
    /\ UNCHANGED <<unauth_enabled, auth_role_broad, unauth_role_broad,
                   data_logging, scp_applied, mfa_required>>

ToggleAuthRoleBroad ==
    /\ auth_role_broad' = ~auth_role_broad
    /\ UNCHANGED <<unauth_enabled, self_reg_open, unauth_role_broad,
                   data_logging, scp_applied, mfa_required>>

ToggleUnauthRoleBroad ==
    /\ unauth_role_broad' = ~unauth_role_broad
    /\ UNCHANGED <<unauth_enabled, self_reg_open, auth_role_broad,
                   data_logging, scp_applied, mfa_required>>

ToggleLogging ==
    /\ data_logging' = ~data_logging
    /\ UNCHANGED <<unauth_enabled, self_reg_open, auth_role_broad,
                   unauth_role_broad, scp_applied, mfa_required>>

ToggleSCP ==
    /\ scp_applied' = ~scp_applied
    /\ UNCHANGED <<unauth_enabled, self_reg_open, auth_role_broad,
                   unauth_role_broad, data_logging, mfa_required>>

ToggleMFA ==
    /\ mfa_required' = ~mfa_required
    /\ UNCHANGED <<unauth_enabled, self_reg_open, auth_role_broad,
                   unauth_role_broad, data_logging, scp_applied>>

Next ==
    \/ ToggleUnauth
    \/ ToggleSelfReg
    \/ ToggleAuthRoleBroad
    \/ ToggleUnauthRoleBroad
    \/ ToggleLogging
    \/ ToggleSCP
    \/ ToggleMFA

\* Safety invariants (mirror temporal_check.py).
NoAnonBroadAccess ==
    ~(unauth_enabled /\ unauth_role_broad)

NoSelfRegBroadAccessWithoutMFA ==
    ~(self_reg_open /\ auth_role_broad /\ ~mfa_required)

NoBroadAccessWithoutLogging ==
    ~(auth_role_broad /\ ~data_logging)

NoBroadAccessWithoutSCP ==
    ~(auth_role_broad /\ ~scp_applied)

SafetyInvariant ==
    /\ NoAnonBroadAccess
    /\ NoSelfRegBroadAccessWithoutMFA
    /\ NoBroadAccessWithoutLogging
    /\ NoBroadAccessWithoutSCP

Spec == Init /\ [][Next]_vars

=============================================================================
