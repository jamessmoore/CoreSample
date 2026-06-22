# IAM audit checks

Implemented in `iam-audit-mcp/audit.py` (`IAMAuditor`). Four checks, each
its own key in the JSON returned by the `audit_iam` tool. IAM is a global
service, so these checks cover the whole account regardless of the
`region` parameter passed to the tool.

A policy-wildcard scan (`Action: "*"` / `Resource: "*"` on directly-attached
user policies) is explicitly **out of scope** for this round — see the
README's "Future expansions" section.

## Console users without MFA

**What it checks** — IAM users who have signed in with a password at
least once (`PasswordLastUsed` present on `list_users`) but have no MFA
device attached (`list_mfa_devices` returns empty).

**Why it matters** — A console password with no MFA is a single point of
failure: anyone who phishes or guesses that password gets full console
access with no second factor in the way.

**Severity** — `critical`

**Example finding**

```json
{
  "user_name": "alice",
  "severity": "critical",
  "recommendation": "Enable MFA for this console user immediately"
}
```

**Remediation** — Require the user to register a virtual or hardware MFA
device, and consider an IAM policy condition (`aws:MultiFactorAuthPresent`)
to deny console actions until they do.

## Access keys older than 90 days

**What it checks** — Active access keys whose `CreateDate` is more than 90
days in the past (`list_access_keys` per user).

**Why it matters** — Long-lived access keys widen the blast radius of a
leak — the longer a key has been valid, the more places it may have been
copied into scripts, CI config, or local `.env` files.

**Severity** — `high`

**Example finding**

```json
{
  "user_name": "alice",
  "access_key_id": "AKIAEXAMPLE00000000",
  "age_days": 137,
  "severity": "high",
  "recommendation": "Rotate this access key -- it exceeds the 90-day rotation threshold"
}
```

**Remediation** — Rotate the key: create a new one, update every consumer,
then deactivate and delete the old one. Automate rotation going forward
(e.g. AWS Secrets Manager's IAM key rotation, or a scheduled Lambda).

## Root account risk

**What it checks** — Two account-level conditions from
`get_account_summary`: root MFA not enabled (`AccountMFAEnabled != 1`),
and/or root access keys present (`AccountAccessKeysPresent`).

**Why it matters** — The root user can never be restricted by IAM policy.
A root credential compromise is the worst-case scenario for the entire
account.

**Severity** — `critical`

**Example finding**

```json
{
  "resource": "root_account",
  "issue": "Root account MFA is not enabled",
  "severity": "critical",
  "recommendation": "Enable MFA on the root account immediately -- it is the single highest-risk credential in the account"
}
```

**Remediation** — Enable MFA on the root user immediately (hardware MFA
recommended), and delete any root access keys — day-to-day and
programmatic work should always go through an IAM role or user, never
root.

## Unused credentials

**What it checks** — Passwords or active access keys with no recorded
activity in 90+ days: password via `list_users`' `PasswordLastUsed`,
access keys via `get_access_key_last_used`.

**Why it matters** — A credential nobody is using is pure liability with
no operational upside — it's an open door with no one watching to notice
if it's used maliciously.

**Severity** — `medium`

**Example finding**

```json
{
  "user_name": "alice",
  "credential_type": "access_key",
  "access_key_id": "AKIAEXAMPLE00000000",
  "last_used": "2026-02-01T00:00:00+00:00",
  "severity": "medium",
  "recommendation": "Deactivate or delete this access key if it's no longer needed"
}
```

**Remediation** — Confirm with the user/owning team whether the credential
is still needed. If not, deactivate it first (reversible) before deleting
it outright.
