"""IAM audit checks: console users without MFA, stale access keys, root
account risk, and unused credentials.

Unlike a policy-wildcard scan (deferred -- see README "Future expansions"),
every check here only needs `iam:List*`/`iam:Get*` read calls, no
`iam:GetLoginProfile` or policy-document fetches. Console access is
inferred from `list_users`' `PasswordLastUsed` field (present once a user
has ever signed in with a password) rather than a per-user
`get_login_profile` call -- one fewer API call per user, and it keeps the
task role's policy scoped to exactly the five actions in terraform/iam.tf.

Like EC2Auditor, this auditor never accepts AWS credentials as input. It
always uses boto3's default credential resolution, which inside AWS means
the Fargate task's IAM role -- the audited account's credentials never
leave the account boundary, and no caller (including the LLM) can hand it
different credentials than the ones it was deployed with.
"""

import boto3
from datetime import datetime, timedelta, timezone
from typing import List, Dict, Any

STALE_THRESHOLD = timedelta(days=90)


class IAMAuditor:
    def __init__(self, region: str):
        # IAM is a global service -- region has no effect on the API calls
        # below -- but the parameter is kept for interface consistency with
        # EC2Auditor (see main.py's audit_iam docstring).
        self.client = boto3.client("iam", region_name=region)

    def audit(self) -> Dict[str, Any]:
        """Run full IAM audit and return findings."""
        findings = {
            "console_users_without_mfa": self._find_users_without_mfa(),
            "old_access_keys": self._find_old_access_keys(),
            "root_account_risk": self._check_root_account_risk(),
            "unused_credentials": self._find_unused_credentials(),
            "summary": {},
        }

        findings["summary"] = {
            "total_findings": sum(
                len(v) if isinstance(v, list) else 0
                for v in findings.values()
                if v != findings["summary"]
            ),
            "critical": self._count_severity(findings, "critical"),
            "high": self._count_severity(findings, "high"),
        }

        return findings

    def _find_users_without_mfa(self) -> List[Dict[str, Any]]:
        """Find console users (have signed in with a password at least
        once) with no MFA device attached."""
        response = self.client.list_users()

        findings = []
        for user in response["Users"]:
            if "PasswordLastUsed" not in user:
                continue  # never signed in with a password -- not a console user

            username = user["UserName"]
            mfa_response = self.client.list_mfa_devices(UserName=username)
            if not mfa_response["MFADevices"]:
                findings.append(
                    {
                        "user_name": username,
                        "severity": "critical",
                        "recommendation": "Enable MFA for this console user immediately",
                    }
                )

        return findings

    def _find_old_access_keys(self) -> List[Dict[str, Any]]:
        """Find active access keys past the 90-day rotation threshold."""
        now = datetime.now(timezone.utc)
        response = self.client.list_users()

        findings = []
        for user in response["Users"]:
            username = user["UserName"]
            keys_response = self.client.list_access_keys(UserName=username)
            for key in keys_response["AccessKeyMetadata"]:
                if key["Status"] != "Active":
                    continue

                age = now - key["CreateDate"]
                if age > STALE_THRESHOLD:
                    findings.append(
                        {
                            "user_name": username,
                            "access_key_id": key["AccessKeyId"],
                            "age_days": age.days,
                            "severity": "high",
                            "recommendation": "Rotate this access key -- it exceeds the 90-day rotation threshold",
                        }
                    )

        return findings

    def _check_root_account_risk(self) -> List[Dict[str, Any]]:
        """Flag root account MFA gaps and/or root access keys."""
        response = self.client.get_account_summary()
        summary_map = response["SummaryMap"]

        findings = []
        if summary_map.get("AccountMFAEnabled") != 1:
            findings.append(
                {
                    "resource": "root_account",
                    "issue": "Root account MFA is not enabled",
                    "severity": "critical",
                    "recommendation": "Enable MFA on the root account immediately -- it is the single highest-risk credential in the account",
                }
            )

        if summary_map.get("AccountAccessKeysPresent"):
            findings.append(
                {
                    "resource": "root_account",
                    "issue": "Root account has active access keys",
                    "severity": "critical",
                    "recommendation": "Delete root access keys -- the root user should never have programmatic credentials",
                }
            )

        return findings

    def _find_unused_credentials(self) -> List[Dict[str, Any]]:
        """Find passwords or access keys with no activity in 90+ days."""
        now = datetime.now(timezone.utc)
        response = self.client.list_users()

        findings = []
        for user in response["Users"]:
            username = user["UserName"]

            password_last_used = user.get("PasswordLastUsed")
            if password_last_used and (now - password_last_used) > STALE_THRESHOLD:
                findings.append(
                    {
                        "user_name": username,
                        "credential_type": "password",
                        "last_used": password_last_used.isoformat(),
                        "severity": "medium",
                        "recommendation": "Remove console access for this unused credential or confirm it's still needed",
                    }
                )

            keys_response = self.client.list_access_keys(UserName=username)
            for key in keys_response["AccessKeyMetadata"]:
                if key["Status"] != "Active":
                    continue

                last_used_response = self.client.get_access_key_last_used(
                    AccessKeyId=key["AccessKeyId"]
                )
                last_used_date = last_used_response.get("AccessKeyLastUsed", {}).get(
                    "LastUsedDate"
                )
                if last_used_date is None or (now - last_used_date) > STALE_THRESHOLD:
                    findings.append(
                        {
                            "user_name": username,
                            "credential_type": "access_key",
                            "access_key_id": key["AccessKeyId"],
                            "last_used": last_used_date.isoformat() if last_used_date else None,
                            "severity": "medium",
                            "recommendation": "Deactivate or delete this access key if it's no longer needed",
                        }
                    )

        return findings

    def _count_severity(self, findings: Dict, severity: str) -> int:
        """Count findings by severity."""
        count = 0
        for key, value in findings.items():
            if isinstance(value, list):
                count += sum(
                    1 for item in value if isinstance(item, dict) and item.get("severity") == severity
                )
        return count
