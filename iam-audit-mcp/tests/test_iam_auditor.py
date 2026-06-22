import pytest
from datetime import datetime, timedelta, timezone
from unittest.mock import MagicMock, patch
from audit import IAMAuditor

NOW = datetime.now(timezone.utc)
OLD = NOW - timedelta(days=120)
RECENT = NOW - timedelta(days=10)


def make_auditor(mock_client: MagicMock) -> IAMAuditor:
    with patch("audit.boto3.client", return_value=mock_client):
        return IAMAuditor(region="us-east-1")


def user(name, password_last_used=None):
    u = {"UserName": name}
    if password_last_used is not None:
        u["PasswordLastUsed"] = password_last_used
    return u


def access_key(key_id, create_date, status="Active"):
    return {"AccessKeyId": key_id, "Status": status, "CreateDate": create_date}


# ---------------------------------------------------------------------------
# _find_users_without_mfa
# ---------------------------------------------------------------------------

class TestFindUsersWithoutMfa:
    def test_console_user_without_mfa_is_reported(self):
        mock_client = MagicMock()
        mock_client.list_users.return_value = {"Users": [user("alice", RECENT)]}
        mock_client.list_mfa_devices.return_value = {"MFADevices": []}
        result = make_auditor(mock_client)._find_users_without_mfa()
        assert len(result) == 1
        assert result[0]["user_name"] == "alice"
        assert result[0]["severity"] == "critical"
        assert "recommendation" in result[0]

    def test_console_user_with_mfa_not_reported(self):
        mock_client = MagicMock()
        mock_client.list_users.return_value = {"Users": [user("alice", RECENT)]}
        mock_client.list_mfa_devices.return_value = {"MFADevices": [{"SerialNumber": "x"}]}
        assert make_auditor(mock_client)._find_users_without_mfa() == []

    def test_non_console_user_not_checked(self):
        mock_client = MagicMock()
        mock_client.list_users.return_value = {"Users": [user("api-only")]}
        result = make_auditor(mock_client)._find_users_without_mfa()
        assert result == []
        mock_client.list_mfa_devices.assert_not_called()

    def test_multiple_users_only_console_without_mfa_reported(self):
        mock_client = MagicMock()
        mock_client.list_users.return_value = {
            "Users": [user("alice", RECENT), user("bob", RECENT), user("api-only")]
        }
        mock_client.list_mfa_devices.side_effect = [
            {"MFADevices": []},
            {"MFADevices": [{"SerialNumber": "x"}]},
        ]
        result = make_auditor(mock_client)._find_users_without_mfa()
        assert len(result) == 1
        assert result[0]["user_name"] == "alice"


# ---------------------------------------------------------------------------
# _find_old_access_keys
# ---------------------------------------------------------------------------

class TestFindOldAccessKeys:
    def test_key_older_than_90_days_is_reported(self):
        mock_client = MagicMock()
        mock_client.list_users.return_value = {"Users": [user("alice")]}
        mock_client.list_access_keys.return_value = {
            "AccessKeyMetadata": [access_key("AKIAOLD", OLD)]
        }
        result = make_auditor(mock_client)._find_old_access_keys()
        assert len(result) == 1
        assert result[0]["access_key_id"] == "AKIAOLD"
        assert result[0]["severity"] == "high"

    def test_key_within_90_days_not_reported(self):
        mock_client = MagicMock()
        mock_client.list_users.return_value = {"Users": [user("alice")]}
        mock_client.list_access_keys.return_value = {
            "AccessKeyMetadata": [access_key("AKIANEW", RECENT)]
        }
        assert make_auditor(mock_client)._find_old_access_keys() == []

    def test_inactive_old_key_not_reported(self):
        mock_client = MagicMock()
        mock_client.list_users.return_value = {"Users": [user("alice")]}
        mock_client.list_access_keys.return_value = {
            "AccessKeyMetadata": [access_key("AKIAOLD", OLD, status="Inactive")]
        }
        assert make_auditor(mock_client)._find_old_access_keys() == []

    def test_multiple_users_aggregated(self):
        mock_client = MagicMock()
        mock_client.list_users.return_value = {"Users": [user("alice"), user("bob")]}
        mock_client.list_access_keys.side_effect = [
            {"AccessKeyMetadata": [access_key("AKIAOLD1", OLD)]},
            {"AccessKeyMetadata": [access_key("AKIAOLD2", OLD)]},
        ]
        result = make_auditor(mock_client)._find_old_access_keys()
        ids = {r["access_key_id"] for r in result}
        assert ids == {"AKIAOLD1", "AKIAOLD2"}


# ---------------------------------------------------------------------------
# _check_root_account_risk
# ---------------------------------------------------------------------------

class TestCheckRootAccountRisk:
    def test_no_mfa_and_keys_present_reports_both(self):
        mock_client = MagicMock()
        mock_client.get_account_summary.return_value = {
            "SummaryMap": {"AccountMFAEnabled": 0, "AccountAccessKeysPresent": 1}
        }
        result = make_auditor(mock_client)._check_root_account_risk()
        assert len(result) == 2
        assert all(r["severity"] == "critical" for r in result)

    def test_mfa_enabled_and_no_keys_reports_nothing(self):
        mock_client = MagicMock()
        mock_client.get_account_summary.return_value = {
            "SummaryMap": {"AccountMFAEnabled": 1, "AccountAccessKeysPresent": 0}
        }
        assert make_auditor(mock_client)._check_root_account_risk() == []

    def test_only_mfa_missing_reports_one(self):
        mock_client = MagicMock()
        mock_client.get_account_summary.return_value = {
            "SummaryMap": {"AccountMFAEnabled": 0, "AccountAccessKeysPresent": 0}
        }
        result = make_auditor(mock_client)._check_root_account_risk()
        assert len(result) == 1
        assert "MFA" in result[0]["issue"]

    def test_only_keys_present_reports_one(self):
        mock_client = MagicMock()
        mock_client.get_account_summary.return_value = {
            "SummaryMap": {"AccountMFAEnabled": 1, "AccountAccessKeysPresent": 1}
        }
        result = make_auditor(mock_client)._check_root_account_risk()
        assert len(result) == 1
        assert "access keys" in result[0]["issue"]


# ---------------------------------------------------------------------------
# _find_unused_credentials
# ---------------------------------------------------------------------------

class TestFindUnusedCredentials:
    def test_unused_password_is_reported(self):
        mock_client = MagicMock()
        mock_client.list_users.return_value = {"Users": [user("alice", OLD)]}
        mock_client.list_access_keys.return_value = {"AccessKeyMetadata": []}
        result = make_auditor(mock_client)._find_unused_credentials()
        assert len(result) == 1
        assert result[0]["credential_type"] == "password"
        assert result[0]["severity"] == "medium"

    def test_recently_used_password_not_reported(self):
        mock_client = MagicMock()
        mock_client.list_users.return_value = {"Users": [user("alice", RECENT)]}
        mock_client.list_access_keys.return_value = {"AccessKeyMetadata": []}
        assert make_auditor(mock_client)._find_unused_credentials() == []

    def test_unused_access_key_is_reported(self):
        mock_client = MagicMock()
        mock_client.list_users.return_value = {"Users": [user("alice")]}
        mock_client.list_access_keys.return_value = {
            "AccessKeyMetadata": [access_key("AKIASTALE", OLD)]
        }
        mock_client.get_access_key_last_used.return_value = {
            "AccessKeyLastUsed": {"LastUsedDate": OLD}
        }
        result = make_auditor(mock_client)._find_unused_credentials()
        assert len(result) == 1
        assert result[0]["credential_type"] == "access_key"
        assert result[0]["access_key_id"] == "AKIASTALE"

    def test_active_access_key_not_reported(self):
        mock_client = MagicMock()
        mock_client.list_users.return_value = {"Users": [user("alice")]}
        mock_client.list_access_keys.return_value = {
            "AccessKeyMetadata": [access_key("AKIAACTIVE", OLD)]
        }
        mock_client.get_access_key_last_used.return_value = {
            "AccessKeyLastUsed": {"LastUsedDate": RECENT}
        }
        assert make_auditor(mock_client)._find_unused_credentials() == []

    def test_never_used_access_key_is_reported(self):
        mock_client = MagicMock()
        mock_client.list_users.return_value = {"Users": [user("alice")]}
        mock_client.list_access_keys.return_value = {
            "AccessKeyMetadata": [access_key("AKIANEVER", OLD)]
        }
        mock_client.get_access_key_last_used.return_value = {"AccessKeyLastUsed": {}}
        result = make_auditor(mock_client)._find_unused_credentials()
        assert len(result) == 1
        assert result[0]["last_used"] is None

    def test_inactive_key_skipped(self):
        mock_client = MagicMock()
        mock_client.list_users.return_value = {"Users": [user("alice")]}
        mock_client.list_access_keys.return_value = {
            "AccessKeyMetadata": [access_key("AKIAINACTIVE", OLD, status="Inactive")]
        }
        result = make_auditor(mock_client)._find_unused_credentials()
        assert result == []
        mock_client.get_access_key_last_used.assert_not_called()


# ---------------------------------------------------------------------------
# audit() -- full run + summary
# ---------------------------------------------------------------------------

class TestAudit:
    def _make_clean_client(self):
        mock_client = MagicMock()
        mock_client.list_users.return_value = {"Users": []}
        mock_client.get_account_summary.return_value = {
            "SummaryMap": {"AccountMFAEnabled": 1, "AccountAccessKeysPresent": 0}
        }
        return mock_client

    def test_audit_returns_expected_keys(self):
        result = make_auditor(self._make_clean_client()).audit()
        assert "console_users_without_mfa" in result
        assert "old_access_keys" in result
        assert "root_account_risk" in result
        assert "unused_credentials" in result
        assert "summary" in result

    def test_summary_zero_when_all_clean(self):
        result = make_auditor(self._make_clean_client()).audit()
        assert result["summary"]["total_findings"] == 0
        assert result["summary"]["critical"] == 0
        assert result["summary"]["high"] == 0

    def test_summary_counts_root_risk_as_critical(self):
        mock_client = MagicMock()
        mock_client.list_users.return_value = {"Users": []}
        mock_client.get_account_summary.return_value = {
            "SummaryMap": {"AccountMFAEnabled": 0, "AccountAccessKeysPresent": 1}
        }
        result = make_auditor(mock_client).audit()
        assert result["summary"]["critical"] == 2
        assert result["summary"]["total_findings"] == 2

    def test_summary_aggregates_across_checks(self):
        mock_client = MagicMock()
        mock_client.list_users.return_value = {"Users": [user("alice", OLD)]}
        mock_client.list_mfa_devices.return_value = {"MFADevices": []}
        mock_client.list_access_keys.return_value = {
            "AccessKeyMetadata": [access_key("AKIAOLD", OLD)]
        }
        mock_client.get_access_key_last_used.return_value = {
            "AccessKeyLastUsed": {"LastUsedDate": OLD}
        }
        mock_client.get_account_summary.return_value = {
            "SummaryMap": {"AccountMFAEnabled": 1, "AccountAccessKeysPresent": 0}
        }
        result = make_auditor(mock_client).audit()
        # alice: no mfa (critical), old key (high), unused password (medium),
        # unused key (medium)
        assert result["summary"]["total_findings"] == 4
        assert result["summary"]["critical"] == 1
        assert result["summary"]["high"] == 1


# ---------------------------------------------------------------------------
# _count_severity
# ---------------------------------------------------------------------------

class TestCountSeverity:
    def test_counts_across_multiple_lists(self):
        mock_client = MagicMock()
        mock_client.list_users.return_value = {"Users": []}
        mock_client.get_account_summary.return_value = {"SummaryMap": {}}
        auditor = make_auditor(mock_client)
        findings = {
            "list_a": [{"severity": "critical"}, {"severity": "high"}],
            "list_b": [{"severity": "critical"}],
            "summary": {},
        }
        assert auditor._count_severity(findings, "critical") == 2
        assert auditor._count_severity(findings, "high") == 1
        assert auditor._count_severity(findings, "medium") == 0

    def test_ignores_non_list_values(self):
        mock_client = MagicMock()
        mock_client.list_users.return_value = {"Users": []}
        mock_client.get_account_summary.return_value = {"SummaryMap": {}}
        auditor = make_auditor(mock_client)
        findings = {"summary": {"total_findings": 5}, "items": [{"severity": "high"}]}
        assert auditor._count_severity(findings, "high") == 1
