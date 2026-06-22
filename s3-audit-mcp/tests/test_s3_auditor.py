import pytest
from unittest.mock import MagicMock, patch
from botocore.exceptions import ClientError
from audit import S3Auditor

REGION = "us-west-2"


def make_auditor(mock_client: MagicMock, region: str = REGION) -> S3Auditor:
    with patch("audit.boto3.client", return_value=mock_client):
        return S3Auditor(region=region)


def list_buckets_response(*names):
    return {"Buckets": [{"Name": n} for n in names]}


def location_response(region):
    return {"LocationConstraint": None if region == "us-east-1" else region}


def client_error(code, operation="Operation"):
    return ClientError({"Error": {"Code": code, "Message": "msg"}}, operation)


def acl_response(*public_uris):
    return {
        "Grants": [
            {"Grantee": {"Type": "Group", "URI": uri}, "Permission": "READ"} for uri in public_uris
        ]
    }


def pab_response(**overrides):
    config = {
        "BlockPublicAcls": True,
        "IgnorePublicAcls": True,
        "BlockPublicPolicy": True,
        "RestrictPublicBuckets": True,
    }
    config.update(overrides)
    return {"PublicAccessBlockConfiguration": config}


# ---------------------------------------------------------------------------
# _buckets_in_region
# ---------------------------------------------------------------------------

class TestBucketsInRegion:
    def test_filters_to_matching_region(self):
        mock_client = MagicMock()
        mock_client.list_buckets.return_value = list_buckets_response("in-region", "other-region")
        mock_client.get_bucket_location.side_effect = [
            location_response("us-west-2"),
            location_response("us-east-1"),
        ]
        result = make_auditor(mock_client)._buckets_in_region()
        assert result == ["in-region"]

    def test_us_east_1_location_constraint_none(self):
        mock_client = MagicMock()
        mock_client.list_buckets.return_value = list_buckets_response("legacy-bucket")
        mock_client.get_bucket_location.return_value = {"LocationConstraint": None}
        result = make_auditor(mock_client, region="us-east-1")._buckets_in_region()
        assert result == ["legacy-bucket"]


# ---------------------------------------------------------------------------
# _find_public_buckets
# ---------------------------------------------------------------------------

class TestFindPublicBuckets:
    def test_bucket_with_public_acl_is_reported(self):
        mock_client = MagicMock()
        mock_client.list_buckets.return_value = list_buckets_response("open-bucket")
        mock_client.get_bucket_location.return_value = location_response(REGION)
        mock_client.get_bucket_acl.return_value = acl_response(
            "http://acs.amazonaws.com/groups/global/AllUsers"
        )
        result = make_auditor(mock_client)._find_public_buckets()
        assert len(result) == 1
        assert result[0]["bucket_name"] == "open-bucket"
        assert result[0]["severity"] == "critical"
        assert "recommendation" in result[0]

    def test_bucket_with_public_policy_is_reported(self):
        mock_client = MagicMock()
        mock_client.list_buckets.return_value = list_buckets_response("policy-public-bucket")
        mock_client.get_bucket_location.return_value = location_response(REGION)
        mock_client.get_bucket_acl.return_value = acl_response()
        mock_client.get_bucket_policy_status.return_value = {"PolicyStatus": {"IsPublic": True}}
        result = make_auditor(mock_client)._find_public_buckets()
        assert len(result) == 1
        assert result[0]["bucket_name"] == "policy-public-bucket"

    def test_bucket_with_no_policy_attached_not_reported(self):
        mock_client = MagicMock()
        mock_client.list_buckets.return_value = list_buckets_response("private-bucket")
        mock_client.get_bucket_location.return_value = location_response(REGION)
        mock_client.get_bucket_acl.return_value = acl_response()
        mock_client.get_bucket_policy_status.side_effect = client_error("NoSuchBucketPolicy")
        assert make_auditor(mock_client)._find_public_buckets() == []

    def test_private_bucket_not_reported(self):
        mock_client = MagicMock()
        mock_client.list_buckets.return_value = list_buckets_response("private-bucket")
        mock_client.get_bucket_location.return_value = location_response(REGION)
        mock_client.get_bucket_acl.return_value = acl_response()
        mock_client.get_bucket_policy_status.return_value = {"PolicyStatus": {"IsPublic": False}}
        assert make_auditor(mock_client)._find_public_buckets() == []

    def test_bucket_outside_region_not_checked(self):
        mock_client = MagicMock()
        mock_client.list_buckets.return_value = list_buckets_response("other-region-bucket")
        mock_client.get_bucket_location.return_value = location_response("eu-west-1")
        result = make_auditor(mock_client)._find_public_buckets()
        assert result == []
        mock_client.get_bucket_acl.assert_not_called()


# ---------------------------------------------------------------------------
# _find_public_access_block_gaps
# ---------------------------------------------------------------------------

class TestFindPublicAccessBlockGaps:
    def test_fully_blocked_bucket_not_reported(self):
        mock_client = MagicMock()
        mock_client.list_buckets.return_value = list_buckets_response("locked-down")
        mock_client.get_bucket_location.return_value = location_response(REGION)
        mock_client.get_public_access_block.return_value = pab_response()
        assert make_auditor(mock_client)._find_public_access_block_gaps() == []

    def test_missing_one_setting_is_reported(self):
        mock_client = MagicMock()
        mock_client.list_buckets.return_value = list_buckets_response("partial-bucket")
        mock_client.get_bucket_location.return_value = location_response(REGION)
        mock_client.get_public_access_block.return_value = pab_response(RestrictPublicBuckets=False)
        result = make_auditor(mock_client)._find_public_access_block_gaps()
        assert len(result) == 1
        assert result[0]["missing_protections"] == ["RestrictPublicBuckets"]
        assert result[0]["severity"] == "high"

    def test_no_config_at_all_is_reported_with_all_missing(self):
        mock_client = MagicMock()
        mock_client.list_buckets.return_value = list_buckets_response("no-pab-bucket")
        mock_client.get_bucket_location.return_value = location_response(REGION)
        mock_client.get_public_access_block.side_effect = client_error(
            "NoSuchPublicAccessBlockConfiguration"
        )
        result = make_auditor(mock_client)._find_public_access_block_gaps()
        assert len(result) == 1
        assert set(result[0]["missing_protections"]) == {
            "BlockPublicAcls",
            "IgnorePublicAcls",
            "BlockPublicPolicy",
            "RestrictPublicBuckets",
        }


# ---------------------------------------------------------------------------
# _find_unencrypted_buckets
# ---------------------------------------------------------------------------

class TestFindUnencryptedBuckets:
    def test_bucket_with_encryption_not_reported(self):
        mock_client = MagicMock()
        mock_client.list_buckets.return_value = list_buckets_response("encrypted-bucket")
        mock_client.get_bucket_location.return_value = location_response(REGION)
        mock_client.get_bucket_encryption.return_value = {
            "ServerSideEncryptionConfiguration": {"Rules": [{"ApplyServerSideEncryptionByDefault": {}}]}
        }
        assert make_auditor(mock_client)._find_unencrypted_buckets() == []

    def test_bucket_without_encryption_is_reported(self):
        mock_client = MagicMock()
        mock_client.list_buckets.return_value = list_buckets_response("plain-bucket")
        mock_client.get_bucket_location.return_value = location_response(REGION)
        mock_client.get_bucket_encryption.side_effect = client_error(
            "ServerSideEncryptionConfigurationNotFoundError"
        )
        result = make_auditor(mock_client)._find_unencrypted_buckets()
        assert len(result) == 1
        assert result[0]["bucket_name"] == "plain-bucket"
        assert result[0]["severity"] == "medium"

    def test_empty_rules_list_is_reported(self):
        mock_client = MagicMock()
        mock_client.list_buckets.return_value = list_buckets_response("odd-bucket")
        mock_client.get_bucket_location.return_value = location_response(REGION)
        mock_client.get_bucket_encryption.return_value = {
            "ServerSideEncryptionConfiguration": {"Rules": []}
        }
        result = make_auditor(mock_client)._find_unencrypted_buckets()
        assert len(result) == 1


# ---------------------------------------------------------------------------
# _find_unversioned_buckets
# ---------------------------------------------------------------------------

class TestFindUnversionedBuckets:
    def test_versioning_enabled_not_reported(self):
        mock_client = MagicMock()
        mock_client.list_buckets.return_value = list_buckets_response("versioned-bucket")
        mock_client.get_bucket_location.return_value = location_response(REGION)
        mock_client.get_bucket_versioning.return_value = {"Status": "Enabled"}
        assert make_auditor(mock_client)._find_unversioned_buckets() == []

    def test_versioning_suspended_is_reported(self):
        mock_client = MagicMock()
        mock_client.list_buckets.return_value = list_buckets_response("suspended-bucket")
        mock_client.get_bucket_location.return_value = location_response(REGION)
        mock_client.get_bucket_versioning.return_value = {"Status": "Suspended"}
        result = make_auditor(mock_client)._find_unversioned_buckets()
        assert len(result) == 1
        assert result[0]["severity"] == "medium"

    def test_versioning_never_configured_is_reported(self):
        mock_client = MagicMock()
        mock_client.list_buckets.return_value = list_buckets_response("never-versioned")
        mock_client.get_bucket_location.return_value = location_response(REGION)
        mock_client.get_bucket_versioning.return_value = {}
        result = make_auditor(mock_client)._find_unversioned_buckets()
        assert len(result) == 1


# ---------------------------------------------------------------------------
# audit() -- full run + summary
# ---------------------------------------------------------------------------

class TestAudit:
    def _make_clean_client(self):
        mock_client = MagicMock()
        mock_client.list_buckets.return_value = list_buckets_response("clean-bucket")
        mock_client.get_bucket_location.return_value = location_response(REGION)
        mock_client.get_bucket_acl.return_value = acl_response()
        mock_client.get_bucket_policy_status.side_effect = client_error("NoSuchBucketPolicy")
        mock_client.get_public_access_block.return_value = pab_response()
        mock_client.get_bucket_encryption.return_value = {
            "ServerSideEncryptionConfiguration": {"Rules": [{"ApplyServerSideEncryptionByDefault": {}}]}
        }
        mock_client.get_bucket_versioning.return_value = {"Status": "Enabled"}
        return mock_client

    def test_audit_returns_expected_keys(self):
        result = make_auditor(self._make_clean_client()).audit()
        assert "public_buckets" in result
        assert "public_access_block_gaps" in result
        assert "unencrypted_buckets" in result
        assert "unversioned_buckets" in result
        assert "summary" in result

    def test_summary_zero_when_all_clean(self):
        result = make_auditor(self._make_clean_client()).audit()
        assert result["summary"]["total_findings"] == 0
        assert result["summary"]["critical"] == 0
        assert result["summary"]["high"] == 0

    def test_summary_aggregates_across_checks(self):
        mock_client = MagicMock()
        mock_client.list_buckets.return_value = list_buckets_response("bad-bucket")
        mock_client.get_bucket_location.return_value = location_response(REGION)
        mock_client.get_bucket_acl.return_value = acl_response(
            "http://acs.amazonaws.com/groups/global/AllUsers"
        )
        mock_client.get_public_access_block.side_effect = client_error(
            "NoSuchPublicAccessBlockConfiguration"
        )
        mock_client.get_bucket_encryption.side_effect = client_error(
            "ServerSideEncryptionConfigurationNotFoundError"
        )
        mock_client.get_bucket_versioning.return_value = {}
        result = make_auditor(mock_client).audit()
        # bad-bucket: public ACL (critical), PAB gap (high), unencrypted (medium),
        # unversioned (medium)
        assert result["summary"]["total_findings"] == 4
        assert result["summary"]["critical"] == 1
        assert result["summary"]["high"] == 1


# ---------------------------------------------------------------------------
# _count_severity
# ---------------------------------------------------------------------------

class TestCountSeverity:
    def test_counts_across_multiple_lists(self):
        auditor = make_auditor(MagicMock())
        findings = {
            "list_a": [{"severity": "critical"}, {"severity": "high"}],
            "list_b": [{"severity": "critical"}],
            "summary": {},
        }
        assert auditor._count_severity(findings, "critical") == 2
        assert auditor._count_severity(findings, "high") == 1
        assert auditor._count_severity(findings, "medium") == 0

    def test_ignores_non_list_values(self):
        auditor = make_auditor(MagicMock())
        findings = {"summary": {"total_findings": 5}, "items": [{"severity": "high"}]}
        assert auditor._count_severity(findings, "high") == 1
