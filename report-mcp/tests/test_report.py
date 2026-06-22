import pytest
from report import generate_markdown_report, _all_findings, _risk_posture, _executive_summary


@pytest.fixture
def findings_with_all_issues():
    return {
        "untagged_instances": [
            {
                "instance_id": "i-0abc123def456001",
                "missing_tags": ["Name", "Environment", "Owner"],
                "severity": "high",
                "recommendation": "Add missing tags for compliance and cost tracking",
            }
        ],
        "public_instances": [
            {
                "instance_id": "i-0abc123def456002",
                "public_ip": "54.12.34.56",
                "severity": "medium",
                "recommendation": "Review if public IP is necessary; consider NAT or bastion host",
            }
        ],
        "security_group_issues": [
            {
                "security_group_id": "sg-0critical001",
                "security_group_name": "open-sg",
                "issue": "Allows world access on port 22",
                "severity": "critical",
                "recommendation": "Restrict CIDR to known IPs or use security group references",
            },
            {
                "security_group_id": "sg-0high001",
                "security_group_name": "open-sg",
                "issue": "Allows world access on port 443",
                "severity": "high",
                "recommendation": "Restrict CIDR to known IPs or use security group references",
            },
        ],
        "summary": {"total_findings": 4, "critical": 1, "high": 2},
    }


@pytest.fixture
def findings_clean():
    return {
        "untagged_instances": [],
        "public_instances": [],
        "security_group_issues": [],
        "summary": {"total_findings": 0, "critical": 0, "high": 0},
    }


@pytest.fixture
def iam_findings():
    return {
        "console_users_without_mfa": [
            {
                "user_name": "alice",
                "severity": "critical",
                "recommendation": "Enable MFA for this console user immediately",
            }
        ],
        "old_access_keys": [
            {
                "user_name": "bob",
                "access_key_id": "AKIAOLD12345678",
                "age_days": 137,
                "severity": "high",
                "recommendation": "Rotate this access key -- it exceeds the 90-day rotation threshold",
            }
        ],
        "root_account_risk": [
            {
                "resource": "root_account",
                "issue": "Root account MFA is not enabled",
                "severity": "critical",
                "recommendation": "Enable MFA on the root account immediately",
            }
        ],
        "unused_credentials": [
            {
                "user_name": "carol",
                "credential_type": "access_key",
                "access_key_id": "AKIASTALE0000001",
                "last_used": "2026-01-01T00:00:00+00:00",
                "severity": "medium",
                "recommendation": "Deactivate or delete this access key if it's no longer needed",
            }
        ],
        "summary": {"total_findings": 4, "critical": 2, "high": 1},
    }


@pytest.fixture
def s3_findings():
    return {
        "public_buckets": [
            {
                "bucket_name": "open-bucket",
                "severity": "critical",
                "recommendation": "Remove public ACL grants and/or the public bucket policy immediately",
            }
        ],
        "public_access_block_gaps": [
            {
                "bucket_name": "partial-bucket",
                "missing_protections": ["RestrictPublicBuckets"],
                "severity": "high",
                "recommendation": "Enable all four S3 Block Public Access settings for this bucket",
            }
        ],
        "unencrypted_buckets": [
            {
                "bucket_name": "plain-bucket",
                "severity": "medium",
                "recommendation": "Enable default server-side encryption (SSE-S3 or SSE-KMS) on this bucket",
            }
        ],
        "unversioned_buckets": [
            {
                "bucket_name": "no-versioning-bucket",
                "severity": "medium",
                "recommendation": "Enable versioning to protect against accidental deletion or overwrite",
            }
        ],
        "summary": {"total_findings": 4, "critical": 1, "high": 1},
    }


class TestAllFindings:
    def test_flattens_all_categories(self, findings_with_all_issues):
        assert len(_all_findings(findings_with_all_issues)) == 4

    def test_sorted_critical_first(self, findings_with_all_issues):
        flat = _all_findings(findings_with_all_issues)
        assert flat[0]["severity"] == "critical"

    def test_empty_findings_returns_empty_list(self, findings_clean):
        assert _all_findings(findings_clean) == []

    def test_flattens_iam_categories(self, iam_findings):
        flat = _all_findings(iam_findings)
        assert len(flat) == 4
        checks = {item["check"] for item in flat}
        assert checks == {
            "Console User Without MFA",
            "Stale Access Key",
            "Root Account Risk",
            "Unused Credential",
        }

    def test_iam_resource_ids(self, iam_findings):
        flat = _all_findings(iam_findings)
        resource_ids = {item["resource_id"] for item in flat}
        assert resource_ids == {"alice", "AKIAOLD12345678", "root_account", "AKIASTALE0000001"}

    def test_flattens_s3_categories(self, s3_findings):
        flat = _all_findings(s3_findings)
        assert len(flat) == 4
        checks = {item["check"] for item in flat}
        assert checks == {
            "Public Bucket",
            "Public Access Block Gap",
            "Unencrypted Bucket",
            "Versioning Disabled",
        }

    def test_s3_resource_ids(self, s3_findings):
        flat = _all_findings(s3_findings)
        resource_ids = {item["resource_id"] for item in flat}
        assert resource_ids == {
            "open-bucket",
            "partial-bucket",
            "plain-bucket",
            "no-versioning-bucket",
        }

    def test_unused_credential_falls_back_to_user_name(self):
        findings = {
            "unused_credentials": [
                {
                    "user_name": "dave",
                    "credential_type": "password",
                    "last_used": None,
                    "severity": "medium",
                    "recommendation": "Remove console access for this unused credential",
                }
            ]
        }
        flat = _all_findings(findings)
        assert flat[0]["resource_id"] == "dave"
        assert "never" in flat[0]["issue"]

    def test_mixed_services_combined_and_sorted(self, findings_with_all_issues, iam_findings, s3_findings):
        merged = {**findings_with_all_issues, **iam_findings, **s3_findings}
        flat = _all_findings(merged)
        assert len(flat) == 12
        assert flat[0]["severity"] == "critical"
        checks = {item["check"] for item in flat}
        assert "Permissive Security Group" in checks
        assert "Root Account Risk" in checks
        assert "Public Bucket" in checks

    def test_unrecognized_category_is_skipped_not_crashed(self):
        findings = {
            "some_future_service_findings": [{"weird_shape": True, "severity": "critical"}],
            "summary": {"total_findings": 1, "critical": 1, "high": 0},
        }
        assert _all_findings(findings) == []

    def test_non_list_summary_value_ignored(self, findings_with_all_issues):
        # "summary" itself is a dict, not a list -- must not be iterated as findings
        flat = _all_findings(findings_with_all_issues)
        assert all(isinstance(item, dict) for item in flat)


class TestRiskPosture:
    def test_critical_risk_when_critical_findings(self, findings_with_all_issues):
        assert _risk_posture(findings_with_all_issues["summary"]) == "CRITICAL RISK"

    def test_clean_when_no_findings(self, findings_clean):
        assert _risk_posture(findings_clean["summary"]) == "CLEAN"


class TestExecutiveSummary:
    def test_clean_summary_mentions_no_findings(self, findings_clean):
        summary = _executive_summary(findings_clean, region="us-east-1")
        assert "no findings" in summary.lower()
        assert "us-east-1" in summary

    def test_critical_summary_mentions_immediate_remediation(self, findings_with_all_issues):
        summary = _executive_summary(findings_with_all_issues, region="us-east-1")
        assert "immediate" in summary.lower()

    def test_mixed_services_summary_lists_all_categories(
        self, findings_with_all_issues, iam_findings, s3_findings
    ):
        merged = {**findings_with_all_issues, **iam_findings, **s3_findings}
        merged["summary"] = {"total_findings": 12, "critical": 4, "high": 4}
        summary = _executive_summary(merged, region="us-west-2")
        assert "Root Account Risk" in summary
        assert "Public Bucket" in summary
        assert "Permissive Security Group" in summary


class TestMarkdownReport:
    def test_returns_string(self, findings_with_all_issues):
        result = generate_markdown_report(findings_with_all_issues, region="us-east-1")
        assert isinstance(result, str)
        assert len(result) > 0

    def test_contains_report_title(self, findings_with_all_issues):
        md = generate_markdown_report(findings_with_all_issues, region="us-east-1")
        assert "AWS Infrastructure Audit Report" in md

    def test_contains_region_and_account(self, findings_with_all_issues):
        md = generate_markdown_report(
            findings_with_all_issues, region="ap-southeast-1", account_id="123456789012"
        )
        assert "ap-southeast-1" in md
        assert "123456789012" in md

    def test_contains_all_resource_ids(self, findings_with_all_issues):
        md = generate_markdown_report(findings_with_all_issues, region="us-east-1")
        assert "i-0abc123def456001" in md
        assert "sg-0critical001" in md

    def test_clean_report_no_findings_table(self, findings_clean):
        md = generate_markdown_report(findings_clean, region="us-east-1")
        assert "| Severity |" not in md

    def test_clean_report_mentions_clean_or_no_findings(self, findings_clean):
        md = generate_markdown_report(findings_clean, region="us-east-1")
        assert "no findings" in md.lower()

    def test_mixed_services_report_contains_every_section(
        self, findings_with_all_issues, iam_findings, s3_findings
    ):
        merged = {**findings_with_all_issues, **iam_findings, **s3_findings}
        merged["summary"] = {"total_findings": 12, "critical": 4, "high": 4}
        md = generate_markdown_report(merged, region="us-west-2")
        assert "sg-0critical001" in md
        assert "root_account" in md
        assert "open-bucket" in md
        assert "AKIAOLD12345678" in md
