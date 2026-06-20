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


class TestAllFindings:
    def test_flattens_all_categories(self, findings_with_all_issues):
        assert len(_all_findings(findings_with_all_issues)) == 4

    def test_sorted_critical_first(self, findings_with_all_issues):
        flat = _all_findings(findings_with_all_issues)
        assert flat[0]["severity"] == "critical"

    def test_empty_findings_returns_empty_list(self, findings_clean):
        assert _all_findings(findings_clean) == []


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
