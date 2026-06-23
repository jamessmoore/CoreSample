import os
from unittest.mock import MagicMock, patch

import pytest

from asff_mapper import (
    SEVERITY_MAP,
    CoreSampleFinding,
    batch_import,
    calculate_finding_id,
    to_asff,
)

REQUIRED_FIELDS = [
    "SchemaVersion",
    "Id",
    "ProductArn",
    "GeneratorId",
    "AwsAccountId",
    "Types",
    "CreatedAt",
    "UpdatedAt",
    "Severity",
    "Title",
    "Description",
    "Resources",
    "RecordState",
    "WorkflowState",
]


def make_finding(**overrides) -> CoreSampleFinding:
    defaults = dict(
        check_id="SG_OPEN_INGRESS_22",
        title="Security group allows SSH from 0.0.0.0/0",
        description="Security group sg-0abc123 permits inbound TCP/22 from 0.0.0.0/0.",
        severity="critical",
        resource_arn="arn:aws:ec2:us-east-1:123456789012:security-group/sg-0abc123",
        resource_type="AwsEc2SecurityGroup",
        region="us-east-1",
        account_id="123456789012",
    )
    defaults.update(overrides)
    return CoreSampleFinding(**defaults)


class TestToAsff:
    def test_required_fields_present(self):
        asff = to_asff(make_finding(), security_hub_account_id="123456789012")
        for key in REQUIRED_FIELDS:
            assert key in asff, f"missing required ASFF field: {key}"

    @pytest.mark.parametrize("severity", list(SEVERITY_MAP.keys()))
    def test_severity_mapping(self, severity):
        label, normalized = SEVERITY_MAP[severity]
        asff = to_asff(make_finding(severity=severity), security_hub_account_id="123456789012")
        assert asff["Severity"]["Label"] == label
        assert asff["Severity"]["Normalized"] == normalized
        assert asff["Severity"]["Original"] == severity

    def test_unknown_severity_falls_back_to_informational(self):
        asff = to_asff(make_finding(severity="nonsense"), security_hub_account_id="123456789012")
        assert asff["Severity"]["Label"] == "INFORMATIONAL"
        assert asff["Severity"]["Normalized"] == 0

    def test_finding_id_deterministic_for_same_inputs(self):
        first = to_asff(make_finding(), security_hub_account_id="123456789012")
        second = to_asff(make_finding(), security_hub_account_id="123456789012")
        assert first["Id"] == second["Id"]

    def test_finding_id_differs_by_resource_arn(self):
        first = calculate_finding_id("123456789012", "us-east-1", "CHECK", "arn:aws:ec2:us-east-1:123456789012:security-group/sg-1")
        second = calculate_finding_id("123456789012", "us-east-1", "CHECK", "arn:aws:ec2:us-east-1:123456789012:security-group/sg-2")
        assert first != second

    def test_compliance_absent_when_no_controls(self):
        asff = to_asff(make_finding(compliance_controls=[]), security_hub_account_id="123456789012")
        assert "Compliance" not in asff

    def test_compliance_present_when_controls_given(self):
        asff = to_asff(
            make_finding(compliance_controls=["CJIS-5.10.1"]),
            security_hub_account_id="123456789012",
        )
        assert asff["Compliance"] == {
            "Status": "FAILED",
            "RelatedRequirements": ["CJIS-5.10.1"],
        }

    def test_remediation_absent_when_not_given(self):
        asff = to_asff(make_finding(remediation_text=None), security_hub_account_id="123456789012")
        assert "Remediation" not in asff

    def test_remediation_present_when_given(self):
        asff = to_asff(
            make_finding(remediation_text="Restrict ingress to known CIDR ranges."),
            security_hub_account_id="123456789012",
        )
        assert asff["Remediation"]["Recommendation"]["Text"] == "Restrict ingress to known CIDR ranges."

    def test_title_and_description_truncated(self):
        asff = to_asff(
            make_finding(title="x" * 300, description="y" * 2000),
            security_hub_account_id="123456789012",
        )
        assert len(asff["Title"]) == 256
        assert len(asff["Description"]) == 1024


class TestBatchImport:
    def test_disabled_by_default_does_not_call_boto3(self, monkeypatch):
        monkeypatch.delenv("ENABLE_SECURITY_HUB_EXPORT", raising=False)
        with patch("asff_mapper.boto3.client") as mock_client:
            with pytest.raises(RuntimeError, match="disabled"):
                batch_import([make_finding()], security_hub_account_id="123456789012", region="us-east-1")
            mock_client.assert_not_called()

    def test_explicitly_false_does_not_call_boto3(self, monkeypatch):
        monkeypatch.setenv("ENABLE_SECURITY_HUB_EXPORT", "false")
        with patch("asff_mapper.boto3.client") as mock_client:
            with pytest.raises(RuntimeError, match="disabled"):
                batch_import([make_finding()], security_hub_account_id="123456789012", region="us-east-1")
            mock_client.assert_not_called()

    def test_enabled_calls_batch_import_findings(self, monkeypatch):
        monkeypatch.setenv("ENABLE_SECURITY_HUB_EXPORT", "true")
        mock_client = MagicMock()
        mock_client.batch_import_findings.return_value = {"FailedCount": 0, "FailedFindings": []}

        with patch("asff_mapper.boto3.client", return_value=mock_client) as mock_boto:
            response = batch_import(
                [make_finding()], security_hub_account_id="123456789012", region="us-east-1"
            )

        mock_boto.assert_called_once_with("securityhub", region_name="us-east-1")
        mock_client.batch_import_findings.assert_called_once()
        sent_findings = mock_client.batch_import_findings.call_args.kwargs["Findings"]
        assert len(sent_findings) == 1
        assert sent_findings[0]["GeneratorId"] == "coresample/SG_OPEN_INGRESS_22"
        assert response["FailedCount"] == 0

    def test_raises_when_security_hub_reports_failures(self, monkeypatch):
        monkeypatch.setenv("ENABLE_SECURITY_HUB_EXPORT", "true")
        mock_client = MagicMock()
        mock_client.batch_import_findings.return_value = {
            "FailedCount": 1,
            "FailedFindings": [{"Id": "abc", "ErrorCode": "InvalidInput", "ErrorMessage": "bad"}],
        }

        with patch("asff_mapper.boto3.client", return_value=mock_client):
            with pytest.raises(RuntimeError, match="failed to import"):
                batch_import(
                    [make_finding()], security_hub_account_id="123456789012", region="us-east-1"
                )
