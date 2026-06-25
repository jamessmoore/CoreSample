import json
from unittest.mock import patch

from main import generate_report


def _ec2_audit_json():
    return json.dumps(
        {
            "untagged_instances": [
                {
                    "instance_id": "i-1",
                    "missing_tags": ["Owner"],
                    "severity": "high",
                    "recommendation": "tag it",
                }
            ],
            "summary": {"total_findings": 1, "critical": 0, "high": 1},
        }
    )


def test_generate_report_publishes_merged_findings_to_eventbridge():
    with patch("main.publish_audit_event") as mock_publish:
        generate_report([_ec2_audit_json()], region="us-west-2")

    mock_publish.assert_called_once()
    args, kwargs = mock_publish.call_args
    published_findings = args[0]
    assert "untagged_instances" in published_findings
    assert kwargs["region"] == "us-west-2"


def test_generate_report_does_not_publish_on_invalid_json():
    with patch("main.publish_audit_event") as mock_publish:
        result = generate_report(["not valid json"], region="us-west-2")

    mock_publish.assert_not_called()
    assert "error" in json.loads(result)
