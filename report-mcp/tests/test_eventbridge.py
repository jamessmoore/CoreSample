import json
import logging
from unittest.mock import MagicMock, patch

from eventbridge import EVENT_DETAIL_TYPE, EVENT_SOURCE, publish_audit_event


def test_publish_audit_event_sends_findings_and_region():
    mock_client = MagicMock()
    mock_client.put_events.return_value = {"FailedEntryCount": 0}
    findings = {"public_buckets": [{"bucket_name": "b1", "severity": "critical"}]}

    with patch("eventbridge.boto3.client", return_value=mock_client) as mock_boto:
        publish_audit_event(findings, region="us-west-2")

    mock_boto.assert_called_once_with("events")
    mock_client.put_events.assert_called_once()
    entries = mock_client.put_events.call_args.kwargs["Entries"]
    assert len(entries) == 1
    entry = entries[0]
    assert entry["Source"] == EVENT_SOURCE
    assert entry["DetailType"] == EVENT_DETAIL_TYPE
    detail = json.loads(entry["Detail"])
    assert detail["findings"] == findings
    assert detail["region"] == "us-west-2"


def test_publish_audit_event_does_not_include_account_id():
    mock_client = MagicMock()
    mock_client.put_events.return_value = {"FailedEntryCount": 0}

    with patch("eventbridge.boto3.client", return_value=mock_client):
        publish_audit_event({}, region="us-west-2")

    entry = mock_client.put_events.call_args.kwargs["Entries"][0]
    detail = json.loads(entry["Detail"])
    assert "account_id" not in detail


def test_publish_audit_event_logs_and_swallows_boto3_failure(caplog):
    mock_client = MagicMock()
    mock_client.put_events.side_effect = Exception("eventbridge unreachable")

    with patch("eventbridge.boto3.client", return_value=mock_client):
        with caplog.at_level(logging.ERROR):
            publish_audit_event({"public_buckets": []}, region="us-east-1")

    assert "Failed to publish audit event" in caplog.text


def test_publish_audit_event_logs_on_partial_failure(caplog):
    mock_client = MagicMock()
    mock_client.put_events.return_value = {
        "FailedEntryCount": 1,
        "Entries": [{"ErrorCode": "InternalException", "ErrorMessage": "boom"}],
    }

    with patch("eventbridge.boto3.client", return_value=mock_client):
        with caplog.at_level(logging.ERROR):
            publish_audit_event({"public_buckets": []}, region="us-east-1")

    assert "EventBridge rejected the audit event" in caplog.text


def test_publish_audit_event_never_raises():
    mock_client = MagicMock()
    mock_client.put_events.side_effect = Exception("boom")

    with patch("eventbridge.boto3.client", return_value=mock_client):
        publish_audit_event({"public_buckets": []}, region="us-east-1")  # must not raise
