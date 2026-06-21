from unittest.mock import MagicMock, patch

from storage import upload_report


def test_upload_report_returns_s3_uri():
    mock_client = MagicMock()

    with patch("storage.boto3.client", return_value=mock_client):
        uri = upload_report(
            "# Report\n\nfindings here",
            bucket="coresample-reports-123",
            region="us-west-2",
            account_id="123456789012",
        )

    assert uri.startswith("s3://coresample-reports-123/reports/123456789012/us-west-2/")
    assert uri.endswith(".md")


def test_upload_report_puts_object_with_correct_content():
    mock_client = MagicMock()

    with patch("storage.boto3.client", return_value=mock_client):
        upload_report("# Report body", bucket="my-bucket", region="us-east-1", account_id="N/A")

    mock_client.put_object.assert_called_once()
    _, kwargs = mock_client.put_object.call_args
    assert kwargs["Bucket"] == "my-bucket"
    assert kwargs["Body"] == b"# Report body"
    assert kwargs["ContentType"] == "text/markdown"
    assert kwargs["Key"].startswith("reports/N-A/us-east-1/")


def test_upload_report_sanitizes_account_id_for_key():
    mock_client = MagicMock()

    with patch("storage.boto3.client", return_value=mock_client):
        upload_report("body", bucket="b", region="us-west-2", account_id="my account/1")

    _, kwargs = mock_client.put_object.call_args
    assert kwargs["Key"].startswith("reports/my-account-1/us-west-2/")
