from unittest.mock import MagicMock, patch

from exporter.handler import _account_id_from_context, lambda_handler


def make_context(account_id="123456789012", region="us-west-2", function_name="coresample-security-hub-exporter"):
    context = MagicMock()
    context.invoked_function_arn = f"arn:aws:lambda:{region}:{account_id}:function:{function_name}"
    return context


def make_event(findings, region="us-west-2"):
    return {
        "version": "0",
        "source": "coresample.report-mcp",
        "detail-type": "AuditReportGenerated",
        "detail": {"findings": findings, "region": region},
    }


class TestAccountIdFromContext:
    def test_parses_account_id_from_invoked_function_arn(self):
        context = make_context(account_id="999999999999")
        assert _account_id_from_context(context) == "999999999999"


class TestLambdaHandler:
    def test_disabled_by_default_does_not_touch_boto3(self, monkeypatch):
        monkeypatch.delenv("ENABLE_SECURITY_HUB_EXPORT", raising=False)
        event = make_event({"public_buckets": [{"bucket_name": "b1", "severity": "critical", "recommendation": "fix"}]})

        with patch("exporter.handler.batch_import") as mock_batch_import:
            result = lambda_handler(event, make_context())

        assert result == {"status": "disabled"}
        mock_batch_import.assert_not_called()

    def test_explicitly_false_does_not_touch_boto3(self, monkeypatch):
        monkeypatch.setenv("ENABLE_SECURITY_HUB_EXPORT", "false")
        event = make_event({"public_buckets": [{"bucket_name": "b1", "severity": "critical", "recommendation": "fix"}]})

        with patch("exporter.handler.batch_import") as mock_batch_import:
            result = lambda_handler(event, make_context())

        assert result == {"status": "disabled"}
        mock_batch_import.assert_not_called()

    def test_no_mappable_findings_short_circuits(self, monkeypatch):
        monkeypatch.setenv("ENABLE_SECURITY_HUB_EXPORT", "true")
        event = make_event({"some_future_service_findings": [{"weird_shape": True, "severity": "critical"}]})

        with patch("exporter.handler.batch_import") as mock_batch_import:
            result = lambda_handler(event, make_context())

        assert result == {"status": "no_findings"}
        mock_batch_import.assert_not_called()

    def test_enabled_maps_and_calls_batch_import(self, monkeypatch):
        monkeypatch.setenv("ENABLE_SECURITY_HUB_EXPORT", "true")
        event = make_event(
            {
                "public_buckets": [
                    {"bucket_name": "b1", "severity": "critical", "recommendation": "fix it"}
                ]
            },
            region="us-west-2",
        )
        context = make_context(account_id="123456789012", region="us-west-2")

        with patch(
            "exporter.handler.batch_import", return_value={"FailedCount": 0}
        ) as mock_batch_import:
            result = lambda_handler(event, context)

        mock_batch_import.assert_called_once()
        args, kwargs = mock_batch_import.call_args
        mapped_findings = args[0]
        assert len(mapped_findings) == 1
        assert mapped_findings[0].account_id == "123456789012"
        assert mapped_findings[0].region == "us-west-2"
        assert kwargs["security_hub_account_id"] == "123456789012"
        assert kwargs["region"] == "us-west-2"
        assert result == {"status": "exported", "failed_count": 0}

    def test_account_id_comes_from_context_not_event(self, monkeypatch):
        # Even if a caller tried to put an account_id in the event detail,
        # it has no effect -- only the Lambda's own context is trusted.
        monkeypatch.setenv("ENABLE_SECURITY_HUB_EXPORT", "true")
        event = make_event(
            {"public_buckets": [{"bucket_name": "b1", "severity": "critical", "recommendation": "fix"}]}
        )
        event["detail"]["account_id"] = "999999999999"  # ignored
        context = make_context(account_id="123456789012")

        with patch("exporter.handler.batch_import", return_value={"FailedCount": 0}) as mock_batch_import:
            lambda_handler(event, context)

        mapped_findings = mock_batch_import.call_args.args[0]
        assert mapped_findings[0].account_id == "123456789012"
