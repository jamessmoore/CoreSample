"""EventBridge publishing for report-mcp.

Kept separate from report.py, which stays pure rendering logic with no AWS
API calls of its own -- mirrors storage.py's existing split (S3 upload is
the only other AWS call this service makes).

Publishing is best-effort: a failed put_events logs and falls through
rather than raising, the same pattern storage.py's caller (_with_storage_note
in main.py) already uses for the S3 upload. The audit/report flow must keep
working even if EventBridge is unreachable or misconfigured -- whether a
finding reaches Security Hub downstream is deliberately decoupled from
whether the agent's report request succeeds.
"""

import json
import logging
from typing import Any

import boto3

logger = logging.getLogger(__name__)

EVENT_SOURCE = "coresample.report-mcp"
EVENT_DETAIL_TYPE = "AuditReportGenerated"


def publish_audit_event(findings: dict[str, Any], region: str) -> None:
    """Publish the merged findings dict to the default EventBridge bus.

    A separate, independently-deployed Lambda (integrations/security_hub/
    exporter/handler.py) subscribes to this event and performs the ASFF
    mapping + Security Hub export. report-mcp never calls that Lambda
    directly and has no knowledge of whether it's enabled.

    account_id is deliberately not included -- the exporter Lambda derives
    it from its own execution context rather than trusting a value that
    flows through report-mcp's (currently unreliable, agent-supplied)
    account_id parameter.
    """
    client = boto3.client("events")
    detail = {"findings": findings, "region": region}

    try:
        response = client.put_events(
            Entries=[
                {
                    "Source": EVENT_SOURCE,
                    "DetailType": EVENT_DETAIL_TYPE,
                    "Detail": json.dumps(detail),
                }
            ]
        )
    except Exception as e:
        logger.error("Failed to publish audit event to EventBridge: %s", str(e))
        return

    if response.get("FailedEntryCount", 0) > 0:
        logger.error("EventBridge rejected the audit event: %s", response.get("Entries"))
