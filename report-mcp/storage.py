"""S3 persistence for generated reports.

Kept separate from report.py, which stays pure markdown rendering with no
AWS API calls of its own (and is tested that way) -- this module is the
only part of report-mcp that touches AWS.
"""

import logging
from datetime import datetime, timezone

import boto3

logger = logging.getLogger(__name__)


def upload_report(content: str, bucket: str, region: str, account_id: str) -> str:
    """Upload a report to S3 and return its s3:// URI."""
    timestamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    safe_account = account_id.replace("/", "-").replace(" ", "-")
    key = f"reports/{safe_account}/{region}/{timestamp}.md"

    s3 = boto3.client("s3")
    s3.put_object(
        Bucket=bucket,
        Key=key,
        Body=content.encode("utf-8"),
        ContentType="text/markdown",
    )

    uri = f"s3://{bucket}/{key}"
    logger.info("Report uploaded to %s", uri)
    return uri
