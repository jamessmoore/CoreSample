"""
exporter/handler.py

Lambda entrypoint for AWS Security Hub ASFF export. Subscribed via an
EventBridge rule (terraform/security_hub_exporter.tf) to the
"AuditReportGenerated" event report-mcp's eventbridge.py publishes after a
report is generated. The Bedrock Agent never sees this Lambda and has no
tool definition that could invoke it -- whether a finding gets logged to
Security Hub is a deterministic, post-audit step, not an LLM decision.

Gated by ENABLE_SECURITY_HUB_EXPORT: when unset/false, this no-ops before
touching AWS at all, so the EventBridge rule can stay enabled in Terraform
with zero side effects until a real Security Hub subscription exists.

account_id is deliberately NOT read from the event. It's derived from this
Lambda's own execution context (invoked_function_arn), which needs zero
IAM permissions and doesn't depend on report-mcp (or anything upstream of
it, including the LLM) supplying an accurate value. This only works
because CoreSample is single-account/single-region by design -- the
account this Lambda runs in is always the account being audited.
"""

import logging
import os

from asff_mapper import batch_import, findings_dict_to_asff_findings

# logging.basicConfig() is a no-op here -- the Lambda runtime pre-attaches
# its own handler to the root logger before this module ever loads, and
# that root logger defaults to WARNING. Without an explicit setLevel() on
# *this* logger, every logger.info() call below is silently dropped --
# confirmed against a real deployed invocation, where the no-op path ran
# correctly but left zero log output. setLevel() on the named logger (not
# basicConfig on root) is what actually fixes it.
logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)


def _account_id_from_context(context) -> str:
    """invoked_function_arn: arn:aws:lambda:{region}:{account_id}:function:{name}"""
    return context.invoked_function_arn.split(":")[4]


def lambda_handler(event, context):
    if os.environ.get("ENABLE_SECURITY_HUB_EXPORT", "false").lower() != "true":
        logger.info("Security Hub export disabled (ENABLE_SECURITY_HUB_EXPORT != true); no-op.")
        return {"status": "disabled"}

    detail = event.get("detail", {})
    findings = detail.get("findings", {})
    region = detail.get("region", "unknown")
    account_id = _account_id_from_context(context)

    mapped = findings_dict_to_asff_findings(findings, account_id=account_id, region=region)
    if not mapped:
        logger.info("No mappable findings in event; nothing to export to Security Hub.")
        return {"status": "no_findings"}

    logger.info(
        "Exporting %d finding(s) to Security Hub for account %s region %s",
        len(mapped),
        account_id,
        region,
    )
    response = batch_import(mapped, security_hub_account_id=account_id, region=region)
    return {"status": "exported", "failed_count": response.get("FailedCount", 0)}
