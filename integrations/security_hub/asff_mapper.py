"""
asff_mapper.py

Maps CoreSample audit findings to AWS Security Finding Format (ASFF)
for ingestion into AWS Security Hub via BatchImportFindings.

Once findings land in Security Hub, they automatically correlate alongside
GuardDuty / Inspector / IAM Access Analyzer findings on the same resource,
and Security Hub emits a "Security Hub Findings - Imported" EventBridge
event you can route to Splunk, Datadog, SNS/Slack, or a SOAR playbook.

Status: designed, not yet activated. `CoreSampleFinding`'s shape
(resource_arn, resource_type, account_id, region, compliance_controls)
doesn't match what the live audit services produce today -- they don't
carry that information per-finding yet. Wiring this into the real
audit/report pipeline requires plumbing those fields through first. See
the README's "Future expansions" entry for the full status.

Reference: https://docs.aws.amazon.com/securityhub/latest/userguide/securityhub-findings-format.html
"""

from __future__ import annotations

import datetime
import hashlib
import os
from dataclasses import dataclass, field
from typing import Optional

import boto3


# ---------------------------------------------------------------------------
# 1. Your existing CoreSample finding shape (adjust to match reality)
# ---------------------------------------------------------------------------

@dataclass
class CoreSampleFinding:
    """Whatever CoreSample's audit logic already produces internally."""
    check_id: str            # e.g. "IAM_OVERLY_PERMISSIVE_POLICY"
    title: str                # short human-readable title
    description: str          # full explanation
    severity: str              # CoreSample's own scale, e.g. "high" | "medium" | "low"
    resource_arn: str          # the AWS resource this finding is about
    resource_type: str         # e.g. "AwsIamRole", "AwsEc2SecurityGroup"
    region: str
    account_id: str
    remediation_text: Optional[str] = None
    compliance_controls: list[str] = field(default_factory=list)  # e.g. ["CJIS-5.5", "SOC2-CC6.1"]


# ---------------------------------------------------------------------------
# 2. Severity mapping — CoreSample scale -> ASFF Severity.Label
# ---------------------------------------------------------------------------
# Per AWS guidance:
#   INFORMATIONAL - passed/warning/no-action checks
#   LOW           - could result in future compromise (config weaknesses)
#   MEDIUM        - indicates active compromise, no completed objective
#   HIGH/CRITICAL - adversary completed their objective
#
# CoreSample is a posture/config auditor, not a runtime detector, so its
# findings should almost always map to INFORMATIONAL/LOW/MEDIUM — it is
# reporting exposure, not confirmed breach. Reserve CRITICAL for cases
# where you've confirmed actual public exposure of sensitive data.
#
# Both "info" and "informational" are mapped -- the live audit services
# (ec2-audit-mcp, iam-audit-mcp, s3-audit-mcp) use "info", not the longer
# form, as their lowest severity value.

SEVERITY_MAP = {
    "critical": ("CRITICAL", 90),
    "high": ("HIGH", 70),
    "medium": ("MEDIUM", 40),
    "low": ("LOW", 20),
    "informational": ("INFORMATIONAL", 0),
    "info": ("INFORMATIONAL", 0),
}

PRODUCT_NAME = "CoreSample"
COMPANY_NAME = "Moore Solutions"


def calculate_finding_id(account_id: str, region: str, check_id: str, resource_arn: str) -> str:
    """
    Deterministic finding ID so re-running CoreSample on an unchanged
    resource UPDATES the existing finding instead of creating a duplicate.
    Security Hub treats matching Id as an update if UpdatedAt is newer.
    """
    raw = f"{account_id}:{region}:{check_id}:{resource_arn}"
    return hashlib.sha256(raw.encode()).hexdigest()


def to_asff(finding: CoreSampleFinding, security_hub_account_id: str) -> dict:
    """
    Convert a single CoreSampleFinding into an ASFF-compliant dict,
    ready to pass into securityhub.batch_import_findings(Findings=[...]).
    """
    now = datetime.datetime.now(datetime.timezone.utc).isoformat()
    label, normalized_score = SEVERITY_MAP.get(finding.severity.lower(), ("INFORMATIONAL", 0))

    finding_id = calculate_finding_id(
        finding.account_id, finding.region, finding.check_id, finding.resource_arn
    )

    asff_finding = {
        "SchemaVersion": "2018-10-08",
        "Id": finding_id,
        "ProductArn": (
            f"arn:aws:securityhub:{finding.region}:{security_hub_account_id}"
            f":product/{security_hub_account_id}/default"
        ),
        "GeneratorId": f"coresample/{finding.check_id}",
        "AwsAccountId": finding.account_id,
        "Types": [f"Software and Configuration Checks/{COMPANY_NAME}/{finding.check_id}"],
        "CreatedAt": now,
        "UpdatedAt": now,
        "Severity": {
            "Label": label,
            "Normalized": normalized_score,
            "Original": finding.severity,
        },
        "Title": finding.title[:256],
        "Description": finding.description[:1024],
        "Resources": [
            {
                "Type": finding.resource_type,
                "Id": finding.resource_arn,
                "Region": finding.region,
                "Partition": "aws",
            }
        ],
        "ProductFields": {
            "Provider": COMPANY_NAME,
            "CoreSampleCheckId": finding.check_id,
        },
        "RecordState": "ACTIVE",
        "WorkflowState": "NEW",
    }

    if finding.remediation_text:
        asff_finding["Remediation"] = {
            "Recommendation": {
                "Text": finding.remediation_text[:512],
            }
        }

    # Only populate Compliance if this finding maps to specific controls —
    # AWS guidance is explicit that Compliance should be reserved for
    # compliance-related findings, not used as a catch-all.
    if finding.compliance_controls:
        asff_finding["Compliance"] = {
            "Status": "FAILED",
            "RelatedRequirements": finding.compliance_controls,
        }

    return asff_finding


def batch_import(findings: list[CoreSampleFinding], security_hub_account_id: str, region: str):
    """
    Sends up to 100 findings per call (AWS hard limit) to Security Hub.
    Chunking is the caller's responsibility for >100 findings per run.

    Gated by ENABLE_SECURITY_HUB_EXPORT -- nothing in CoreSample's live
    audit/report pipeline calls this yet, so this guard is the only thing
    standing between "designed" and "active" once something does.
    """
    if os.environ.get("ENABLE_SECURITY_HUB_EXPORT", "false").lower() != "true":
        raise RuntimeError(
            "Security Hub export is disabled; set ENABLE_SECURITY_HUB_EXPORT=true to enable."
        )

    client = boto3.client("securityhub", region_name=region)
    asff_findings = [to_asff(f, security_hub_account_id) for f in findings]

    response = client.batch_import_findings(Findings=asff_findings)

    if response.get("FailedCount", 0) > 0:
        # In production: log response["FailedFindings"] with their ErrorCode/ErrorMessage
        # and consider routing failures to a dead-letter queue rather than silently dropping.
        raise RuntimeError(
            f"{response['FailedCount']} findings failed to import: {response['FailedFindings']}"
        )

    return response


# ---------------------------------------------------------------------------
# 3. Example usage — what wiring this into CoreSample's output stage looks like
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    example_findings = [
        CoreSampleFinding(
            check_id="IAM_OVERLY_PERMISSIVE_POLICY",
            title="IAM role grants iam:* on all resources",
            description=(
                "Role arn:aws:iam::123456789012:role/legacy-deploy-role attaches a "
                "policy granting iam:* across all resources (Resource: *), violating "
                "least-privilege. No resource-level or condition-key constraints present."
            ),
            severity="high",
            resource_arn="arn:aws:iam::123456789012:role/legacy-deploy-role",
            resource_type="AwsIamRole",
            region="us-east-1",
            account_id="123456789012",
            remediation_text=(
                "Scope the policy to specific resource ARNs and required actions only; "
                "remove iam:* wildcard and add an explicit Deny for cross-account PassRole."
            ),
            compliance_controls=["CJIS-5.5.2", "SOC2-CC6.1"],
        ),
        CoreSampleFinding(
            check_id="SG_OPEN_INGRESS_22",
            title="Security group allows SSH (22) from 0.0.0.0/0",
            description=(
                "Security group sg-0abc123 permits inbound TCP/22 from 0.0.0.0/0, "
                "exposing SSH to the entire internet."
            ),
            severity="critical",
            resource_arn="arn:aws:ec2:us-east-1:123456789012:security-group/sg-0abc123",
            resource_type="AwsEc2SecurityGroup",
            region="us-east-1",
            account_id="123456789012",
            remediation_text="Restrict ingress to known CIDR ranges or require SSM Session Manager instead of direct SSH.",
            compliance_controls=["CJIS-5.10.1"],
        ),
    ]

    for f in example_findings:
        import json
        print(json.dumps(to_asff(f, security_hub_account_id="123456789012"), indent=2))
        print("---")
