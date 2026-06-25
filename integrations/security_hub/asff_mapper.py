"""
asff_mapper.py

Maps CoreSample audit findings to AWS Security Finding Format (ASFF)
for ingestion into AWS Security Hub via BatchImportFindings.

Once findings land in Security Hub, they automatically correlate alongside
GuardDuty / Inspector / IAM Access Analyzer findings on the same resource,
and Security Hub emits a "Security Hub Findings - Imported" EventBridge
event you can route to Splunk, Datadog, SNS/Slack, or a SOAR playbook.

Status: wired, not yet activated against live Security Hub. The
finding-shape gap this module's docstring used to describe is closed --
`findings_dict_to_asff_findings()` below maps the raw {category: [...]}
shape the live audit services (ec2-audit-mcp/iam-audit-mcp/s3-audit-mcp)
actually produce into `CoreSampleFinding`s, deriving `resource_arn` per
category (the live services never carry an ARN themselves -- see
CATEGORY_MAP) and taking `account_id`/`region` as caller-supplied
arguments rather than per-finding fields, since both are uniform across
one audit run. The remaining gap is real-world activation: this hasn't
run against a live Security Hub instance, and `ENABLE_SECURITY_HUB_EXPORT`
defaults to false. See `exporter/handler.py` for the Lambda that calls
this, and the README's "Current status" entry for the full picture.

Reference: https://docs.aws.amazon.com/securityhub/latest/userguide/securityhub-findings-format.html
"""

from __future__ import annotations

import datetime
import hashlib
import os
from dataclasses import dataclass, field
from typing import Any, Callable, NamedTuple, Optional

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
# 3. Mapping the live audit services' raw findings into CoreSampleFindings
# ---------------------------------------------------------------------------
# ec2-audit-mcp/iam-audit-mcp/s3-audit-mcp findings are plain dicts keyed by
# category (e.g. "untagged_instances", "public_buckets") -- the same shape
# report.py's _CATEGORY_RENDERERS table already maps to Markdown rows. This
# table is the ASFF equivalent: it doesn't import report.py (this module
# ships in its own Lambda deployment package, separate from report-mcp), so
# it duplicates the *shape knowledge* of each category, not the rendering
# logic itself.
#
# resource_id is the raw identifier already present on each finding
# (instance_id, bucket_name, user_name, ...). arn builds the full ARN from
# that id plus the account_id/region the caller supplies -- IAM and S3 ARNs
# don't take the same segments as EC2 ARNs, hence a per-category builder
# rather than one shared template.
#
# IAM access keys and the root account have no AWS-recognized ARN of their
# own, so those categories point at the parent identity that does have one
# (the IAM user, or the account root user) -- this is the expected ASFF
# pattern when the underlying issue isn't independently addressable as its
# own resource.


class CategoryMapping(NamedTuple):
    check_id: str
    resource_type: str
    resource_id: Callable[[dict], str]
    arn: Callable[[str, str, dict, str], str]
    title: Callable[[dict, str], str]
    description: Callable[[dict, str], str]


CATEGORY_MAP: dict[str, CategoryMapping] = {
    # ec2-audit-mcp
    "untagged_instances": CategoryMapping(
        check_id="EC2_UNTAGGED_INSTANCE",
        resource_type="AwsEc2Instance",
        resource_id=lambda item: item["instance_id"],
        arn=lambda account_id, region, item, rid: f"arn:aws:ec2:{region}:{account_id}:instance/{rid}",
        title=lambda item, rid: f"EC2 instance missing required tags: {rid}",
        description=lambda item, rid: (
            f"Instance {rid} is missing required tags: {', '.join(item['missing_tags'])}."
        ),
    ),
    "public_instances": CategoryMapping(
        check_id="EC2_PUBLIC_IP_ASSIGNED",
        resource_type="AwsEc2Instance",
        resource_id=lambda item: item["instance_id"],
        arn=lambda account_id, region, item, rid: f"arn:aws:ec2:{region}:{account_id}:instance/{rid}",
        title=lambda item, rid: f"EC2 instance has a public IP: {rid}",
        description=lambda item, rid: f"Instance {rid} has public IP {item['public_ip']} assigned.",
    ),
    "security_group_issues": CategoryMapping(
        check_id="EC2_PERMISSIVE_SECURITY_GROUP",
        resource_type="AwsEc2SecurityGroup",
        resource_id=lambda item: item["security_group_id"],
        arn=lambda account_id, region, item, rid: (
            f"arn:aws:ec2:{region}:{account_id}:security-group/{rid}"
        ),
        title=lambda item, rid: f"Permissive security group: {rid}",
        description=lambda item, rid: (
            f"Security group {rid} ({item['security_group_name']}): {item['issue']}."
        ),
    ),
    # iam-audit-mcp -- access keys/root have no ARN of their own, so these
    # point at the parent IAM user or the account root user instead.
    "console_users_without_mfa": CategoryMapping(
        check_id="IAM_CONSOLE_USER_WITHOUT_MFA",
        resource_type="AwsIamUser",
        resource_id=lambda item: item["user_name"],
        arn=lambda account_id, region, item, rid: f"arn:aws:iam::{account_id}:user/{rid}",
        title=lambda item, rid: f"Console user without MFA: {rid}",
        description=lambda item, rid: (
            f"IAM user {rid} has console access but no MFA device attached."
        ),
    ),
    "old_access_keys": CategoryMapping(
        check_id="IAM_STALE_ACCESS_KEY",
        resource_type="AwsIamUser",
        resource_id=lambda item: item["user_name"],
        arn=lambda account_id, region, item, rid: f"arn:aws:iam::{account_id}:user/{rid}",
        title=lambda item, rid: f"Stale access key for user: {rid}",
        description=lambda item, rid: (
            f"Access key {item['access_key_id']} for user {rid} is {item['age_days']} days "
            "old, exceeding the 90-day rotation threshold."
        ),
    ),
    "root_account_risk": CategoryMapping(
        check_id="IAM_ROOT_ACCOUNT_RISK",
        resource_type="AwsAccount",
        resource_id=lambda item: "root_account",
        arn=lambda account_id, region, item, rid: f"arn:aws:iam::{account_id}:root",
        title=lambda item, rid: "Root account risk",
        description=lambda item, rid: item["issue"],
    ),
    "unused_credentials": CategoryMapping(
        check_id="IAM_UNUSED_CREDENTIAL",
        resource_type="AwsIamUser",
        resource_id=lambda item: item["user_name"],
        arn=lambda account_id, region, item, rid: f"arn:aws:iam::{account_id}:user/{rid}",
        title=lambda item, rid: f"Unused credential for user: {rid}",
        description=lambda item, rid: (
            f"{item['credential_type'].replace('_', ' ').title()} for user {rid} last used "
            f"{item.get('last_used') or 'never'}."
        ),
    ),
    # s3-audit-mcp -- bucket ARNs carry neither account_id nor region.
    "public_buckets": CategoryMapping(
        check_id="S3_PUBLIC_BUCKET",
        resource_type="AwsS3Bucket",
        resource_id=lambda item: item["bucket_name"],
        arn=lambda account_id, region, item, rid: f"arn:aws:s3:::{rid}",
        title=lambda item, rid: f"Publicly accessible S3 bucket: {rid}",
        description=lambda item, rid: (
            f"Bucket {rid} is publicly accessible via ACL grant or bucket policy."
        ),
    ),
    "public_access_block_gaps": CategoryMapping(
        check_id="S3_PUBLIC_ACCESS_BLOCK_GAP",
        resource_type="AwsS3Bucket",
        resource_id=lambda item: item["bucket_name"],
        arn=lambda account_id, region, item, rid: f"arn:aws:s3:::{rid}",
        title=lambda item, rid: f"S3 Block Public Access gap: {rid}",
        description=lambda item, rid: (
            f"Bucket {rid} is missing protections: {', '.join(item['missing_protections'])}."
        ),
    ),
    "unencrypted_buckets": CategoryMapping(
        check_id="S3_UNENCRYPTED_BUCKET",
        resource_type="AwsS3Bucket",
        resource_id=lambda item: item["bucket_name"],
        arn=lambda account_id, region, item, rid: f"arn:aws:s3:::{rid}",
        title=lambda item, rid: f"S3 bucket without default encryption: {rid}",
        description=lambda item, rid: (
            f"Bucket {rid} has no default server-side encryption configured."
        ),
    ),
    "unversioned_buckets": CategoryMapping(
        check_id="S3_VERSIONING_DISABLED",
        resource_type="AwsS3Bucket",
        resource_id=lambda item: item["bucket_name"],
        arn=lambda account_id, region, item, rid: f"arn:aws:s3:::{rid}",
        title=lambda item, rid: f"S3 bucket without versioning: {rid}",
        description=lambda item, rid: f"Bucket {rid} does not have versioning enabled.",
    ),
}


def findings_dict_to_asff_findings(
    findings: dict[str, Any], account_id: str, region: str
) -> list[CoreSampleFinding]:
    """
    Convert the merged {category: [...]} findings dict (the same shape
    report.py renders to Markdown) into CoreSampleFindings ready for
    to_asff()/batch_import().

    account_id and region are taken as arguments rather than read from the
    findings dict because CoreSample is single-account/single-region per
    audit run -- both are uniform across every finding in one call, so
    there's no need for the live audit services to carry either field
    per-finding. A category with no entry in CATEGORY_MAP (e.g. a future
    audit service's output) is skipped rather than raising, matching
    report.py's _all_findings() behavior for unrecognized categories.
    """
    results: list[CoreSampleFinding] = []

    for category, items in findings.items():
        mapping = CATEGORY_MAP.get(category)
        if mapping is None or not isinstance(items, list):
            continue

        for item in items:
            resource_id = mapping.resource_id(item)
            results.append(
                CoreSampleFinding(
                    check_id=mapping.check_id,
                    title=mapping.title(item, resource_id),
                    description=mapping.description(item, resource_id),
                    severity=item.get("severity", "informational"),
                    resource_arn=mapping.arn(account_id, region, item, resource_id),
                    resource_type=mapping.resource_type,
                    region=region,
                    account_id=account_id,
                    remediation_text=item.get("recommendation"),
                )
            )

    return results


# ---------------------------------------------------------------------------
# 4. Example usage — what wiring this into CoreSample's output stage looks like
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
