"""report.py -- Markdown report generator for report-mcp.

Decoupled from audit logic: takes the findings dict shape produced by any
*-audit-mcp server's audit tool (the common {category: [...], summary: {
...}} shape) and renders it as a client-ready report. `_CATEGORY_RENDERERS`
below is the registry of every category key currently recognized, across
ec2-audit-mcp, iam-audit-mcp, and s3-audit-mcp -- a category key not in
this table is skipped rather than crashing, so an unrecognized future
service's findings degrade gracefully (missing from the rendered table)
instead of breaking the whole report.

v1 ships Markdown only. HTML/PDF (WeasyPrint) are deferred -- see
report-mcp/main.py -- to keep this server's image lean while the
Fargate-vs-Lambda compute question for the suite is still being worked out.
"""

from datetime import datetime, timezone
from typing import Any, Callable

SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
SEVERITY_EMOJI = {
    "critical": "\U0001f534",
    "high": "\U0001f7e0",
    "medium": "\U0001f7e1",
    "low": "\U0001f7e2",
    "info": "⚪",
}

# category key -> (check label, resource-id extractor, issue-description extractor)
_CATEGORY_RENDERERS: dict[str, tuple[str, Callable[[dict], str], Callable[[dict], str]]] = {
    # ec2-audit-mcp
    "untagged_instances": (
        "Untagged Instance",
        lambda item: item["instance_id"],
        lambda item: f"Missing required tags: {', '.join(item['missing_tags'])}",
    ),
    "public_instances": (
        "Public IP Assigned",
        lambda item: item["instance_id"],
        lambda item: f"Instance has public IP: {item['public_ip']}",
    ),
    "security_group_issues": (
        "Permissive Security Group",
        lambda item: item["security_group_id"],
        lambda item: f"{item['issue']} (SG: {item['security_group_name']})",
    ),
    # iam-audit-mcp
    "console_users_without_mfa": (
        "Console User Without MFA",
        lambda item: item["user_name"],
        lambda item: "Console user has no MFA device attached",
    ),
    "old_access_keys": (
        "Stale Access Key",
        lambda item: item["access_key_id"],
        lambda item: (
            f"Access key for {item['user_name']} is {item['age_days']} days old "
            "(exceeds 90-day rotation threshold)"
        ),
    ),
    "root_account_risk": (
        "Root Account Risk",
        lambda item: item["resource"],
        lambda item: item["issue"],
    ),
    "unused_credentials": (
        "Unused Credential",
        lambda item: item.get("access_key_id") or item["user_name"],
        lambda item: (
            f"{item['credential_type'].replace('_', ' ').title()} for {item['user_name']} "
            f"last used {item.get('last_used') or 'never'}"
        ),
    ),
    # s3-audit-mcp
    "public_buckets": (
        "Public Bucket",
        lambda item: item["bucket_name"],
        lambda item: "Bucket is publicly accessible via ACL grant or bucket policy",
    ),
    "public_access_block_gaps": (
        "Public Access Block Gap",
        lambda item: item["bucket_name"],
        lambda item: f"Missing protections: {', '.join(item['missing_protections'])}",
    ),
    "unencrypted_buckets": (
        "Unencrypted Bucket",
        lambda item: item["bucket_name"],
        lambda item: "No default server-side encryption configured",
    ),
    "unversioned_buckets": (
        "Versioning Disabled",
        lambda item: item["bucket_name"],
        lambda item: "Versioning is not enabled",
    ),
}


def _all_findings(findings: dict[str, Any]) -> list[dict[str, Any]]:
    """Flatten all findings from all recognized check categories into a single sorted list."""
    flat = []

    for category, items in findings.items():
        renderer = _CATEGORY_RENDERERS.get(category)
        if renderer is None or not isinstance(items, list):
            continue

        check_label, resource_id_fn, issue_fn = renderer
        for item in items:
            flat.append(
                {
                    "check": check_label,
                    "resource_id": resource_id_fn(item),
                    "severity": item["severity"],
                    "issue": issue_fn(item),
                    "recommendation": item["recommendation"],
                }
            )

    flat.sort(key=lambda x: SEVERITY_ORDER.get(x["severity"], 99))
    return flat


def _risk_posture(summary: dict[str, Any]) -> str:
    if summary.get("critical", 0) > 0:
        return "CRITICAL RISK"
    elif summary.get("high", 0) > 0:
        return "HIGH RISK"
    elif summary.get("total_findings", 0) > 0:
        return "MODERATE RISK"
    else:
        return "CLEAN"


def _executive_summary(findings: dict[str, Any], region: str) -> str:
    """Generate a plain-English 2-3 sentence executive summary."""
    summary = findings.get("summary", {})
    total = summary.get("total_findings", 0)
    critical = summary.get("critical", 0)
    high = summary.get("high", 0)

    if total == 0:
        return (
            f"The audit of region **{region}** returned no findings. "
            "No immediate action is required."
        )

    counts: dict[str, int] = {}
    for item in _all_findings(findings):
        counts[item["check"]] = counts.get(item["check"], 0) + 1
    finding_list = ", ".join(f"{label} ({count})" for label, count in counts.items())

    urgency = ""
    if critical > 0:
        urgency = (
            f"**{critical} critical finding{'s' if critical > 1 else ''} "
            f"{'require' if critical > 1 else 'requires'} immediate remediation.** "
        )
    elif high > 0:
        urgency = f"**{high} high-severity finding{'s' if high > 1 else ''} should be addressed within 24-48 hours.** "

    return (
        f"The audit of region **{region}** identified **{total} finding{'s' if total > 1 else ''}** "
        f"across the following categories: {finding_list}. "
        f"{urgency}"
        "Full details and remediation steps are provided in the findings section below."
    )


def generate_markdown_report(
    findings: dict[str, Any],
    region: str = "unknown",
    account_id: str = "N/A",
) -> str:
    """Render audit findings as a Markdown string."""
    now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    all_items = _all_findings(findings)
    summary = findings.get("summary", {})
    total = summary.get("total_findings", 0)
    risk_label = _risk_posture(summary)

    lines = [
        "# AWS Infrastructure Audit Report",
        "",
        "| Field | Value |",
        "|---|---|",
        f"| **Account** | {account_id} |",
        f"| **Region** | {region} |",
        f"| **Scan Date** | {now} |",
        f"| **Overall Risk** | {risk_label} |",
        f"| **Total Findings** | {total} |",
        f"| **Critical** | {summary.get('critical', 0)} |",
        f"| **High** | {summary.get('high', 0)} |",
        "",
        "---",
        "",
        "## Executive Summary",
        "",
        _executive_summary(findings, region),
        "",
        "---",
        "",
    ]

    if all_items:
        lines += [
            "## Findings",
            "",
            "| Severity | Check | Resource ID | Issue |",
            "|---|---|---|---|",
        ]
        for item in all_items:
            sev = item["severity"].upper()
            emoji = SEVERITY_EMOJI.get(item["severity"], "")
            lines.append(f"| {emoji} {sev} | {item['check']} | `{item['resource_id']}` | {item['issue']} |")
        lines += ["", "---", ""]

        lines += ["## Finding Details", ""]
        for i, item in enumerate(all_items, start=1):
            emoji = SEVERITY_EMOJI.get(item["severity"], "")
            lines += [
                f"### {i}. {emoji} {item['check']} -- `{item['resource_id']}`",
                "",
                f"**Severity:** {item['severity'].upper()}  ",
                f"**Resource:** `{item['resource_id']}`  ",
                f"**Issue:** {item['issue']}  ",
                f"**Recommendation:** {item['recommendation']}",
                "",
            ]
        lines += ["---", ""]

    lines += [
        "*Report generated by CoreSample -- audit logic, model invocation, and AWS API "
        "calls all run inside the account boundary.*",
        "",
    ]

    return "\n".join(lines)
