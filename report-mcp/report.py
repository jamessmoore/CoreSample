"""report.py -- Markdown report generator for report-mcp.

Decoupled from audit logic: takes the findings dict shape produced by
ec2-audit-mcp's audit_ec2 tool (or any future *-audit-mcp server using the
same {category: [...], summary: {...}} shape) and renders it as a
client-ready report.

v1 ships Markdown only. HTML/PDF (WeasyPrint) are deferred -- see
report-mcp/main.py -- to keep this server's image lean while the
Fargate-vs-Lambda compute question for the suite is still being worked out.
"""

from datetime import datetime, timezone
from typing import Any

SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
SEVERITY_EMOJI = {
    "critical": "\U0001f534",
    "high": "\U0001f7e0",
    "medium": "\U0001f7e1",
    "low": "\U0001f7e2",
    "info": "⚪",
}


def _all_findings(findings: dict[str, Any]) -> list[dict[str, Any]]:
    """Flatten all findings from all check categories into a single sorted list."""
    flat = []

    for item in findings.get("untagged_instances", []):
        flat.append(
            {
                "check": "Untagged Instance",
                "resource_id": item["instance_id"],
                "severity": item["severity"],
                "issue": f"Missing required tags: {', '.join(item['missing_tags'])}",
                "recommendation": item["recommendation"],
            }
        )

    for item in findings.get("public_instances", []):
        flat.append(
            {
                "check": "Public IP Assigned",
                "resource_id": item["instance_id"],
                "severity": item["severity"],
                "issue": f"Instance has public IP: {item['public_ip']}",
                "recommendation": item["recommendation"],
            }
        )

    for item in findings.get("security_group_issues", []):
        flat.append(
            {
                "check": "Permissive Security Group",
                "resource_id": item["security_group_id"],
                "severity": item["severity"],
                "issue": f"{item['issue']} (SG: {item['security_group_name']})",
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
    untagged = len(findings.get("untagged_instances", []))
    public_ips = len(findings.get("public_instances", []))
    sg_issues = len(findings.get("security_group_issues", []))

    if total == 0:
        return (
            f"The EC2 audit of region **{region}** returned no findings. "
            "All scanned instances are tagged correctly, have no unnecessary public IPs, "
            "and all security groups restrict inbound access appropriately. "
            "No immediate action is required."
        )

    parts = []
    if untagged:
        parts.append(f"{untagged} untagged instance{'s' if untagged > 1 else ''}")
    if public_ips:
        parts.append(f"{public_ips} instance{'s' if public_ips > 1 else ''} with public IPs")
    if sg_issues:
        parts.append(f"{sg_issues} overly permissive security group rule{'s' if sg_issues > 1 else ''}")

    finding_list = ", ".join(parts[:-1]) + (" and " if len(parts) > 1 else "") + parts[-1]

    urgency = ""
    if critical > 0:
        urgency = (
            f"**{critical} critical finding{'s' if critical > 1 else ''} "
            f"{'require' if critical > 1 else 'requires'} immediate remediation** -- "
            "open SSH or RDP access from the internet represents active attack surface. "
        )
    elif high > 0:
        urgency = f"**{high} high-severity finding{'s' if high > 1 else ''} should be addressed within 24-48 hours.** "

    return (
        f"The EC2 audit of region **{region}** identified **{total} finding{'s' if total > 1 else ''}** "
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
