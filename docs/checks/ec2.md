# EC2 audit checks

Implemented in `ec2-audit-mcp/audit.py` (`EC2Auditor`). Three checks, each
its own key in the JSON returned by the `audit_ec2` tool.

## Untagged instances

**What it checks** — Running or stopped EC2 instances missing one or more
of the required tags: `Name`, `Environment`, `Owner`.

**Why it matters** — Untagged instances are invisible to cost allocation
reports and ownership tracking, which makes incident response and
decommissioning slower and error-prone.

**Severity** — `high`

**Example finding**

```json
{
  "instance_id": "i-0123456789abcdef0",
  "missing_tags": ["Environment", "Owner"],
  "severity": "high",
  "recommendation": "Add missing tags for compliance and cost tracking"
}
```

**Remediation** — Apply the missing tags via the console, CLI, or your IaC
tool of record. Consider an AWS Config rule (`required-tags`) to prevent
future drift.

## Public IP assignments

**What it checks** — Running instances with a public IP address attached
(`PublicIpAddress` present in `describe_instances`).

**Why it matters** — A public IP is a direct internet-reachable surface.
Even with a security group in front of it, it's one less layer of
defense-in-depth than routing through a NAT gateway or bastion host.

**Severity** — `medium`

**Example finding**

```json
{
  "instance_id": "i-0123456789abcdef0",
  "public_ip": "54.1.2.3",
  "severity": "medium",
  "recommendation": "Review if public IP is necessary; consider NAT or bastion host"
}
```

**Remediation** — Move the instance to a private subnet and route
outbound traffic through a NAT gateway, or front inbound access with a
bastion host / SSM Session Manager instead of a public IP.

## Overly permissive security groups

**What it checks** — Security group rules that allow inbound access from
`0.0.0.0/0` (any source).

**Why it matters** — World-open ingress is the most common root cause of
opportunistic compromise. SSH (22) and RDP (3389) open to the world are
especially high-value targets for credential-stuffing and brute-force
bots.

**Severity** — `critical` for SSH (22) or RDP (3389); `high` for any other
port

**Example finding**

```json
{
  "security_group_id": "sg-0123456789abcdef0",
  "security_group_name": "open-ssh",
  "issue": "Allows world access on port 22",
  "severity": "critical",
  "recommendation": "Restrict CIDR to known IPs or use security group references"
}
```

**Remediation** — Restrict the rule's CIDR to known, specific IP ranges, or
replace it with a security-group reference scoped to the resources that
actually need access.
