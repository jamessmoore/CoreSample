import json
import logging
import os

from mcp.server.fastmcp import FastMCP

from audit import EC2Auditor

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# AgentCore Gateway calls MCP targets over HTTP, not stdio -- a Gateway
# can't spawn this as a local subprocess the way a CLI-based MCP client
# would. Streamable HTTP is the current MCP transport for network-reachable
# servers (the older HTTP+SSE transport is being phased out in favor of it).
mcp = FastMCP("ec2-audit-mcp", host="0.0.0.0", port=int(os.environ.get("PORT", "8000")))


@mcp.tool()
def audit_ec2(region: str) -> str:
    """
    Audit EC2 infrastructure for compliance and security issues.

    Credentials are never passed in -- this server always uses the Fargate
    task's IAM role (boto3's default credential chain), scoped read-only to
    EC2 describe* actions. The audited account's credentials never leave
    the account boundary and can't be substituted by a caller.

    Args:
        region: AWS region to audit (e.g., 'us-east-1')

    Returns:
        JSON string containing audit findings
    """
    try:
        findings = EC2Auditor(region).audit()
        logger.info(
            "Audit complete for region %s. Found %d issues.",
            region,
            findings["summary"]["total_findings"],
        )
        return json.dumps(findings, indent=2, default=str)

    except Exception as e:
        logger.error("Audit failed: %s", str(e))
        return json.dumps({"error": str(e)}, indent=2)


if __name__ == "__main__":
    mcp.run(transport="streamable-http")
