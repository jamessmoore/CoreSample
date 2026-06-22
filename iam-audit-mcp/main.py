import json
import logging
import os

from mcp.server.fastmcp import FastMCP
from starlette.requests import Request
from starlette.responses import PlainTextResponse

from audit import IAMAuditor

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# AgentCore Gateway calls MCP targets over HTTP, not stdio -- a Gateway
# can't spawn this as a local subprocess the way a CLI-based MCP client
# would. Streamable HTTP is the current MCP transport for network-reachable
# servers (the older HTTP+SSE transport is being phased out in favor of it).
mcp = FastMCP("iam-audit-mcp", host="0.0.0.0", port=int(os.environ.get("PORT", "8000")))


@mcp.custom_route("/health", methods=["GET"])
async def health(_request: Request) -> PlainTextResponse:
    # ALB target group health check -- GET /mcp returns 406 since the MCP
    # streamable-http endpoint requires MCP-specific Accept headers.
    return PlainTextResponse("ok")


@mcp.tool()
def audit_iam(region: str) -> str:
    """
    Audit IAM users and the root account for compliance and security issues.

    Credentials are never passed in -- this server always uses the Fargate
    task's IAM role (boto3's default credential chain), scoped read-only to
    IAM list/get actions. The audited account's credentials never leave the
    account boundary and can't be substituted by a caller.

    IAM is a global service, so this call ignores `region` and always
    audits the account as a whole. The parameter is kept for interface
    consistency with `audit_ec2`.

    Args:
        region: AWS region (ignored -- IAM is global)

    Returns:
        JSON string containing audit findings
    """
    try:
        findings = IAMAuditor(region).audit()
        logger.info(
            "Audit complete. Found %d issues.",
            findings["summary"]["total_findings"],
        )
        return json.dumps(findings, indent=2, default=str)

    except Exception as e:
        logger.error("Audit failed: %s", str(e))
        return json.dumps({"error": str(e)}, indent=2)


if __name__ == "__main__":
    mcp.run(transport="streamable-http")
