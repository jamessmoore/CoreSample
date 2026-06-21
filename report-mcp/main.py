import json
import logging
import os

from mcp.server.fastmcp import FastMCP
from starlette.requests import Request
from starlette.responses import PlainTextResponse

from report import generate_markdown_report

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

mcp = FastMCP("report-mcp", host="0.0.0.0", port=int(os.environ.get("PORT", "8000")))


@mcp.custom_route("/health", methods=["GET"])
async def health(_request: Request) -> PlainTextResponse:
    # ALB target group health check -- GET /mcp returns 406 since the MCP
    # streamable-http endpoint requires MCP-specific Accept headers.
    return PlainTextResponse("ok")


@mcp.tool()
def generate_report(
    audit_json: str,
    format: str = "markdown",
    region: str = "unknown",
    account_id: str = "N/A",
) -> str:
    """
    Generate a formatted audit report from the JSON output of an audit tool
    (e.g. ec2-audit-mcp's audit_ec2). Decoupled from any specific audit
    server -- accepts the {category: [...], summary: {...}} findings shape.

    Args:
        audit_json:  JSON string from an audit tool
        format:      Output format -- only "markdown" is implemented in v1.
                     "html"/"pdf" are queued (WeasyPrint adds real image
                     weight; deferring until needed keeps this server lean).
        region:      AWS region that was audited (for report header)
        account_id:  AWS account ID or alias (for report header, optional)

    Returns:
        Markdown report string, or an error/not-implemented JSON object.
    """
    try:
        findings = json.loads(audit_json)
    except json.JSONDecodeError as e:
        return json.dumps({"error": f"Invalid audit_json -- could not parse: {str(e)}"})

    fmt = format.lower().strip()

    if fmt == "markdown":
        return generate_markdown_report(findings, region=region, account_id=account_id)

    if fmt in ("html", "pdf"):
        return json.dumps(
            {
                "error": f"format '{fmt}' is not implemented yet",
                "fallback": "markdown",
                "report": generate_markdown_report(findings, region=region, account_id=account_id),
            }
        )

    return json.dumps({"error": f"Unknown format '{format}'. Supported: markdown"})


if __name__ == "__main__":
    mcp.run(transport="streamable-http")
