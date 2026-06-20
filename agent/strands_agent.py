"""Builds the Strands Agent: Claude via Bedrock as the model, with the
AgentCore Gateway's MCP tools (ec2-audit-mcp, report-mcp) as its tools.

The Gateway's inbound authorizer is AWS_IAM (see
terraform/agentcore_gateway.tf), so the MCP client signs its requests with
this Runtime's own execution-role credentials via SigV4 -- mcp-proxy-for-aws
handles that signing; nothing here ever touches the audited account's
credentials directly.
"""

import os

from mcp_proxy_for_aws.client import aws_iam_streamablehttp_client
from strands import Agent
from strands.models import BedrockModel
from strands.tools.mcp import MCPClient

GATEWAY_URL = os.environ["GATEWAY_URL"]  # AgentCore Gateway's gateway_url + "/mcp"
BEDROCK_MODEL_ID = os.environ["BEDROCK_MODEL_ID"]

SYSTEM_PROMPT = """\
You are CoreSample, an AWS infrastructure security and compliance auditor.
You have access to tools that run real, read-only checks against the
customer's own AWS account -- you never receive or handle AWS credentials
yourself; the tools execute under their own scoped IAM roles inside the
account boundary.

When asked to audit an account or region:
1. Call the EC2 audit tool for the target region to get raw findings.
2. Pass those findings to the report generation tool to produce a
   client-ready Markdown report.
3. Summarize the key risks (especially anything CRITICAL or HIGH
   severity) in your own response, and reference the full report.

Be precise about severity and specific about remediation. Don't speculate
about resources you haven't actually queried.
"""


def build_agent() -> Agent:
    mcp_client = MCPClient(
        lambda: aws_iam_streamablehttp_client(
            endpoint=GATEWAY_URL,
            aws_service="bedrock-agentcore",
        )
    )
    model = BedrockModel(model_id=BEDROCK_MODEL_ID, max_tokens=8192)
    return Agent(model=model, system_prompt=SYSTEM_PROMPT, tools=[mcp_client])
