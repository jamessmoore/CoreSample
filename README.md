# CoreSample

An AWS-native security/compliance audit framework. The audit logic, the
foundation-model invocation, and the AWS API calls it makes all run *inside*
the account boundary — no external service reaches in to inspect your
infrastructure. That's the differentiator for compliance-minded buyers, and
the proof-of-concept behind this repo.

This is the evolution of [`aws-audit-mcp`](https://github.com/jamessmoore/aws-audit-mcp),
re-platformed onto Amazon Bedrock as the foundation-model layer instead of an
external API.

## Architecture

```
Strands Agent (on AgentCore Runtime)
  - Foundation model: Claude via Bedrock
  - MCP client (IAM/SigV4) -> AgentCore Gateway
        v
AgentCore Gateway (MCP layer, AWS_IAM inbound auth)
  - Exposes MCP server(s) as agent-callable tools
  - Outbound auth: SigV4, signed as "execute-api"
        v
API Gateway (HTTP API) + VPC Link  <- HTTPS + SigV4 verification, both
        v                             required by the Gateway target and
Internal ALB                          neither satisfied by a bare ALB
        v
ECS Fargate
  - ec2-audit-mcp   (untagged instances, public IPs, permissive security groups)
  - report-mcp      (findings -> client-ready Markdown report)
        |  read-only IAM role, scoped per service
        v
Target AWS account (the account being audited -- my own, for v1)
```

**This is not what the original kickoff plan described.** The first pass at
this scaffold used a classic Bedrock Agent (the GA service, action groups
backed by Lambda) and a bare ALB as the Gateway target. Both turned out to
be wrong once checked against current AWS docs and the real Terraform
provider schema:

- A classic Bedrock Agent's action group only supports a Lambda ARN or a
  custom-control executor — there's no way to point it at an AgentCore
  Gateway. Gateway is consumed by an MCP client (AgentCore Runtime, Strands,
  LangGraph, or a hand-rolled client), not by that resource. Swapped in a
  Strands Agent on AgentCore Runtime instead.
- An AgentCore Gateway's `mcp_server` target endpoint must be HTTPS, and
  IAM/SigV4 outbound auth requires the target be fronted by something that
  natively verifies SigV4 (AgentCore Runtime, API Gateway, Lambda Function
  URLs all qualify; a bare ALB doesn't). Added API Gateway (HTTP API) +
  VPC Link in front of the ALB to get both for free, with no custom domain
  needed.

Every resource/attribute name in `terraform/` below was checked against the
real provider schema (`terraform providers schema -json` against the
installed `hashicorp/aws` v6.51.0 and `hashicorp/awscc` v1.89.0 providers)
and `terraform validate`/`terraform plan` both pass clean against my actual
AWS account (no resources created — plan only reads existing VPC/subnet
data).

**Design principles, maintained as this grows:**
- One MCP server per audited AWS service — never a monolith. Adding a new
  audit domain means standing up a new MCP server and registering it with
  the Gateway, not refactoring the existing ones.
- `report-mcp` is its own server, decoupled from audit logic, so output
  format/destination can change independently.
- Each MCP server's execution role is read-only and scoped only to the
  service it audits. `ec2-audit-mcp`'s task role grants exactly
  `ec2:DescribeInstances` and `ec2:DescribeSecurityGroups` — see
  `terraform/iam.tf`.
- No MCP server ever accepts AWS credentials as a tool parameter. Every
  server runs under its own IAM role (the Fargate task role) and uses
  boto3's default credential chain. A caller — including the LLM itself —
  cannot hand it different credentials than the ones it was deployed with.
  (`aws-audit-mcp`'s original `audit_ec2` tool took `access_key_id`/
  `secret_access_key` as plaintext parameters; that pattern was dropped
  here as the first thing fixed when porting the logic over, since it
  directly contradicts the "nothing reaches in, nothing leaves" pitch.)

## Repository layout

```
ec2-audit-mcp/    EC2 audit checks (ported from aws-audit-mcp), FastMCP server,
                  streamable-HTTP transport (network-reachable, not stdio --
                  required so AgentCore Gateway can call it)
report-mcp/       Findings -> Markdown report. HTML/PDF deferred (v1 ships
                  Markdown only, to keep the image lean -- see report-mcp/main.py)
agent/            Strands Agent + FastAPI, implementing the AgentCore Runtime
                  HTTP protocol contract (POST /invocations, GET /ping on
                  0.0.0.0:8080). MCP client to the Gateway signs with this
                  Runtime's own IAM role via mcp-proxy-for-aws -- no audited-
                  account credentials ever touch this service either.
terraform/        ECR, ECS cluster/services/tasks (Fargate), internal ALB,
                  API Gateway HTTP API + VPC Link, AgentCore Gateway +
                  targets, AgentCore Runtime (awscc provider), least-
                  privilege IAM throughout.
```

## Status

v1 Terraform scaffold complete and validated (`terraform validate` +
`terraform plan` clean against my real AWS account — 40 resources to add, 0
errors). `ec2-audit-mcp`, `report-mcp`, and `agent` all have passing local
test suites. **Nothing has been deployed yet** — `terraform apply` has not
been run.

Known gaps before a real deploy:
- `terraform/ecs.tf`'s ALB target group health check assumes FastMCP's
  streamable-HTTP route is `/mcp` — confirm against the installed `mcp` SDK
  version.
- `terraform/agentcore_runtime.tf`'s IAM policy for the Runtime role is
  reasoned from the Lambda container-image precedent (ECR pull, logs) plus
  the two AgentCore-specific actions confirmed during research
  (`bedrock-agentcore:InvokeGateway`, `bedrock:InvokeModel`). Whether
  AgentCore Runtime needs anything else (e.g. its own ECR repository
  resource policy, the way Lambda does) needs confirming at first deploy.
- `awscc_bedrockagentcore_runtime.agent_runtime_name`'s allowed character
  set is unconfirmed (currently `replace(var.project_name, "-", "_")` as a
  guess).

## v1 scope

- [x] Port EC2 audit checks into `ec2-audit-mcp`
- [x] `report-mcp` stub producing a real Markdown report from findings
- [x] Terraform for Fargate + API Gateway/VPC Link + AgentCore Gateway +
      AgentCore Runtime + least-privilege IAM, schema-validated end to end
- [x] Strands agent (`agent/`) implementing the Runtime HTTP contract
- [ ] First real deploy + end-to-end audit run against my own account

Out of scope for v1: `iam-audit-mcp`, `s3-audit-mcp`, multi-account support,
any UI beyond the generated report.

## Audit checks (EC2, v1)

- Untagged instances (missing `Name`, `Environment`, `Owner`)
- Public IP assignments
- Overly permissive security groups (`0.0.0.0/0` — SSH/RDP flagged critical,
  other ports flagged high)

## Local development

```bash
cd ec2-audit-mcp && uv venv .venv -p 3.11 && uv pip install -p .venv -r requirements.txt
.venv/bin/python -m pytest tests/ -v

cd ../report-mcp && uv venv .venv -p 3.11 && uv pip install -p .venv -r requirements.txt
.venv/bin/python -m pytest tests/ -v

cd ../agent && uv venv .venv -p 3.11 && uv pip install -p .venv -r requirements.txt
.venv/bin/python -m pytest tests/ -v
```

```bash
cd terraform
terraform init -backend=false
terraform validate
terraform plan -var="bedrock_model_id=<your model/inference-profile id>"
```

## Deploying

1. Enable Bedrock model access for your target Claude model in the console
   (Bedrock → Model access), then find the exact model/inference-profile ID:
   ```
   aws bedrock list-inference-profiles --region <region>
   ```
   Set it as `bedrock_model_id` in a gitignored `terraform.tfvars`.
2. First apply is two-step, same chicken-and-egg as any container-image
   resource: create the ECR repos first, build + push real images, *then*
   apply everything else.
   ```
   cd terraform
   terraform apply -target=aws_ecr_repository.ec2_audit_mcp -target=aws_ecr_repository.report_mcp -target=aws_ecr_repository.agent

   aws ecr get-login-password --region <region> | docker login --username AWS --password-stdin <account_id>.dkr.ecr.<region>.amazonaws.com
   docker build -t <ec2_audit_mcp_repo_url>:latest ../ec2-audit-mcp && docker push <ec2_audit_mcp_repo_url>:latest
   docker build -t <report_mcp_repo_url>:latest ../report-mcp && docker push <report_mcp_repo_url>:latest
   docker buildx build --platform linux/arm64 --provenance=false -t <agent_repo_url>:latest ../agent --push

   terraform apply
   ```
3. Invoke the agent once deployed (boto3 `bedrock-agentcore` client, or the
   AWS CLI's `bedrock-agentcore` commands) with a prompt like
   `"audit us-west-2"` and confirm a real Markdown report comes back.

## Future expansions

- `iam-audit-mcp`, `s3-audit-mcp`
- HTML/PDF report formats in `report-mcp` (WeasyPrint, same approach as
  `aws-audit-mcp`)
- Cross-account role assumption
- Remote Terraform state (S3 + native locking — see the pattern already in
  use in `daily-tech-brief-bedrock`)
