<p align="center">
  <img src="docs/architecture.gif" width="100%"
    alt="CoreSample architecture: an audit request flows through IAM/SigV4-gated hops — Strands Agent, AgentCore Gateway, API Gateway, internal ALB, ECS Fargate MCP servers — inside the AWS account boundary; findings return as a Markdown report.">
</p>

# CoreSample

An AWS-native security/compliance audit framework. The audit logic, the
foundation-model invocation, and the AWS API calls it makes all run *inside*
the account boundary — no external service reaches in to inspect your
infrastructure. For compliance-minded enterprises, that is a key objective — and
it's exactly what this repo sets out to prove.

This is the evolution of [`aws-audit-mcp`](https://github.com/jamessmoore/aws-audit-mcp),
re-platformed onto Amazon Bedrock as the foundation-model layer instead of an
external API.

## Audit checks by service

A running index, one row per `*-audit-mcp` server — grows every time a new
one is added. Each links to a per-check breakdown (what it checks, why it
matters, severity, an example finding, and remediation).

| Service | Checks | Docs |
|---|---|---|
| EC2 | 3 checks | [ec2.md](docs/checks/ec2.md) |
| IAM | 4 checks | [iam.md](docs/checks/iam.md) |
| S3 | 4 checks | [s3.md](docs/checks/s3.md) |

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
  - iam-audit-mcp   (console users without MFA, stale/unused credentials, root risk)
  - s3-audit-mcp    (public buckets, public-access-block gaps, encryption, versioning)
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
installed `hashicorp/aws` v6.51.0 and `hashicorp/awscc` v1.89.0 providers),
and `terraform validate`/`terraform plan`/`terraform apply` have all run
clean against my actual AWS account — see "Status" below.

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
iam-audit-mcp/    IAM audit checks (console users without MFA, stale/unused
                  credentials, root account risk), same FastMCP/streamable-
                  HTTP shape as ec2-audit-mcp
s3-audit-mcp/     S3 audit checks (public buckets, public-access-block gaps,
                  missing encryption/versioning), same FastMCP/streamable-
                  HTTP shape as ec2-audit-mcp. Buckets are regional like EC2
                  instances (unlike IAM) -- filtered by actual bucket
                  region, resolved via get_bucket_location.
report-mcp/       Findings -> Markdown report, persisted to S3 (storage.py)
                  in addition to being returned inline. HTML/PDF deferred
                  (v1 ships Markdown only, to keep the image lean -- see
                  report-mcp/main.py)
agent/            Strands Agent + FastAPI, implementing the AgentCore Runtime
                  HTTP protocol contract (POST /invocations, GET /ping on
                  0.0.0.0:8080). MCP client to the Gateway signs with this
                  Runtime's own IAM role via mcp-proxy-for-aws -- no audited-
                  account credentials ever touch this service either.
terraform/        ECR, ECS cluster/services/tasks (Fargate), internal ALB,
                  API Gateway HTTP API + VPC Link, AgentCore Gateway +
                  targets, AgentCore Runtime (awscc provider), an S3 bucket
                  for generated reports, least-privilege IAM throughout.
                  Remote state in S3 with native locking -- see "Terraform
                  state backend" below.
```

## Status

`ec2-audit-mcp`, `iam-audit-mcp`, and `s3-audit-mcp` are all **deployed and
verified end-to-end** against my real AWS account: a real audit request
flows through every hop (Strands Agent on AgentCore Runtime → AgentCore
Gateway → API Gateway → internal ALB → ECS Fargate) for all three, and a
real combined Markdown report comes back. `ec2-audit-mcp`, `iam-audit-mcp`,
`s3-audit-mcp`, `report-mcp`, and `agent` all have passing local test
suites. Terraform state lives in S3 with native locking — see "Terraform
state backend" below.

Known gaps:
- `awscc_bedrockagentcore_runtime.agent_runtime_name`'s allowed character
  set is unconfirmed (currently `replace(var.project_name, "-", "_")` as a
  guess) — hasn't caused a problem in practice yet, but isn't confirmed
  against AWS's actual validation rules either.
- A second real end-to-end run (after redeploying `report-mcp` with the
  `_all_findings()` fix) surfaced a deeper issue: `generate_report` took a
  single `audit_json` string, so producing one combined report required
  the *agent* to hand-merge multiple tool-call results into one JSON blob
  itself before calling it -- unreliable LLM behavior, not deterministic
  code. One run kept only EC2's raw data with a patched summary count; the
  next produced an empty/"CLEAN" report with no category data at all, even
  though all three tools had real findings.
  Fixed by changing `generate_report` to accept `audit_jsons: list[str]`
  (one entry per tool's raw, unmodified output) and merging them
  deterministically in `report.py`'s new `merge_findings()` -- the summary
  is recomputed from the merged categories rather than trusted from the
  inputs, so it can't drift out of sync with what's actually rendered.
  `agent/strands_agent.py`'s `SYSTEM_PROMPT` was also rewritten to name all
  three audit tools explicitly and tell the agent not to hand-merge JSON
  itself.
  **Deployed and verified** -- a real post-redeploy audit run produced a
  correctly-merged 4-finding report across EC2 and S3, persisted to S3
  intact.
- Rolling out that fix surfaced a general gotcha: the AgentCore Gateway
  caches a target's tool schema at *target-creation* time and never
  re-fetches it on a plain ECS redeploy. After `report-mcp`'s tool
  signature changed, the Gateway kept serving the old schema, so the agent
  got a validation error claiming the tool "requires a field that isn't
  exposed in its schema" -- the new code was deployed correctly, but the
  Gateway hadn't re-registered it. Fixed with the same `-replace` approach
  used for the Runtime's `:latest`-tag problem:
  `terraform apply -replace=aws_bedrockagentcore_gateway_target.report_mcp`.
  Any future change to an MCP tool's parameters needs this step, not just
  an ECS redeploy -- see "Deploying" below.

## v1 scope

- [x] Port EC2 audit checks into `ec2-audit-mcp`
- [x] `report-mcp` stub producing a real Markdown report from findings
- [x] Terraform for Fargate + API Gateway/VPC Link + AgentCore Gateway +
      AgentCore Runtime + least-privilege IAM, schema-validated end to end
- [x] Strands agent (`agent/`) implementing the Runtime HTTP contract
- [x] First real deploy + end-to-end audit run against my own account
- [x] Port IAM audit checks into `iam-audit-mcp`
- [x] Port S3 audit checks into `s3-audit-mcp`

Out of scope for v1: multi-account support, any UI beyond the generated
report.

## Audit checks

See the table above — per-check detail (what it checks, why it matters,
severity, an example finding, remediation) lives in `docs/checks/`, not
here, to avoid the same checks being described twice and drifting out of
sync.

## Local development

```bash
cd ec2-audit-mcp && uv venv .venv -p 3.11 && uv pip install -p .venv -r requirements.txt
.venv/bin/python -m pytest tests/ -v

cd ../iam-audit-mcp && uv venv .venv -p 3.11 && uv pip install -p .venv -r requirements.txt
.venv/bin/python -m pytest tests/ -v

cd ../s3-audit-mcp && uv venv .venv -p 3.11 && uv pip install -p .venv -r requirements.txt
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

## Terraform state backend

Terraform state lives in S3, not locally — `terraform/versions.tf`'s
`backend "s3"` block. Locking is native S3 conditional writes
(`use_lockfile = true`), which needs **Terraform 1.10+** — no DynamoDB lock
table required. Same pattern as
[`daily-tech-brief-bedrock`](https://github.com/jamessmoore/daily-tech-brief-bedrock/blob/main/terraform/main.tf).

The bucket can't be created by the same config that uses it as a backend
(chicken-and-egg), so it's bootstrapped out of band, once:

```bash
aws s3api create-bucket --bucket coresample-tfstate-<account_id> \
  --region <region> --create-bucket-configuration LocationConstraint=<region>
aws s3api put-bucket-versioning --bucket coresample-tfstate-<account_id> \
  --versioning-configuration Status=Enabled
aws s3api put-bucket-encryption --bucket coresample-tfstate-<account_id> \
  --server-side-encryption-configuration '{"Rules":[{"ApplyServerSideEncryptionByDefault":{"SSEAlgorithm":"AES256"}}]}'
aws s3api put-public-access-block --bucket coresample-tfstate-<account_id> \
  --public-access-block-configuration BlockPublicAcls=true,IgnorePublicAcls=true,BlockPublicPolicy=true,RestrictPublicBuckets=true
```

Then point `terraform/versions.tf`'s `backend "s3"` block at that bucket
(bucket name, key, region — see the existing block for the deployed
instance's values, currently `coresample-tfstate-293528978619` in
`us-west-2`). The IAM identity running `terraform init`/`plan`/`apply` needs
`s3:CreateBucket`/`PutBucketVersioning`/`PutEncryptionConfiguration`/
`PutBucketPublicAccessBlock` on the bucket for the one-time bootstrap, plus
ongoing `s3:GetObject`/`PutObject`/`DeleteObject`/`ListBucket` on the bucket
and its contents for every state read/write. Two of the bootstrap action
names are easy to get wrong: the IAM action for the `PutBucketEncryption`
API is `s3:PutEncryptionConfiguration`, and the IAM action for
`PutPublicAccessBlock` is `s3:PutBucketPublicAccessBlock` — neither matches
its API operation name exactly.

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
   terraform apply -target=aws_ecr_repository.ec2_audit_mcp -target=aws_ecr_repository.iam_audit_mcp -target=aws_ecr_repository.s3_audit_mcp -target=aws_ecr_repository.report_mcp -target=aws_ecr_repository.agent

   aws ecr get-login-password --region <region> | docker login --username AWS --password-stdin <account_id>.dkr.ecr.<region>.amazonaws.com
   docker build -t <ec2_audit_mcp_repo_url>:latest ../ec2-audit-mcp && docker push <ec2_audit_mcp_repo_url>:latest
   docker build -t <iam_audit_mcp_repo_url>:latest ../iam-audit-mcp && docker push <iam_audit_mcp_repo_url>:latest
   docker build -t <s3_audit_mcp_repo_url>:latest ../s3-audit-mcp && docker push <s3_audit_mcp_repo_url>:latest
   docker build -t <report_mcp_repo_url>:latest ../report-mcp && docker push <report_mcp_repo_url>:latest
   docker buildx build --platform linux/arm64 --provenance=false -t <agent_repo_url>:latest ../agent --push

   terraform apply
   ```
   The AgentCore Gateway target for a brand-new MCP server can fail on this
   first `apply` with `Failed to connect and fetch tools from the provided
   MCP target server` -- it tries to connect before the new ECS service has
   passed its ALB health check. Confirm the service reached steady state
   (`aws ecs describe-services`) and the target is `healthy`
   (`aws elbv2 describe-target-health`), then re-run `terraform apply` --
   everything else is already created, so it only retries the gateway
   target.
3. Invoke the agent once deployed (boto3 `bedrock-agentcore` client, or the
   AWS CLI's `bedrock-agentcore` commands) with a prompt like
   `"audit us-west-2"` and confirm a real Markdown report comes back.
4. If you ever change parameters on an existing MCP tool (rename, retype,
   add/remove an argument) on an already-deployed server: a plain ECS
   redeploy of the container is *not* enough. The AgentCore Gateway target
   fetches and caches a target's tool schema once, at target-creation
   time, and won't notice the underlying server's tool definitions changed.
   Force it to re-register:
   ```
   terraform apply -replace=aws_bedrockagentcore_gateway_target.<name>
   ```
   Symptom if you skip this: the agent reports a validation error claiming
   the tool needs a field that "isn't exposed in its schema," even though
   the new code is deployed correctly. Same root cause as the Runtime's
   `:latest`-tag problem -- a resource referencing something Terraform
   doesn't see as changed -- same `-replace` fix.

## Future expansions

- **`iam-audit-mcp` policy-wildcard scan (v1.1)** — flag directly-attached
  user policies containing `Action: "*"` / `Resource: "*"` (critical
  severity). Deferred out of the initial `iam-audit-mcp` round; the other
  four IAM checks shipped without it.
- HTML/PDF report formats in `report-mcp` (WeasyPrint, same approach as
  `aws-audit-mcp`)
- Cross-account role assumption

## Contributing

- Please see [CONTRIBUTING](CONTRIBUTING.md) for details, and
  [CONTRIBUTORS](CONTRIBUTORS.md) for how AI tooling is used in this repo.
- `main` is protected — all changes go through a PR with a passing `test`
  CI check (`.github/workflows/test.yml`). See `CLAUDE.md` for the full
  workflow.

## License

Apache License 2.0 — see [LICENSE](LICENSE).
