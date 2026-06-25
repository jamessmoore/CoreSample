# CLAUDE.md

Guidance for Claude Code when working in this repository.

## Project

CoreSample is an AWS-native security/compliance audit framework: a Strands
agent (on Amazon Bedrock AgentCore Runtime) orchestrates calls through an
AgentCore Gateway to MCP servers running read-only audits against the
account's own resources (`ec2-audit-mcp`, `iam-audit-mcp`, and `s3-audit-mcp`
so far, more to follow), with a decoupled `report-mcp` turning findings
into a client-ready Markdown report. The pitch: audit logic, model
invocation, and AWS API calls all happen inside the account boundary — no
external service reaches in. For compliance-minded enterprises, that's the
whole point — and it's exactly what this repo sets out to prove. See
`README.md` for the full architecture, including what changed from the
original kickoff plan and why (classic Bedrock Agents can't target an
AgentCore Gateway; a bare ALB can't satisfy the Gateway target's HTTPS/
SigV4 requirements).

This is the evolution of [`aws-audit-mcp`](https://github.com/jamessmoore/aws-audit-mcp),
re-platformed onto Bedrock/AgentCore instead of an external API.

## Current status — read before assuming anything is stale

`ec2-audit-mcp`, `iam-audit-mcp`, `s3-audit-mcp`, `report-mcp`, and `agent`
are all **deployed and verified end-to-end** against the real AWS account:
a real audit request flows through every hop (Strands Agent on AgentCore
Runtime → AgentCore Gateway → API Gateway → internal ALB → ECS Fargate)
for all three audit services, and a real combined Markdown report comes
back. All five have passing local test suites.

`report-mcp`'s `generate_report` tool used to take a single `audit_json`
string, which forced the agent to hand-merge multiple tool calls' JSON into
one blob itself before calling it -- unreliable LLM behavior. Confirmed in
production: one run kept only EC2's raw data with a patched summary count,
the next produced an empty "CLEAN" report with no category data at all
despite real findings existing. Fixed by changing the tool to accept
`audit_jsons: list[str]` (each tool's raw, unmodified output) and merging
deterministically in `report.py`'s `merge_findings()`, which recomputes the
summary from the merged categories instead of trusting the inputs.
`agent/strands_agent.py`'s `SYSTEM_PROMPT` was rewritten to name all three
audit tools and forbid hand-merging. **Deployed and verified** -- a real
post-redeploy audit run produced a correctly-merged 4-finding report across
EC2 and S3, persisted to S3 intact.

Getting this live also surfaced a general gotcha worth remembering: after
redeploying an MCP server with a *changed tool signature* (new/renamed/
retyped parameters), the AgentCore Gateway target for that server still
serves the old cached schema -- it fetches a target's tool list once, at
target-creation time, and never re-fetches it just because the underlying
ECS service redeployed. Symptom: the agent reports the tool "requires a
field that isn't exposed in the tool's schema" even though the new code is
correctly deployed and the agent is calling it correctly. Fix: force the
Gateway target to re-register, the same `-replace` trick used for the
Runtime's `:latest`-tag image problem:
`terraform apply -replace=aws_bedrockagentcore_gateway_target.report_mcp`.
Any future change to an MCP tool's parameters needs this same step, not
just an ECS redeploy.

AWS Security Hub export is now **wired and deployed, not yet activated
against live Security Hub** -- one step further than the previous
"designed, not yet activated" state. `report-mcp` publishes an
`AuditReportGenerated` EventBridge event (merged findings + region, no
`account_id`) after merging findings; a new exporter Lambda
(`integrations/security_hub/exporter/`) subscribes via its own
EventBridge rule, derives `account_id` from its own execution context
(zero extra IAM permissions -- doesn't depend on report-mcp or the LLM
supplying one), maps findings to ASFF via a new category→resource table
in `asff_mapper.py`, and would call `BatchImportFindings` if enabled.
`ec2-audit-mcp`/`iam-audit-mcp`/`s3-audit-mcp` are untouched -- the
ASFF-specific mapping lives entirely in `asff_mapper.py`, since
`resource_type`/`resource_arn` are static per finding category and don't
need to flow through the live audit services. **Deployed and verified**
against the real account: a real audit run produced a real combined
report, `report-mcp` published the event, and the exporter Lambda fired
and no-op'd cleanly (`ENABLE_SECURITY_HUB_EXPORT` is `false` -- this
account has no paid Security Hub subscription; `aws securityhub
describe-hub` returns `SubscriptionRequiredException`).

That verification pass also caught a real bug: the exporter's
`logger.info()` calls produced zero CloudWatch output on the first
deployed invocation, even though the no-op path itself ran correctly.
`logging.basicConfig()` no-ops in AWS Lambda's Python runtime -- the
runtime pre-attaches its own handler to the root logger before the module
loads, and that root logger defaults to `WARNING`, silently dropping
every `INFO` record. Fixed with `logger.setLevel(logging.INFO)` on the
named logger instead of `basicConfig` on root, redeployed via
`terraform apply` (only the Lambda's `source_code_hash` changed -- no
other resource needed touching), and re-verified: the no-op log line now
appears as expected. Worth remembering for any future Lambda in this
repo -- this is a Lambda-runtime-specific quirk, not something a unit
test reproduces.

Terraform state lives in S3
(`terraform/versions.tf`'s `backend "s3"` block, native locking via
`use_lockfile`) — not local state, so
`terraform plan`/`apply` need real AWS credentials and read/write access to
the `coresample-tfstate-293528978619` bucket to do anything useful. To
confirm current resource state directly: `aws bedrockagentcore-control
list-gateways` / `list-agent-runtimes` / `aws ecs list-services` etc.

## Required workflow — no direct commits to main

`main` is protected by a GitHub ruleset ("Protect main"): no direct pushes,
no force-pushes, no branch deletion, and no bypass — applies even to repo
admins. A PR with a passing `test` status check (`.github/workflows/test.yml`)
is required before merge.

1. Create a new branch off `main` for the change (e.g. `git checkout -b fix/short-description`).
2. Commit changes to that branch.
3. Push the branch and open a pull request targeting `main` (`gh pr create`).
4. Wait for the `test` status check to pass on the PR.
5. Merge the PR into `main` only after CI passes (`gh pr merge --merge --delete-branch`).
6. The repo has `delete_branch_on_merge` enabled, so the **remote** branch is
   deleted automatically on merge — no separate cleanup step needed there.
   After merging, switch back to `main`, pull, then clean up the **local**
   copy: `git checkout main && git pull && git fetch --prune && git branch -d <branch>`.

Never commit directly to `main` and never push directly to `main`.

## Local verification before opening/updating a PR

This mirrors `.github/workflows/test.yml` — if these pass locally, the
`test` status check will pass.

```bash
# Each Python service (ec2-audit-mcp, iam-audit-mcp, s3-audit-mcp, report-mcp,
# agent, integrations/security_hub) the same way:
cd ec2-audit-mcp && uv venv .venv -p 3.11 && uv pip install -p .venv -r requirements.txt
.venv/bin/pytest

# Terraform
cd terraform && terraform fmt -check -recursive . && terraform init -backend=false && terraform validate
```

Keep this section and `.github/workflows/test.yml` in sync if either changes.

## Project structure

```
ec2-audit-mcp/    EC2 audit checks (untagged instances, public IPs, permissive
                  security groups), FastMCP server, streamable-HTTP transport.
                  No credentials accepted as input -- uses the Fargate task
                  role via boto3's default credential chain.
iam-audit-mcp/    IAM audit checks (console users without MFA, stale/unused
                  credentials, root account risk), same FastMCP/streamable-
                  HTTP shape and credential model as ec2-audit-mcp. Policy-
                  wildcard scan deferred to v1.1 (see README "Future
                  expansions").
s3-audit-mcp/     S3 audit checks (public buckets, public-access-block gaps,
                  missing encryption/versioning), same FastMCP/streamable-
                  HTTP shape and credential model as ec2-audit-mcp. Buckets
                  are regional (unlike IAM) -- filtered by actual bucket
                  region via get_bucket_location. Not yet deployed -- see
                  "Current status" above.
report-mcp/       Findings -> Markdown report, decoupled from audit logic.
                  Also persists each report to S3 (storage.py) and notes the
                  s3:// location alongside the inline report text. HTML/PDF
                  deferred (v1 ships Markdown only).
agent/            Strands Agent + FastAPI, implementing the AgentCore Runtime
                  HTTP protocol contract (POST /invocations, GET /ping on
                  0.0.0.0:8080, ARM64). MCP client to the Gateway signs with
                  this Runtime's own IAM role via mcp-proxy-for-aws.
integrations/
  security_hub/   AWS Security Hub ASFF export. asff_mapper.py maps raw
                  audit findings into ASFF, including the category->
                  resource_type/resource_arn table that closes the gap
                  the module's docstring used to describe. exporter/ is a
                  separately-deployed Lambda (not an MCP service, no
                  Gateway tool -- see terraform/security_hub_exporter.tf)
                  subscribed to report-mcp's AuditReportGenerated
                  EventBridge event. Deployed and wired end-to-end, gated
                  by ENABLE_SECURITY_HUB_EXPORT (false by default -- see
                  "Current status" above). See README "Future expansions".
terraform/        ECR, ECS cluster/services/tasks (Fargate), internal ALB,
                  API Gateway HTTP API + VPC Link, AgentCore Gateway +
                  targets, AgentCore Runtime (awscc provider), an S3 bucket
                  for generated reports (s3.tf), the Security Hub exporter
                  Lambda + EventBridge rule (security_hub_exporter.tf),
                  least-privilege IAM throughout. Remote state in S3 with
                  native locking (versions.tf) -- the bucket is
                  bootstrapped out of band, see README "Terraform state
                  backend".
.github/workflows/
  test.yml        CI gate: pytest (x6 services) + terraform fmt/validate,
                  on every PR to main and push to main.
```

## License & contributors

Apache License 2.0 (`LICENSE`) — adapted from `vigil`'s license (vigil's
copy on disk was truncated mid-clause; the complete, standard Apache 2.0
text was used instead). `CONTRIBUTING.md` and `CONTRIBUTORS.md` are adapted
from `daily-tech-brief-bedrock`'s, documenting that this is a solo project
with Claude (Anthropic) as an AI development collaborator with no commit
access or independent decision-making authority.

## Commit messages

Short, imperative, capitalized summary line. No conventional-commit prefixes
(`feat:`, `fix:`, etc.) — matches the convention used in `daily-tech-brief-bedrock`
and `aws-audit-mcp`.

## Notes

- This repo is a portfolio/interview proof-of-concept (see the user's global
  CLAUDE.md, section 9) — keep README and commit history client-presentable.
- When in doubt about an AgentCore/Bedrock Terraform resource's exact
  schema, don't guess from docs/blog posts alone — check the installed
  provider's real schema first: `terraform providers schema -json`. Several
  mistakes were caught this way during the initial scaffold (e.g.
  `credential_provider_configuration`'s `gateway_iam_role` block) that
  guessing from AWS docs/blog examples alone got wrong.
