# CLAUDE.md

Guidance for Claude Code when working in this repository.

## Project

CoreSample is an AWS-native security/compliance audit framework: a Strands
agent (on Amazon Bedrock AgentCore Runtime) orchestrates calls through an
AgentCore Gateway to MCP servers running read-only audits against the
account's own resources (`ec2-audit-mcp` first, more to follow), with a
decoupled `report-mcp` turning findings into a client-ready Markdown
report. The pitch: audit logic, model invocation, and AWS API calls all
happen inside the account boundary — no external service reaches in. See
`README.md` for the full architecture, including what changed from the
original kickoff plan and why (classic Bedrock Agents can't target an
AgentCore Gateway; a bare ALB can't satisfy the Gateway target's HTTPS/
SigV4 requirements).

This is the evolution of [`aws-audit-mcp`](https://github.com/jamessmoore/aws-audit-mcp),
re-platformed onto Bedrock/AgentCore instead of an external API.

## Current status — read before assuming anything is stale

Terraform scaffold is complete and schema-validated (`terraform validate` +
`terraform plan` clean against the real AWS account, 0 errors) but **nothing
has been deployed** — `terraform apply` has not been run. `ec2-audit-mcp`,
`report-mcp`, and `agent` each have passing local test suites. Don't assume
any AWS infrastructure described in `terraform/` actually exists yet; check
`aws bedrockagentcore-control list-gateways` / `list-agent-runtimes` /
`aws ecs list-services` etc. if in doubt.

## Required workflow — no direct commits to main

`main` is protected by a GitHub ruleset ("Protect main"): no direct pushes,
no force-pushes, no branch deletion, and no bypass — applies even to repo
admins. A PR with a passing `test` status check (`.github/workflows/test.yml`)
is required before merge.

1. Create a new branch off `main` for the change (e.g. `git checkout -b fix/short-description`).
2. Commit changes to that branch.
3. Push the branch and open a pull request targeting `main` (`gh pr create`).
4. Wait for the `test` status check to pass on the PR.
5. Merge the PR into `main` only after CI passes.
6. After a successful merge, delete the local feature branch (`git branch -d <branch>`) and run `git fetch --prune`.

Never commit directly to `main` and never push directly to `main`.

## Local verification before opening/updating a PR

This mirrors `.github/workflows/test.yml` — if these pass locally, the
`test` status check will pass.

```bash
# Each Python service (ec2-audit-mcp, report-mcp, agent) the same way:
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
report-mcp/       Findings -> Markdown report, decoupled from audit logic.
                  HTML/PDF deferred (v1 ships Markdown only).
agent/            Strands Agent + FastAPI, implementing the AgentCore Runtime
                  HTTP protocol contract (POST /invocations, GET /ping on
                  0.0.0.0:8080, ARM64). MCP client to the Gateway signs with
                  this Runtime's own IAM role via mcp-proxy-for-aws.
terraform/        ECR, ECS cluster/services/tasks (Fargate), internal ALB,
                  API Gateway HTTP API + VPC Link, AgentCore Gateway +
                  targets, AgentCore Runtime (awscc provider), least-
                  privilege IAM throughout. No remote state backend yet
                  (solo project, no team state-sharing need at v1).
.github/workflows/
  test.yml        CI gate: pytest (x3 services) + terraform fmt/validate,
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
