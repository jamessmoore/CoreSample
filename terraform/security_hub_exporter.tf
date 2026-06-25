# AWS Security Hub ASFF export -- the deterministic, post-audit Lambda that
# subscribes to report-mcp's "AuditReportGenerated" EventBridge event and
# calls integrations/security_hub/asff_mapper.py's mapping logic +
# BatchImportFindings. The Bedrock Agent never sees this Lambda and has no
# tool definition that could invoke it -- whether a finding reaches
# Security Hub is a deterministic infrastructure step, not an LLM decision.
# See CLAUDE.md's "Current status" and the README's Security Hub entry for
# the full design rationale.
#
# ENABLE_SECURITY_HUB_EXPORT defaults to "false" here deliberately -- there
# is no paid Security Hub subscription on this account to export to yet
# (confirmed via `aws securityhub describe-hub`, which returns
# SubscriptionRequiredException). The rule stays enabled in Terraform with
# zero side effects until that changes -- see exporter/handler.py's no-op
# path.

# Explicit per-file `source` blocks rather than zipping the whole
# integrations/security_hub/ directory with excludes -- this guarantees the
# deployment package contains exactly these two files, with no risk of a
# glob miss pulling in .venv/__pycache__/tests.
data "archive_file" "security_hub_exporter" {
  type        = "zip"
  output_path = "${path.module}/.build/security_hub_exporter.zip"

  source {
    content  = file("${path.module}/../integrations/security_hub/asff_mapper.py")
    filename = "asff_mapper.py"
  }

  source {
    content  = file("${path.module}/../integrations/security_hub/exporter/handler.py")
    filename = "exporter/handler.py"
  }
}

resource "aws_cloudwatch_log_group" "security_hub_exporter" {
  name              = "/aws/lambda/${var.project_name}-security-hub-exporter"
  retention_in_days = 14
}

resource "aws_iam_role" "security_hub_exporter" {
  name = "${var.project_name}-security-hub-exporter"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { Service = "lambda.amazonaws.com" }
      Action    = "sts:AssumeRole"
    }]
  })
}

# CloudWatch Logs write access scoped to exactly this function's own log
# group -- deliberately not the AWSLambdaBasicExecutionRole managed policy,
# which grants logs:* on Resource "*". This is boilerplate Lambda execution
# plumbing (the same category as ecs_task_execution's role elsewhere in
# this file), not a second business permission.
resource "aws_iam_role_policy" "security_hub_exporter_logs" {
  name = "${var.project_name}-security-hub-exporter-logs"
  role = aws_iam_role.security_hub_exporter.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Sid    = "SecurityHubExporterLogs"
      Effect = "Allow"
      Action = [
        "logs:CreateLogStream",
        "logs:PutLogEvents",
      ]
      Resource = "${aws_cloudwatch_log_group.security_hub_exporter.arn}:*"
    }]
  })
}

# The single business permission this role has. BatchImportFindings doesn't
# support resource-level scoping -- there's no Security Hub finding ARN to
# scope to before the call creates one -- so Resource is "*" the same way
# ec2-audit-mcp's describe* actions are (see the comment on that policy).
resource "aws_iam_role_policy" "security_hub_exporter_export" {
  name = "${var.project_name}-security-hub-exporter-batchimport"
  role = aws_iam_role.security_hub_exporter.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Sid      = "SecurityHubBatchImport"
      Effect   = "Allow"
      Action   = "securityhub:BatchImportFindings"
      Resource = "*"
    }]
  })
}

resource "aws_lambda_function" "security_hub_exporter" {
  function_name    = "${var.project_name}-security-hub-exporter"
  role             = aws_iam_role.security_hub_exporter.arn
  handler          = "exporter.handler.lambda_handler"
  runtime          = "python3.11"
  architectures    = ["arm64"]
  memory_size      = 128
  timeout          = 30
  filename         = data.archive_file.security_hub_exporter.output_path
  source_code_hash = data.archive_file.security_hub_exporter.output_base64sha256

  environment {
    variables = {
      ENABLE_SECURITY_HUB_EXPORT = "false"
    }
  }

  depends_on = [
    aws_iam_role_policy.security_hub_exporter_logs,
    aws_iam_role_policy.security_hub_exporter_export,
  ]
}

resource "aws_cloudwatch_event_rule" "security_hub_exporter" {
  name        = "${var.project_name}-security-hub-export"
  description = "Routes report-mcp's AuditReportGenerated events to the Security Hub exporter Lambda."

  event_pattern = jsonencode({
    source      = ["coresample.report-mcp"]
    detail-type = ["AuditReportGenerated"]
  })
}

resource "aws_cloudwatch_event_target" "security_hub_exporter" {
  rule = aws_cloudwatch_event_rule.security_hub_exporter.name
  arn  = aws_lambda_function.security_hub_exporter.arn
}

resource "aws_lambda_permission" "security_hub_exporter_allow_eventbridge" {
  statement_id  = "AllowEventBridgeInvoke"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.security_hub_exporter.function_name
  principal     = "events.amazonaws.com"
  source_arn    = aws_cloudwatch_event_rule.security_hub_exporter.arn
}
