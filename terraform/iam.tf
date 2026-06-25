# --- ECS task execution role (shared) --------------------------------------
# Pulls container images from ECR and writes to CloudWatch Logs. This is
# AWS-infrastructure plumbing, not application-level access -- it has no
# visibility into the audited account's resources.

resource "aws_iam_role" "ecs_task_execution" {
  name = "${var.project_name}-ecs-task-execution"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { Service = "ecs-tasks.amazonaws.com" }
      Action    = "sts:AssumeRole"
    }]
  })
}

resource "aws_iam_role_policy_attachment" "ecs_task_execution" {
  role       = aws_iam_role.ecs_task_execution.name
  policy_arn = "arn:aws:iam::aws:policy/service-role/AmazonECSTaskExecutionRolePolicy"
}

# --- ec2-audit-mcp task role -------------------------------------------------
# This is the compliance talking point: read-only, scoped to exactly the
# two EC2 describe actions the auditor calls. No write/modify permissions
# anywhere, no access to any other AWS service. Credentials never leave
# this role -- ec2-audit-mcp never accepts them as input (see
# ec2-audit-mcp/audit.py).

resource "aws_iam_role" "ec2_audit_mcp_task" {
  name = "${var.project_name}-ec2-audit-mcp-task"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { Service = "ecs-tasks.amazonaws.com" }
      Action    = "sts:AssumeRole"
    }]
  })
}

resource "aws_iam_role_policy" "ec2_audit_mcp_readonly" {
  name = "${var.project_name}-ec2-readonly"
  role = aws_iam_role.ec2_audit_mcp_task.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Sid    = "Ec2AuditReadOnly"
      Effect = "Allow"
      Action = [
        "ec2:DescribeInstances",
        "ec2:DescribeSecurityGroups",
      ]
      Resource = "*" # describe* actions on EC2 don't support resource-level scoping
    }]
  })
}

# --- iam-audit-mcp task role -------------------------------------------------
# Same compliance talking point as ec2_audit_mcp_task: read-only, scoped to
# exactly the five IAM list/get actions the auditor calls (no
# GetLoginProfile or policy-document reads -- console access is inferred
# from list_users' PasswordLastUsed field instead, see
# iam-audit-mcp/audit.py). No write/modify permissions anywhere. Credentials
# never leave this role -- iam-audit-mcp never accepts them as input.

resource "aws_iam_role" "iam_audit_mcp_task" {
  name = "${var.project_name}-iam-audit-mcp-task"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { Service = "ecs-tasks.amazonaws.com" }
      Action    = "sts:AssumeRole"
    }]
  })
}

resource "aws_iam_role_policy" "iam_audit_mcp_readonly" {
  name = "${var.project_name}-iam-readonly"
  role = aws_iam_role.iam_audit_mcp_task.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Sid    = "IamAuditReadOnly"
      Effect = "Allow"
      Action = [
        "iam:ListUsers",
        "iam:ListAccessKeys",
        "iam:ListMFADevices",
        "iam:GetAccountSummary",
        "iam:GetAccessKeyLastUsed",
      ]
      Resource = "*" # list/get actions on IAM don't support resource-level scoping
    }]
  })
}

# --- s3-audit-mcp task role ---------------------------------------------------
# Same compliance talking point as ec2_audit_mcp_task/iam_audit_mcp_task:
# read-only, scoped to exactly the actions the auditor calls. No write/
# modify permissions anywhere. Credentials never leave this role --
# s3-audit-mcp never accepts them as input (see s3-audit-mcp/audit.py).
#
# Two statements because of how S3 scopes resources: ListAllMyBuckets is an
# account-level action with no bucket to scope to (must be "*"), while the
# rest are bucket-level Get* actions that DO support resource-level
# scoping -- scoped to every bucket ("arn:aws:s3:::*") since the auditor
# doesn't know bucket names ahead of time and must inspect all of them.

resource "aws_iam_role" "s3_audit_mcp_task" {
  name = "${var.project_name}-s3-audit-mcp-task"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { Service = "ecs-tasks.amazonaws.com" }
      Action    = "sts:AssumeRole"
    }]
  })
}

resource "aws_iam_role_policy" "s3_audit_mcp_readonly" {
  name = "${var.project_name}-s3-readonly"
  role = aws_iam_role.s3_audit_mcp_task.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid      = "S3AuditListBuckets"
        Effect   = "Allow"
        Action   = "s3:ListAllMyBuckets"
        Resource = "*" # account-level action -- no bucket ARN to scope to
      },
      {
        Sid    = "S3AuditReadOnly"
        Effect = "Allow"
        Action = [
          "s3:GetBucketLocation",
          "s3:GetBucketAcl",
          "s3:GetBucketPolicyStatus",
          "s3:GetBucketPublicAccessBlock",
          "s3:GetEncryptionConfiguration",
          "s3:GetBucketVersioning",
        ]
        Resource = "arn:aws:s3:::*" # every bucket -- names aren't known ahead of time
      },
    ]
  })
}

# --- report-mcp task role ----------------------------------------------------
# report-mcp transforms JSON into Markdown and writes the result to the
# reports bucket (terraform/s3.tf), and publishes an "AuditReportGenerated"
# event to the default EventBridge bus after merging findings (eventbridge.py)
# -- the two AWS API calls it makes. The EventBridge event is consumed by
# the Security Hub exporter Lambda (terraform/security_hub_exporter.tf);
# report-mcp has no IAM visibility into that Lambda or Security Hub itself.

resource "aws_iam_role" "report_mcp_task" {
  name = "${var.project_name}-report-mcp-task"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { Service = "ecs-tasks.amazonaws.com" }
      Action    = "sts:AssumeRole"
    }]
  })
}

resource "aws_iam_role_policy" "report_mcp_s3_write" {
  name = "${var.project_name}-report-mcp-s3-write"
  role = aws_iam_role.report_mcp_task.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Sid      = "WriteReports"
      Effect   = "Allow"
      Action   = "s3:PutObject"
      Resource = "${aws_s3_bucket.reports.arn}/*"
    }]
  })
}

resource "aws_iam_role_policy" "report_mcp_eventbridge_publish" {
  name = "${var.project_name}-report-mcp-eventbridge-publish"
  role = aws_iam_role.report_mcp_task.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Sid      = "PublishAuditEvents"
      Effect   = "Allow"
      Action   = "events:PutEvents"
      Resource = "arn:aws:events:${var.aws_region}:${data.aws_caller_identity.current.account_id}:event-bus/default"
    }]
  })
}
