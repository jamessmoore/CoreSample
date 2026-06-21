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

# --- report-mcp task role ----------------------------------------------------
# report-mcp transforms JSON into Markdown and writes the result to the
# reports bucket (terraform/s3.tf) -- the only AWS API call it makes.

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
