resource "aws_ecr_repository" "ec2_audit_mcp" {
  name                 = "${var.project_name}/ec2-audit-mcp"
  image_tag_mutability = "MUTABLE"

  image_scanning_configuration {
    scan_on_push = true
  }
}

resource "aws_ecr_repository" "iam_audit_mcp" {
  name                 = "${var.project_name}/iam-audit-mcp"
  image_tag_mutability = "MUTABLE"

  image_scanning_configuration {
    scan_on_push = true
  }
}

resource "aws_ecr_repository" "report_mcp" {
  name                 = "${var.project_name}/report-mcp"
  image_tag_mutability = "MUTABLE"

  image_scanning_configuration {
    scan_on_push = true
  }
}
