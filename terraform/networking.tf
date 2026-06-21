# v1 simplicity: default VPC + its public subnets (Fargate tasks still need
# a public IP to pull images / reach AWS APIs since there's no NAT or VPC
# endpoints here). The ALB itself is internal -- it's no longer reachable
# from the internet directly; the only path in is via API Gateway's VPC
# Link (api_gateway.tf), which is what the AgentCore Gateway target
# actually calls. See README for why API Gateway sits in front of the ALB
# at all: the Gateway target endpoint must be HTTPS, and IAM/SigV4 outbound
# auth requires a front door that natively verifies SigV4 -- a bare ALB
# satisfies neither.

data "aws_vpc" "default" {
  default = true
}

data "aws_subnets" "default" {
  filter {
    name   = "vpc-id"
    values = [data.aws_vpc.default.id]
  }
}

resource "aws_security_group" "alb" {
  name        = "${var.project_name}-alb"
  description = "Ingress to the internal ALB fronting the MCP servers, from the API Gateway VPC Link only"
  vpc_id      = data.aws_vpc.default.id

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
}

# Standalone rule resources (rather than an inline `ingress` block here and
# an inline `egress` block on the VPC Link's SG in api_gateway.tf) to avoid
# the two security groups creating a dependency cycle on each other.
#
# Two dedicated ports (not one shared port + ALB path-based rules): API
# Gateway's HTTP_PROXY integration strips each route's path prefix before
# forwarding (api_gateway.tf's "overwrite:path" mapping) so the backend
# always sees plain "/mcp" -- which means the ALB can no longer tell the
# two backends apart by path. A dedicated listener per backend sidesteps
# that entirely.
resource "aws_vpc_security_group_ingress_rule" "alb_from_vpc_link_ec2_audit" {
  security_group_id            = aws_security_group.alb.id
  referenced_security_group_id = aws_security_group.vpc_link.id
  from_port                    = 8001
  to_port                      = 8001
  ip_protocol                  = "tcp"
}

resource "aws_vpc_security_group_ingress_rule" "alb_from_vpc_link_report" {
  security_group_id            = aws_security_group.alb.id
  referenced_security_group_id = aws_security_group.vpc_link.id
  from_port                    = 8002
  to_port                      = 8002
  ip_protocol                  = "tcp"
}

resource "aws_security_group" "mcp_tasks" {
  name        = "${var.project_name}-mcp-tasks"
  description = "Ingress from the ALB only, to the MCP server Fargate tasks"
  vpc_id      = data.aws_vpc.default.id

  ingress {
    from_port       = var.container_port
    to_port         = var.container_port
    protocol        = "tcp"
    security_groups = [aws_security_group.alb.id]
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
}

resource "aws_lb" "mcp" {
  name               = "${var.project_name}-mcp"
  internal           = true
  load_balancer_type = "application"
  security_groups    = [aws_security_group.alb.id]
  subnets            = data.aws_subnets.default.ids
}

resource "aws_lb_listener" "ec2_audit_mcp" {
  load_balancer_arn = aws_lb.mcp.arn
  port              = 8001
  protocol          = "HTTP"

  default_action {
    type             = "forward"
    target_group_arn = aws_lb_target_group.ec2_audit_mcp.arn
  }
}

resource "aws_lb_listener" "report_mcp" {
  load_balancer_arn = aws_lb.mcp.arn
  port              = 8002
  protocol          = "HTTP"

  default_action {
    type             = "forward"
    target_group_arn = aws_lb_target_group.report_mcp.arn
  }
}
