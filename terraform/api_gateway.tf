# HTTPS + SigV4-verifying front door for the MCP servers, sitting between
# the internal ALB (networking.tf) and the AgentCore Gateway targets
# (agentcore_gateway.tf). Confirmed via AWS docs during research: HTTP API
# VPC Link v2 private integrations support a direct ALB listener target
# (no NLB hop required), and API Gateway natively verifies SigV4, which is
# what makes IAM/SigV4 outbound auth from the Gateway possible at all (a
# bare ALB doesn't verify SigV4, so it can't be the Gateway target directly).

resource "aws_security_group" "vpc_link" {
  name        = "${var.project_name}-vpc-link"
  description = "ENIs for the API Gateway VPC Link, egress to the internal ALB only"
  vpc_id      = data.aws_vpc.default.id
}

resource "aws_vpc_security_group_egress_rule" "vpc_link_to_alb_ec2_audit" {
  security_group_id            = aws_security_group.vpc_link.id
  referenced_security_group_id = aws_security_group.alb.id
  from_port                    = 8001
  to_port                      = 8001
  ip_protocol                  = "tcp"
}

resource "aws_vpc_security_group_egress_rule" "vpc_link_to_alb_report" {
  security_group_id            = aws_security_group.vpc_link.id
  referenced_security_group_id = aws_security_group.alb.id
  from_port                    = 8002
  to_port                      = 8002
  ip_protocol                  = "tcp"
}

resource "aws_apigatewayv2_vpc_link" "mcp" {
  name               = "${var.project_name}-mcp"
  security_group_ids = [aws_security_group.vpc_link.id]
  subnet_ids         = data.aws_subnets.default.ids
}

resource "aws_apigatewayv2_api" "mcp" {
  name          = "${var.project_name}-mcp"
  protocol_type = "HTTP"
}

# Two dedicated integrations (not one shared integration relying on the
# ALB's own path-based rules) -- each strips its route's static prefix
# before forwarding, so the backend always sees plain "/mcp" regardless of
# which route it came in on. That means the ALB can no longer distinguish
# the two backends by path, so each integration instead points at its own
# dedicated ALB listener (networking.tf's ec2_audit_mcp/report_mcp
# listeners on ports 8001/8002).
resource "aws_apigatewayv2_integration" "ec2_audit_mcp" {
  api_id             = aws_apigatewayv2_api.mcp.id
  integration_type   = "HTTP_PROXY"
  integration_method = "ANY"
  connection_type    = "VPC_LINK"
  connection_id      = aws_apigatewayv2_vpc_link.mcp.id
  integration_uri    = aws_lb_listener.ec2_audit_mcp.arn

  request_parameters = {
    "overwrite:path" = "/$request.path.proxy"
  }
}

resource "aws_apigatewayv2_integration" "report_mcp" {
  api_id             = aws_apigatewayv2_api.mcp.id
  integration_type   = "HTTP_PROXY"
  integration_method = "ANY"
  connection_type    = "VPC_LINK"
  connection_id      = aws_apigatewayv2_vpc_link.mcp.id
  integration_uri    = aws_lb_listener.report_mcp.arn

  request_parameters = {
    "overwrite:path" = "/$request.path.proxy"
  }
}

resource "aws_apigatewayv2_route" "ec2_audit_mcp" {
  api_id    = aws_apigatewayv2_api.mcp.id
  route_key = "ANY /ec2-audit/{proxy+}"
  target    = "integrations/${aws_apigatewayv2_integration.ec2_audit_mcp.id}"

  # AWS_IAM here is what makes this endpoint SigV4-verifiable -- required
  # for the AgentCore Gateway target's IAM/SigV4 outbound auth to work.
  authorization_type = "AWS_IAM"
}

resource "aws_apigatewayv2_route" "report_mcp" {
  api_id             = aws_apigatewayv2_api.mcp.id
  route_key          = "ANY /report/{proxy+}"
  target             = "integrations/${aws_apigatewayv2_integration.report_mcp.id}"
  authorization_type = "AWS_IAM"
}

resource "aws_apigatewayv2_stage" "default" {
  api_id      = aws_apigatewayv2_api.mcp.id
  name        = "$default"
  auto_deploy = true
}
