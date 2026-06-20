output "alb_dns_name" {
  description = "ALB DNS name fronting the MCP servers"
  value       = aws_lb.mcp.dns_name
}

output "ec2_audit_mcp_ecr_repository_url" {
  value = aws_ecr_repository.ec2_audit_mcp.repository_url
}

output "report_mcp_ecr_repository_url" {
  value = aws_ecr_repository.report_mcp.repository_url
}

output "agentcore_gateway_url" {
  value = aws_bedrockagentcore_gateway.this.gateway_url
}

output "agent_ecr_repository_url" {
  value = aws_ecr_repository.agent.repository_url
}
