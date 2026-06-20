variable "aws_region" {
  description = "AWS region to deploy into. Must have Bedrock model access enabled for the chosen model."
  type        = string
  default     = "us-west-2"
}

variable "project_name" {
  description = "Name prefix used for ECR repos, ECS resources, and related infra."
  type        = string
  default     = "coresample"
}

variable "audited_region" {
  description = "AWS region that ec2-audit-mcp audits. Usually the same account/region this is deployed into for v1."
  type        = string
  default     = "us-west-2"
}

variable "bedrock_model_id" {
  description = <<-EOT
    Bedrock model ID (or cross-region inference profile ID) for Claude.
    Find the exact value with:
      aws bedrock list-foundation-models --region <region> \
        --query "modelSummaries[?contains(modelId,'sonnet')].modelId"
    or, for cross-region inference profiles:
      aws bedrock list-inference-profiles --region <region>
  EOT
  type        = string
}

variable "container_port" {
  description = "Port each MCP server listens on inside its container (streamable-HTTP transport)."
  type        = number
  default     = 8000
}

variable "fargate_cpu" {
  description = "Fargate task CPU units (256 = .25 vCPU)."
  type        = number
  default     = 256
}

variable "fargate_memory" {
  description = "Fargate task memory in MB."
  type        = number
  default     = 512
}
