# AgentCore Runtime: hosts the Strands agent (agent/) that orchestrates
# calls to the AgentCore Gateway. No native `aws` provider resource exists
# for this yet (checked during research) -- awscc_bedrockagentcore_runtime
# (Cloud Control) is the only Terraform path. Schema confirmed directly
# against the installed hashicorp/awscc v1.89.0 provider via `terraform
# providers schema -json`.

resource "aws_ecr_repository" "agent" {
  name                 = "${var.project_name}/agent"
  image_tag_mutability = "MUTABLE"

  image_scanning_configuration {
    scan_on_push = true
  }
}

resource "aws_iam_role" "agentcore_runtime" {
  name = "${var.project_name}-agentcore-runtime"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { Service = "bedrock-agentcore.amazonaws.com" }
      Action    = "sts:AssumeRole"
      Condition = {
        StringEquals = { "aws:SourceAccount" = data.aws_caller_identity.current.account_id }
        ArnLike      = { "aws:SourceArn" = "arn:aws:bedrock-agentcore:${var.aws_region}:${data.aws_caller_identity.current.account_id}:*" }
      }
    }]
  })
}

# Permissions the Runtime's own role needs are reasoned from the Lambda
# container-image precedent (ECR pull, logs) plus the two AgentCore-specific
# actions confirmed during research (InvokeGateway, InvokeModel). Whether
# AgentCore Runtime needs anything beyond this -- e.g. its own ECR
# repository resource policy, the way Lambda needs one (see
# daily-tech-brief-bedrock/terraform/main.tf's aws_ecr_repository_policy)
# -- should be confirmed at first real deploy; this is a deploy-time
# correctness question, not a Terraform schema one.
resource "aws_iam_role_policy" "agentcore_runtime" {
  name = "${var.project_name}-agentcore-runtime"
  role = aws_iam_role.agentcore_runtime.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid      = "InvokeGateway"
        Effect   = "Allow"
        Action   = "bedrock-agentcore:InvokeGateway"
        Resource = aws_bedrockagentcore_gateway.this.gateway_arn
      },
      {
        Sid    = "InvokeFoundationModel"
        Effect = "Allow"
        Action = [
          "bedrock:InvokeModel",
          "bedrock:InvokeModelWithResponseStream",
        ]
        # Same cross-region-inference-profile ARN shape used elsewhere in
        # this repo (see versions.tf / the removed bedrock_agent.tf).
        Resource = [
          "arn:aws:bedrock:${var.aws_region}:${data.aws_caller_identity.current.account_id}:inference-profile/${var.bedrock_model_id}",
          "arn:aws:bedrock:*::foundation-model/${replace(var.bedrock_model_id, "/^(us|global|eu|apac)\\./", "")}",
        ]
      },
      {
        Sid    = "EcrPull"
        Effect = "Allow"
        Action = [
          "ecr:GetDownloadUrlForLayer",
          "ecr:BatchGetImage",
          "ecr:GetAuthorizationToken",
        ]
        Resource = "*"
      },
      {
        Sid      = "Logs"
        Effect   = "Allow"
        Action   = ["logs:CreateLogGroup", "logs:CreateLogStream", "logs:PutLogEvents"]
        Resource = "*"
      },
    ]
  })
}

resource "awscc_bedrockagentcore_runtime" "agent" {
  agent_runtime_name     = replace(var.project_name, "-", "_") # naming pattern unconfirmed -- verify allowed charset at apply time
  role_arn               = aws_iam_role.agentcore_runtime.arn
  description            = "Strands agent orchestrating CoreSample audits via the AgentCore Gateway"
  protocol_configuration = "HTTP"

  network_configuration = {
    network_mode = "PUBLIC" # no VPC needed -- only calls Bedrock + the Gateway, both public AWS endpoints
  }

  agent_runtime_artifact = {
    container_configuration = {
      container_uri = "${aws_ecr_repository.agent.repository_url}:latest"
    }
  }

  environment_variables = {
    GATEWAY_URL      = "${aws_bedrockagentcore_gateway.this.gateway_url}/mcp"
    BEDROCK_MODEL_ID = var.bedrock_model_id
  }
}
