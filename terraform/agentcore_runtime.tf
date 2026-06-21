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

# Verified against AWS's own published execution-role policy
# (https://docs.aws.amazon.com/bedrock-agentcore/latest/devguide/runtime-permissions.html)
# rather than inferred from the Lambda container-image precedent -- that
# doc confirms no separate ECR *repository* resource policy is needed
# (unlike Lambda); only this execution role's permissions matter. The
# InvokeGateway statement is an addition on top of AWS's baseline example,
# since that example is the generic "run any agent" policy and doesn't
# cover agents that call a Gateway specifically (confirmed separately
# against https://docs.aws.amazon.com/bedrock-agentcore/latest/devguide/policy-permissions.html).
resource "aws_iam_role_policy" "agentcore_runtime" {
  name = "${var.project_name}-agentcore-runtime"
  role = aws_iam_role.agentcore_runtime.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "EcrImageAccess"
        Effect = "Allow"
        Action = [
          "ecr:BatchGetImage",
          "ecr:GetDownloadUrlForLayer",
        ]
        Resource = aws_ecr_repository.agent.arn
      },
      {
        Sid      = "EcrTokenAccess"
        Effect   = "Allow"
        Action   = "ecr:GetAuthorizationToken"
        Resource = "*"
      },
      {
        Effect = "Allow"
        Action = ["logs:DescribeLogStreams", "logs:CreateLogGroup"]
        Resource = [
          "arn:aws:logs:${var.aws_region}:${data.aws_caller_identity.current.account_id}:log-group:/aws/bedrock-agentcore/runtimes/*",
        ]
      },
      {
        Effect   = "Allow"
        Action   = ["logs:DescribeLogGroups"]
        Resource = ["arn:aws:logs:${var.aws_region}:${data.aws_caller_identity.current.account_id}:log-group:*"]
      },
      {
        Effect = "Allow"
        Action = ["logs:CreateLogStream", "logs:PutLogEvents"]
        Resource = [
          "arn:aws:logs:${var.aws_region}:${data.aws_caller_identity.current.account_id}:log-group:/aws/bedrock-agentcore/runtimes/*:log-stream:*",
        ]
      },
      {
        Effect = "Allow"
        Action = [
          "xray:PutTraceSegments",
          "xray:PutTelemetryRecords",
          "xray:GetSamplingRules",
          "xray:GetSamplingTargets",
        ]
        Resource = "*"
      },
      {
        Effect   = "Allow"
        Resource = "*"
        Action   = "cloudwatch:PutMetricData"
        Condition = {
          StringEquals = { "cloudwatch:namespace" = "bedrock-agentcore" }
        }
      },
      {
        # ForUserId omitted deliberately -- AWS's own guidance is to deny it
        # in production unless caller-supplied user identifiers without IdP
        # verification are actually needed, which this agent doesn't do.
        Sid    = "GetAgentAccessToken"
        Effect = "Allow"
        Action = [
          "bedrock-agentcore:GetWorkloadAccessToken",
          "bedrock-agentcore:GetWorkloadAccessTokenForJWT",
        ]
        Resource = [
          "arn:aws:bedrock-agentcore:${var.aws_region}:${data.aws_caller_identity.current.account_id}:workload-identity-directory/default",
          "arn:aws:bedrock-agentcore:${var.aws_region}:${data.aws_caller_identity.current.account_id}:workload-identity-directory/default/workload-identity/${var.project_name}-*",
        ]
      },
      {
        Sid      = "InvokeGateway"
        Effect   = "Allow"
        Action   = "bedrock-agentcore:InvokeGateway"
        Resource = aws_bedrockagentcore_gateway.this.gateway_arn
      },
      {
        Sid    = "BedrockModelInvocation"
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
    # Without this, boto3.Session().region_name resolves to None inside the
    # container (no ~/.aws/config, no IMDS region for this compute type),
    # which mcp_proxy_for_aws's aws_iam_streamablehttp_client then bakes
    # into a malformed SigV4 credential scope -- AWS rejects it with a
    # generic 403, not a region error, which is why this was hard to spot.
    # Must be AWS_DEFAULT_REGION specifically -- this botocore version's
    # region config chain (configprovider.py) only checks that name, not
    # AWS_REGION (confirmed locally: AWS_REGION alone left region_name None).
    AWS_DEFAULT_REGION = var.aws_region
    # gateway_url already ends in "/mcp" -- appending another "/mcp" here
    # produced a double "/mcp/mcp" path that the Gateway 400'd on.
    GATEWAY_URL      = aws_bedrockagentcore_gateway.this.gateway_url
    BEDROCK_MODEL_ID = var.bedrock_model_id
  }
}
