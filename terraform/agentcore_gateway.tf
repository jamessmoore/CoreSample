# AgentCore Gateway: exposes ec2-audit-mcp and report-mcp (via the API
# Gateway/VPC Link front door in api_gateway.tf) as MCP-callable tools for
# the Strands agent on AgentCore Runtime (agentcore_runtime.tf).
#
# Schema confirmed directly against the installed hashicorp/aws v6.51.0
# provider via `terraform providers schema -json` (not just docs/blog
# guessing) -- every block/attribute name below, including the
# credential_provider_configuration -> gateway_iam_role shape, matched
# `terraform validate` cleanly against the real schema.

resource "aws_iam_role" "agentcore_gateway" {
  name = "${var.project_name}-agentcore-gateway"

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

resource "aws_iam_role_policy" "agentcore_gateway_invoke_targets" {
  name = "${var.project_name}-agentcore-gateway-invoke-targets"
  role = aws_iam_role.agentcore_gateway.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Sid      = "InvokeApiGatewayTargets"
      Effect   = "Allow"
      Action   = "execute-api:Invoke"
      Resource = "arn:aws:execute-api:${var.aws_region}:${data.aws_caller_identity.current.account_id}:${aws_apigatewayv2_api.mcp.id}/*"
    }]
  })
}

resource "aws_bedrockagentcore_gateway" "this" {
  name            = var.project_name
  description     = "Exposes CoreSample's MCP audit/report servers as Bedrock-callable tools"
  role_arn        = aws_iam_role.agentcore_gateway.arn
  authorizer_type = "AWS_IAM" # caller must hold bedrock-agentcore:InvokeGateway on this gateway's ARN
  protocol_type   = "MCP"

  protocol_configuration {
    mcp {
      supported_versions = ["2025-06-18", "2025-03-26", "2025-11-25"]
    }
  }
}

resource "aws_bedrockagentcore_gateway_target" "ec2_audit_mcp" {
  gateway_identifier = aws_bedrockagentcore_gateway.this.gateway_id
  name               = "ec2-audit-mcp"
  description        = "EC2 security/compliance audit checks"

  target_configuration {
    mcp {
      mcp_server {
        endpoint = "${aws_apigatewayv2_stage.default.invoke_url}ec2-audit/mcp"
      }
    }
  }

  # gateway_iam_role: the Gateway signs outbound requests with its own
  # role_arn's SigV4 credentials (aws_iam_role.agentcore_gateway above),
  # scoped to the "execute-api" service so API Gateway (api_gateway.tf)
  # accepts the signature. Confirmed against the real provider schema via
  # `terraform providers schema -json` -- no separate "type" attribute;
  # which block you populate (vs. api_key/oauth/caller_iam_credentials/
  # jwt_passthrough) is itself the type selector.
  credential_provider_configuration {
    gateway_iam_role {
      service = "execute-api"
    }
  }
}

resource "aws_bedrockagentcore_gateway_target" "iam_audit_mcp" {
  gateway_identifier = aws_bedrockagentcore_gateway.this.gateway_id
  name               = "iam-audit-mcp"
  description        = "IAM security/compliance audit checks"

  target_configuration {
    mcp {
      mcp_server {
        endpoint = "${aws_apigatewayv2_stage.default.invoke_url}iam-audit/mcp"
      }
    }
  }

  credential_provider_configuration {
    gateway_iam_role {
      service = "execute-api"
    }
  }
}

resource "aws_bedrockagentcore_gateway_target" "s3_audit_mcp" {
  gateway_identifier = aws_bedrockagentcore_gateway.this.gateway_id
  name               = "s3-audit-mcp"
  description        = "S3 security/compliance audit checks"

  target_configuration {
    mcp {
      mcp_server {
        endpoint = "${aws_apigatewayv2_stage.default.invoke_url}s3-audit/mcp"
      }
    }
  }

  credential_provider_configuration {
    gateway_iam_role {
      service = "execute-api"
    }
  }
}

resource "aws_bedrockagentcore_gateway_target" "report_mcp" {
  gateway_identifier = aws_bedrockagentcore_gateway.this.gateway_id
  name               = "report-mcp"
  description        = "Findings-to-Markdown report generation"

  target_configuration {
    mcp {
      mcp_server {
        endpoint = "${aws_apigatewayv2_stage.default.invoke_url}report/mcp"
      }
    }
  }

  credential_provider_configuration {
    gateway_iam_role {
      service = "execute-api"
    }
  }
}
