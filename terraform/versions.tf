terraform {
  required_version = ">= 1.10"

  required_providers {
    aws = {
      source = "hashicorp/aws"
      # aws_bedrockagentcore_gateway / _gateway_target (MCP server target
      # support specifically) landed in v6.21.0+ of this provider -- verify
      # against the changelog before assuming a pinned version here is
      # still current.
      version = ">= 6.22"
    }
    # AgentCore Runtime has no native `aws` provider resource yet as of this
    # writing -- only awscc_bedrockagentcore_runtime (Cloud Control API,
    # auto-generated from the CloudFormation resource schema). See
    # agentcore_runtime.tf.
    awscc = {
      source  = "hashicorp/awscc"
      version = ">= 1.0"
    }
  }

  # No remote backend yet -- this is a solo portfolio project with no team
  # state-sharing need at v1. Local state is fine for now; revisit (S3 +
  # native locking, see daily-tech-brief-bedrock/terraform/main.tf for the
  # pattern already used elsewhere) before this grows beyond one operator.
}

provider "aws" {
  region = var.aws_region
}

provider "awscc" {
  region = var.aws_region
}

data "aws_caller_identity" "current" {}
data "aws_region" "current" {}
