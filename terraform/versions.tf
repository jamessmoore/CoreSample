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

  # S3 backend, same pattern as daily-tech-brief-bedrock/terraform/main.tf:
  # native S3 conditional-write locking (use_lockfile, requires Terraform
  # 1.10+ -- see required_version above), no DynamoDB lock table needed.
  # The bucket can't be created by the same config that uses it as a
  # backend (chicken-and-egg), so it's bootstrapped out of band -- see
  # README "Terraform state backend".
  backend "s3" {
    bucket       = "coresample-tfstate-293528978619"
    key          = "coresample/terraform.tfstate"
    region       = "us-west-2"
    encrypt      = true
    use_lockfile = true
  }
}

provider "aws" {
  region = var.aws_region
}

provider "awscc" {
  region = var.aws_region
}

data "aws_caller_identity" "current" {}
data "aws_region" "current" {}
