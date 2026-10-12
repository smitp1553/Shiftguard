terraform {
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
  }
}

provider "aws" {
  region                      = "us-east-1"
  access_key                  = "fake"
  secret_key                  = "fake"
  skip_credentials_validation = true
  skip_requesting_account_id  = true
  skip_metadata_api_check     = true
}

# Path 1: user can rewrite the policy that is attached to themselves
resource "aws_iam_user" "dev_alice" {
  name = "dev-alice"
}

resource "aws_iam_policy" "dev_alice_policy" {
  name = "dev-alice-policy"
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect   = "Allow"
      Action   = ["iam:CreatePolicyVersion", "iam:SetDefaultPolicyVersion"]
      Resource = "*"
    }]
  })
}

resource "aws_iam_user_policy_attachment" "dev_alice_attach" {
  user       = aws_iam_user.dev_alice.name
  policy_arn = aws_iam_policy.dev_alice_policy.arn
}
