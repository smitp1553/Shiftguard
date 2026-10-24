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

# A two step chain. Each policy looks small on its own:
#   dev-gina can assume key-manager-role (nothing else)
#   key-manager-role can create access keys for admin-user (nothing else)
# Together: dev-gina -> key-manager-role -> admin-user -> ADMIN

resource "aws_iam_user" "dev_gina" {
  name = "dev-gina"
}

resource "aws_iam_user_policy" "dev_gina_inline" {
  name = "dev-gina-inline"
  user = aws_iam_user.dev_gina.name
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect   = "Allow"
      Action   = ["sts:AssumeRole"]
      Resource = "arn:aws:iam::123456789012:role/key-manager-role"
    }]
  })
}

resource "aws_iam_role" "key_manager_role" {
  name = "key-manager-role"
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { AWS = "arn:aws:iam::123456789012:user/dev-gina" }
      Action    = "sts:AssumeRole"
    }]
  })
}

resource "aws_iam_role_policy" "key_manager_inline" {
  name = "key-manager-inline"
  role = aws_iam_role.key_manager_role.name
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect   = "Allow"
      Action   = ["iam:CreateAccessKey"]
      Resource = "arn:aws:iam::123456789012:user/admin-user"
    }]
  })
}

resource "aws_iam_user" "admin_user" {
  name = "admin-user"
}

resource "aws_iam_user_policy_attachment" "admin_user_attach" {
  user       = aws_iam_user.admin_user.name
  policy_arn = "arn:aws:iam::aws:policy/AdministratorAccess"
}