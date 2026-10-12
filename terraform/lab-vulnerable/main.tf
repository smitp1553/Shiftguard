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

# Path 2: user can attach any policy (including admin) to himself
resource "aws_iam_user" "dev_bob" {
  name = "dev-bob"
}

resource "aws_iam_user_policy" "dev_bob_inline" {
  name = "dev-bob-inline"
  user = aws_iam_user.dev_bob.name
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect   = "Allow"
      Action   = ["iam:AttachUserPolicy"]
      Resource = "*"
    }]
  })
}

# Path 3: PassRole + RunInstances to an admin role
resource "aws_iam_role" "ec2_admin_role" {
  name = "ec2-admin-role"
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { Service = "ec2.amazonaws.com" }
      Action    = "sts:AssumeRole"
    }]
  })
}

resource "aws_iam_role_policy_attachment" "ec2_admin_attach" {
  role       = aws_iam_role.ec2_admin_role.name
  policy_arn = "arn:aws:iam::aws:policy/AdministratorAccess"
}

resource "aws_iam_user" "dev_carol" {
  name = "dev-carol"
}

resource "aws_iam_user_policy" "dev_carol_inline" {
  name = "dev-carol-inline"
  user = aws_iam_user.dev_carol.name
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect   = "Allow"
      Action   = ["iam:PassRole", "ec2:RunInstances"]
      Resource = "*"
    }]
  })
}

# Path 4: user can create access keys for another user (an admin)
resource "aws_iam_user" "admin_user" {
  name = "admin-user"
}

resource "aws_iam_user_policy_attachment" "admin_user_attach" {
  user       = aws_iam_user.admin_user.name
  policy_arn = "arn:aws:iam::aws:policy/AdministratorAccess"
}

resource "aws_iam_user" "dev_dave" {
  name = "dev-dave"
}

resource "aws_iam_user_policy" "dev_dave_inline" {
  name = "dev-dave-inline"
  user = aws_iam_user.dev_dave.name
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect   = "Allow"
      Action   = ["iam:CreateAccessKey"]
      Resource = "*"
    }]
  })
}

# Path 5: admin role whose trust policy lets anyone in the account assume it
resource "aws_iam_role" "open_admin_role" {
  name = "open-admin-role"
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { AWS = "arn:aws:iam::123456789012:root" }
      Action    = "sts:AssumeRole"
    }]
  })
}

resource "aws_iam_role_policy_attachment" "open_admin_attach" {
  role       = aws_iam_role.open_admin_role.name
  policy_arn = "arn:aws:iam::aws:policy/AdministratorAccess"
}

# Harmless user: no path, proves the tool does not flag everything
resource "aws_iam_user" "dev_frank" {
  name = "dev-frank"
}

resource "aws_iam_user_policy" "dev_frank_inline" {
  name = "dev-frank-inline"
  user = aws_iam_user.dev_frank.name
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect   = "Allow"
      Action   = ["s3:GetObject"]
      Resource = "arn:aws:s3:::example-reports-bucket/*"
    }]
  })
}
