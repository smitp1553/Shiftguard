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

# alice: was CreatePolicyVersion on *, now only reads one bucket
resource "aws_iam_user" "dev_alice" {
  name = "dev-alice"
}

resource "aws_iam_policy" "dev_alice_policy" {
  name = "dev-alice-policy"
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect   = "Allow"
      Action   = ["s3:GetObject"]
      Resource = "arn:aws:s3:::example-dev-bucket/*"
    }]
  })
}

resource "aws_iam_user_policy_attachment" "dev_alice_attach" {
  user       = aws_iam_user.dev_alice.name
  policy_arn = aws_iam_policy.dev_alice_policy.arn
}

# bob: was AttachUserPolicy on *, now only lists EC2 instances
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
      Action   = ["ec2:DescribeInstances"]
      Resource = "*"
    }]
  })
}

# carol: PassRole is now limited to one low-privilege role (read-only S3)
resource "aws_iam_role" "ec2_app_role" {
  name = "ec2-app-role"
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { Service = "ec2.amazonaws.com" }
      Action    = "sts:AssumeRole"
    }]
  })
}

resource "aws_iam_role_policy_attachment" "ec2_app_attach" {
  role       = aws_iam_role.ec2_app_role.name
  policy_arn = "arn:aws:iam::aws:policy/AmazonS3ReadOnlyAccess"
}

resource "aws_iam_user" "dev_carol" {
  name = "dev-carol"
}

resource "aws_iam_user_policy" "dev_carol_inline" {
  name = "dev-carol-inline"
  user = aws_iam_user.dev_carol.name
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect   = "Allow"
        Action   = ["iam:PassRole"]
        Resource = "arn:aws:iam::123456789012:role/ec2-app-role"
      },
      {
        Effect   = "Allow"
        Action   = ["ec2:RunInstances"]
        Resource = "*"
      }
    ]
  })
}

# admin-user still exists (real accounts have admins), but nobody can reach it
resource "aws_iam_user" "admin_user" {
  name = "admin-user"
}

resource "aws_iam_user_policy_attachment" "admin_user_attach" {
  user       = aws_iam_user.admin_user.name
  policy_arn = "arn:aws:iam::aws:policy/AdministratorAccess"
}

# dave: CreateAccessKey now only for his own user
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
      Resource = "arn:aws:iam::123456789012:user/dev-dave"
    }]
  })
}

# admin role: trust policy now names only admin-user, not the whole account
resource "aws_iam_role" "admin_role" {
  name = "admin-role"
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { AWS = "arn:aws:iam::123456789012:user/admin-user" }
      Action    = "sts:AssumeRole"
    }]
  })
}

resource "aws_iam_role_policy_attachment" "admin_role_attach" {
  role       = aws_iam_role.admin_role.name
  policy_arn = "arn:aws:iam::aws:policy/AdministratorAccess"
}

# frank: unchanged
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
