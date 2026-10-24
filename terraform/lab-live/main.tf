terraform {
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
  }
}

# REAL account: uses the "admin" cli profile (keys are in your home folder, not in this repo)
provider "aws" {
  region  = "us-east-1"
  profile = "admin"
}

data "aws_caller_identity" "me" {}

locals {
  acct = data.aws_caller_identity.me.account_id
  user = "arn:aws:iam::${local.acct}:user"
  role = "arn:aws:iam::${local.acct}:role"
}

# users (force_destroy so terraform can delete keys and passwords created by hand)
resource "aws_iam_user" "dev_alice" {
  name          = "dev-alice"
  force_destroy = true
}
resource "aws_iam_user" "dev_bob" {
  name          = "dev-bob"
  force_destroy = true
}
resource "aws_iam_user" "dev_pete" {
  name          = "dev-pete"
  force_destroy = true
}
resource "aws_iam_user" "dev_dave" {
  name          = "dev-dave"
  force_destroy = true
}
resource "aws_iam_user" "dev_lara" {
  name          = "dev-lara"
  force_destroy = true
}
resource "aws_iam_user" "dev_quinn" {
  name          = "dev-quinn"
  force_destroy = true
}
resource "aws_iam_user" "dev_gina" {
  name          = "dev-gina"
  force_destroy = true
}
resource "aws_iam_user" "victim_user" {
  name          = "victim-user"
  force_destroy = true
}

# alice: CreatePolicyVersion + SetDefaultPolicyVersion on her own managed policy
resource "aws_iam_policy" "dev_alice_policy" {
  name = "dev-alice-policy"
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect   = "Allow"
      Action   = ["iam:CreatePolicyVersion", "iam:SetDefaultPolicyVersion", "iam:ListPolicyVersions"]
      Resource = "arn:aws:iam::${local.acct}:policy/dev-alice-policy"
    }]
  })
}

resource "aws_iam_user_policy_attachment" "dev_alice_attach" {
  user       = aws_iam_user.dev_alice.name
  policy_arn = aws_iam_policy.dev_alice_policy.arn
}

# bob: AttachUserPolicy on himself
resource "aws_iam_user_policy" "dev_bob_inline" {
  name = "dev-bob-inline"
  user = aws_iam_user.dev_bob.name
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect   = "Allow"
      Action   = ["iam:AttachUserPolicy"]
      Resource = "${local.user}/dev-bob"
    }]
  })
}

# pete: PutUserPolicy on himself
resource "aws_iam_user_policy" "dev_pete_inline" {
  name = "dev-pete-inline"
  user = aws_iam_user.dev_pete.name
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect   = "Allow"
      Action   = ["iam:PutUserPolicy"]
      Resource = "${local.user}/dev-pete"
    }]
  })
}

# dave: CreateAccessKey for victim-user
resource "aws_iam_user_policy" "dev_dave_inline" {
  name = "dev-dave-inline"
  user = aws_iam_user.dev_dave.name
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect   = "Allow"
      Action   = ["iam:CreateAccessKey"]
      Resource = "${local.user}/victim-user"
    }]
  })
}

# lara: CreateLoginProfile / UpdateLoginProfile for victim-user
resource "aws_iam_user_policy" "dev_lara_inline" {
  name = "dev-lara-inline"
  user = aws_iam_user.dev_lara.name
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect   = "Allow"
      Action   = ["iam:CreateLoginProfile", "iam:UpdateLoginProfile"]
      Resource = "${local.user}/victim-user"
    }]
  })
}

# quinn: UpdateAssumeRolePolicy on target-role
resource "aws_iam_user_policy" "dev_quinn_inline" {
  name = "dev-quinn-inline"
  user = aws_iam_user.dev_quinn.name
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect   = "Allow"
      Action   = ["iam:UpdateAssumeRolePolicy"]
      Resource = "${local.role}/target-role"
    }]
  })
}

resource "aws_iam_role" "target_role" {
  name       = "target-role"
  depends_on = [aws_iam_user.dev_quinn]
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { AWS = "${local.user}/dev-quinn" }
      Action    = "sts:AssumeRole"
    }]
  })
}

# gina: AssumeRole into key-manager-role, which can create keys for victim-user (the 2 step chain)
resource "aws_iam_user_policy" "dev_gina_inline" {
  name = "dev-gina-inline"
  user = aws_iam_user.dev_gina.name
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect   = "Allow"
      Action   = ["sts:AssumeRole"]
      Resource = "${local.role}/key-manager-role"
    }]
  })
}

resource "aws_iam_role" "key_manager_role" {
  name       = "key-manager-role"
  depends_on = [aws_iam_user.dev_gina]
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { AWS = "${local.user}/dev-gina" }
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
      Resource = "${local.user}/victim-user"
    }]
  })
}