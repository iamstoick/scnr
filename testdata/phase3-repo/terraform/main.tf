provider "aws" {
  region = "us-east-1"
}

variable "db_password" {
  type    = string
  default = "hunter2-not-a-real-pw"
}

resource "aws_s3_bucket" "public_logs" {
  bucket = "demo-public-logs"
  acl    = "public-read"
}

resource "aws_s3_bucket" "guarded" {
  bucket = "demo-guarded"
}

resource "aws_s3_bucket_public_access_block" "guarded" {
  bucket                  = aws_s3_bucket.guarded.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_server_side_encryption_configuration" "guarded" {
  bucket = aws_s3_bucket.guarded.id
  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "aws:kms"
    }
  }
}

resource "aws_s3_bucket_versioning" "guarded" {
  bucket = aws_s3_bucket.guarded.id
  versioning_configuration {
    status = "Enabled"
  }
}

resource "aws_s3_bucket_logging" "guarded" {
  bucket        = "demo-guarded"
  target_bucket = aws_s3_bucket.public_logs.id
  target_prefix = "log/"
}

resource "aws_security_group" "web" {
  name = "web"

  ingress {
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  ingress {
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  ingress {
    from_port        = 0
    to_port          = 0
    protocol         = "-1"
    ipv6_cidr_blocks = ["::/0"]
  }
}

resource "aws_security_group_rule" "rdp" {
  type              = "ingress"
  from_port         = 3389
  to_port           = 3389
  protocol          = "tcp"
  cidr_blocks       = ["0.0.0.0/0"]
  security_group_id = aws_security_group.web.id
}

resource "aws_db_instance" "main" {
  engine                  = "postgres"
  instance_class          = "db.t3.micro"
  publicly_accessible     = true
  backup_retention_period = 0
  password                = var.db_password
}

resource "aws_ebs_volume" "data" {
  availability_zone = "us-east-1a"
  size              = 10
}

resource "aws_instance" "bastion" {
  ami                         = "ami-12345678"
  instance_type               = "t3.micro"
  associate_public_ip_address = true
  root_block_device {
    volume_size = 20
  }
}

resource "aws_iam_policy" "admin" {
  name   = "admin"
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect   = "Allow"
      Action   = "*"
      Resource = "*"
    }]
  })
}

resource "aws_iam_role_policy" "heredoc" {
  name = "heredoc"
  role = "x"
  policy = <<EOT
{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":["s3:GetObject"],"Resource":"*"}]}
EOT
}

data "aws_iam_policy_document" "wild" {
  statement {
    effect    = "Allow"
    actions   = ["*"]
    resources = ["*"]
  }
}

resource "aws_cloudtrail" "main" {
  name           = "main"
  s3_bucket_name = aws_s3_bucket.public_logs.id
  enable_logging = false
}

resource "aws_kms_key" "main" {
  description = "main"
}

resource "aws_lambda_function" "fn" {
  function_name = "fn"
  role          = "arn:aws:iam::123456789012:role/x"
  environment {
    variables = {
      API_KEY  = "fake-api-token-not-real-0000000"
      LOG_LEVEL = "info"
    }
  }
}
