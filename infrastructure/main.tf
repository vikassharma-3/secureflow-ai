# Terraform with intentional misconfigurations (Checkov will catch these)

provider "aws" {
    region = "us-east-1"
}

resource "aws_s3_bucket" "data" {
  bucket = "secureflow-demo-data"

  # VULNERABILITY: Public access not blocked (Checkov will catch this)
}

resource "aws_security_group" "allow_all" {
  name = "allow_all"

  ingress {
    # VULNERABILITY: Open to all IPs (Checkov will catch this)
    from_port   = 0
    to_port     = 65535
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
}