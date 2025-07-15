terraform {
  required_version = ">= 1.0"
  
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
    http = {
      source  = "hashicorp/http"
      version = "~> 3.0"
    }
  }

  backend "s3" {
    bucket         = "831926585319-terraform-states"
    key            = "prod/aws-cloudflare-sg.tfstate"
    encrypt        = true
    region         = "eu-west-1"
    use_lockfile   = true
  }
}

provider "aws" {
  # AWS provider configuration will be handled via environment variables or AWS CLI
}

provider "http" {
  # HTTP provider for fetching Cloudflare IP ranges
}