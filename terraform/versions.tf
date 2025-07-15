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
}

provider "aws" {
  # AWS provider configuration will be handled via environment variables or AWS CLI
}

provider "http" {
  # HTTP provider for fetching Cloudflare IP ranges
}