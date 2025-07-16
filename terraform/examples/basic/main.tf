# Basic example of using the Cloudflare AWS Security Group module

terraform {
  required_version = ">= 1.0"
  
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
  }
}

# Configure the AWS Provider
provider "aws" {
  region = "us-west-2"  # Change to your preferred region
}

# Basic usage with minimal configuration
module "cloudflare_security_group" {
  source = "../../"  # Path to the module root
  
  # Required variables
  vpc_id      = "vpc-12345678"  # Replace with your VPC ID
  environment = "production"
}

# Outputs from the module
output "security_group_id" {
  description = "ID of the created security group"
  value       = module.cloudflare_security_group.security_group_id
}

output "cloudflare_ip_count" {
  description = "Number of Cloudflare IP ranges configured"
  value       = module.cloudflare_security_group.cloudflare_ip_count
}

output "lambda_function_name" {
  description = "Name of the Lambda function for automated updates"
  value       = module.cloudflare_security_group.lambda_function_name
}