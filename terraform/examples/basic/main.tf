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
  region = var.aws_region
}

# Variables for the basic example
variable "vpc_id" {
  description = "VPC ID where the security group will be created (leave empty to use default VPC)"
  type        = string
  default     = ""
  
  validation {
    condition     = var.vpc_id == "" || can(regex("^vpc-[0-9a-f]{8,17}$", var.vpc_id))
    error_message = "VPC ID must be a valid AWS VPC ID format (vpc-xxxxxxxx) or empty string to use default VPC."
  }
}

variable "aws_region" {
  description = "AWS region for resources"
  type        = string
  default     = "us-east-1"
}

variable "environment" {
  description = "Environment name for resource naming and tagging"
  type        = string
  default     = "dev"
  
  validation {
    condition     = can(regex("^[a-zA-Z0-9-_]+$", var.environment))
    error_message = "Environment must contain only alphanumeric characters, hyphens, and underscores."
  }
}

variable "notification_email" {
  description = "Email address for update notifications (optional)"
  type        = string
  default     = ""
  
  validation {
    condition = var.notification_email == "" || can(regex("^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\\.[a-zA-Z]{2,}$", var.notification_email))
    error_message = "Notification email must be a valid email address or empty string."
  }
}

# Data source to get the default VPC if no VPC ID is provided
data "aws_vpc" "default" {
  count   = var.vpc_id == "" ? 1 : 0
  default = true
}

# Local values for configuration
locals {
  vpc_id = var.vpc_id != "" ? var.vpc_id : data.aws_vpc.default[0].id
}

# Basic usage with minimal configuration
module "cloudflare_security_group" {
  source = "../../"  # Path to the module root
  
  # Required variables
  vpc_id      = local.vpc_id
  environment = var.environment
  
  # Optional configuration - customize as needed
  allowed_ports = [80, 443]  # HTTP and HTTPS
  protocol      = "tcp"
  
  # Notification configuration (optional)
  notification_email = var.notification_email
  
  # Automation settings
  enable_automation = true
  update_schedule   = "cron(0 2 * * ? *)"  # Daily at 2 AM UTC
  
  # State management features
  enable_state_validation = true
  enable_drift_detection  = true
  
  # Quota management
  enable_quota_checking = true
  
  # Additional tags
  tags = {
    Project     = "cloudflare-security"
    Owner       = "infrastructure-team"
    Environment = var.environment
    Example     = "basic"
  }
}

# Outputs from the module
output "security_group_id" {
  description = "ID of the created security group"
  value       = module.cloudflare_security_group.security_group_id
}

output "security_group_name" {
  description = "Name of the created security group"
  value       = module.cloudflare_security_group.security_group_name
}

output "cloudflare_ip_count" {
  description = "Number of Cloudflare IP ranges configured"
  value       = module.cloudflare_security_group.cloudflare_ip_count
}

output "configured_ports" {
  description = "List of ports configured in the security group"
  value       = module.cloudflare_security_group.configured_ports
}

output "lambda_function_name" {
  description = "Name of the Lambda function for automated updates"
  value       = module.cloudflare_security_group.lambda_function_name
}

output "lambda_function_arn" {
  description = "ARN of the Lambda function for automated updates"
  value       = module.cloudflare_security_group.lambda_function_arn
}

output "eventbridge_rule_name" {
  description = "Name of the EventBridge rule for scheduled updates"
  value       = module.cloudflare_security_group.eventbridge_rule_name
}

output "cloudwatch_log_group_name" {
  description = "Name of the CloudWatch log group for Lambda function"
  value       = module.cloudflare_security_group.cloudwatch_log_group_name
}

output "sns_topic_arn" {
  description = "ARN of the SNS topic for notifications (if configured)"
  value       = module.cloudflare_security_group.sns_topic_arn
}

output "automation_enabled" {
  description = "Whether automated updates are enabled"
  value       = module.cloudflare_security_group.automation_enabled
}

output "update_schedule" {
  description = "Configured schedule expression for automated updates"
  value       = module.cloudflare_security_group.update_schedule
}

output "cleanup_function_name" {
  description = "Name of the cleanup Lambda function (if automation is enabled)"
  value       = module.cloudflare_security_group.cleanup_function_name
}

output "state_management_status" {
  description = "Status of enhanced state management features"
  value       = module.cloudflare_security_group.state_management_status
}

output "cleanup_resources_inventory" {
  description = "Inventory of all resources that will be cleaned up during destroy"
  value       = module.cloudflare_security_group.cleanup_resources_inventory
}

output "destroy_instructions" {
  description = "Instructions for proper resource destruction"
  value       = module.cloudflare_security_group.destroy_instructions
}