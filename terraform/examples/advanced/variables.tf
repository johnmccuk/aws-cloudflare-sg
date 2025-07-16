# Variables for the advanced example

variable "aws_region" {
  description = "AWS region for resources"
  type        = string
  default     = "us-west-2"
}

variable "vpc_id" {
  description = "VPC ID where security group will be created"
  type        = string
  
  validation {
    condition     = can(regex("^vpc-[0-9a-f]{8,17}$", var.vpc_id))
    error_message = "VPC ID must be a valid AWS VPC ID format (vpc-xxxxxxxx)."
  }
}

variable "environment" {
  description = "Environment name for resource naming and tagging"
  type        = string
  default     = "production"
  
  validation {
    condition     = contains(["development", "staging", "production"], var.environment)
    error_message = "Environment must be one of: development, staging, production."
  }
}

variable "notification_email" {
  description = "Email address for update notifications"
  type        = string
  
  validation {
    condition = can(regex("^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\\.[a-zA-Z]{2,}$", var.notification_email))
    error_message = "Notification email must be a valid email address."
  }
}

# Terraform Cloud variables
variable "terraform_cloud_token" {
  description = "Terraform Cloud API token"
  type        = string
  sensitive   = true
}

variable "terraform_workspace" {
  description = "Terraform Cloud workspace ID"
  type        = string
}

variable "terraform_organization" {
  description = "Terraform Cloud organization name"
  type        = string
}