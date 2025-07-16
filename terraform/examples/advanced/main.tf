# Advanced example of using the Cloudflare AWS Security Group module
# This example demonstrates advanced features including:
# - Multiple ports and custom protocols
# - Terraform Cloud integration
# - Comprehensive monitoring and alerting
# - Custom tagging strategy

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

# Advanced configuration with full feature set
module "cloudflare_security_group" {
  source = "../../"  # Path to the module root
  
  # Required variables
  vpc_id      = var.vpc_id
  environment = var.environment
  
  # Security Group Configuration
  allowed_ports = [80, 443, 8080, 8443]  # HTTP, HTTPS, and custom ports
  protocol      = "tcp"
  
  # Automation Configuration
  enable_automation = true
  update_schedule   = "cron(0 2,14 * * ? *)"  # Twice daily at 2 AM and 2 PM UTC
  
  # Notification Configuration
  notification_email = var.notification_email
  
  # Terraform Cloud Configuration
  terraform_mode         = "cloud"
  terraform_cloud_token  = var.terraform_cloud_token
  terraform_workspace    = var.terraform_workspace
  terraform_organization = var.terraform_organization
  
  # Comprehensive tagging strategy
  tags = {
    Project      = "web-infrastructure"
    Owner        = "platform-team"
    CostCenter   = "engineering"
    Environment  = var.environment
    Criticality  = "high"
    Backup       = "required"
    Monitoring   = "enhanced"
    Compliance   = "required"
    DataClass    = "internal"
    ManagedBy    = "terraform"
    Repository   = "infrastructure/cloudflare-security-group"
    LastModified = timestamp()
  }
}

# Data source to get VPC information
data "aws_vpc" "selected" {
  id = var.vpc_id
}

# Additional security group for internal communication (example of extending the module)
resource "aws_security_group" "internal_communication" {
  name_prefix = "internal-${var.environment}-"
  description = "Internal communication security group"
  vpc_id      = var.vpc_id

  # Allow communication from Cloudflare security group
  ingress {
    description     = "Internal traffic from Cloudflare security group"
    from_port       = 80
    to_port         = 8080
    protocol        = "tcp"
    security_groups = [module.cloudflare_security_group.security_group_id]
  }

  egress {
    description = "All outbound traffic"
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = {
    Name        = "internal-${var.environment}"
    Environment = var.environment
    Purpose     = "Internal communication"
    ManagedBy   = "terraform"
  }
}