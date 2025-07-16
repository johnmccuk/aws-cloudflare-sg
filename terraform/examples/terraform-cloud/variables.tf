# Variables for Terraform Cloud Integration Example

# AWS Configuration
variable "aws_region" {
  description = "AWS region for resource deployment"
  type        = string
  default     = "us-west-2"
  
  validation {
    condition = contains([
      "us-east-1", "us-east-2", "us-west-1", "us-west-2",
      "eu-west-1", "eu-west-2", "eu-west-3", "eu-central-1",
      "ap-southeast-1", "ap-southeast-2", "ap-northeast-1",
      "ca-central-1", "sa-east-1"
    ], var.aws_region)
    error_message = "AWS region must be one of the supported regions for all required services."
  }
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
    condition     = can(regex("^[a-zA-Z0-9-_]+$", var.environment))
    error_message = "Environment must contain only alphanumeric characters, hyphens, and underscores."
  }
}

# Network Configuration
variable "allowed_ports" {
  description = "List of ports to allow from Cloudflare IPs"
  type        = list(number)
  default     = [443, 80]
  
  validation {
    condition     = alltrue([for port in var.allowed_ports : port >= 1 && port <= 65535])
    error_message = "All ports must be between 1 and 65535."
  }
}

variable "protocol" {
  description = "Protocol for security group rules"
  type        = string
  default     = "tcp"
  
  validation {
    condition     = contains(["tcp", "udp", "icmp"], var.protocol)
    error_message = "Protocol must be one of: tcp, udp, icmp."
  }
}

variable "public_subnet_ids" {
  description = "List of public subnet IDs for ALB (required if create_example_alb is true)"
  type        = list(string)
  default     = []
  
  validation {
    condition = alltrue([
      for subnet_id in var.public_subnet_ids : 
      can(regex("^subnet-[0-9a-f]{8,17}$", subnet_id))
    ])
    error_message = "All subnet IDs must be valid AWS subnet ID format (subnet-xxxxxxxx)."
  }
}

# Terraform Cloud Configuration
variable "terraform_organization" {
  description = "Terraform Cloud organization name"
  type        = string
  
  validation {
    condition     = length(var.terraform_organization) > 0
    error_message = "Terraform organization name cannot be empty."
  }
}

variable "terraform_workspace_name" {
  description = "Terraform Cloud workspace name"
  type        = string
  
  validation {
    condition     = can(regex("^[a-zA-Z0-9-_]+$", var.terraform_workspace_name))
    error_message = "Workspace name must contain only alphanumeric characters, hyphens, and underscores."
  }
}

variable "terraform_workspace_id" {
  description = "Terraform Cloud workspace ID (for API operations)"
  type        = string
  
  validation {
    condition     = can(regex("^ws-[a-zA-Z0-9]+$", var.terraform_workspace_id))
    error_message = "Workspace ID must be in the format ws-xxxxxxxx."
  }
}

variable "terraform_cloud_token" {
  description = "Terraform Cloud API token"
  type        = string
  sensitive   = true
  
  validation {
    condition     = length(var.terraform_cloud_token) > 0
    error_message = "Terraform Cloud token cannot be empty."
  }
}

# Automation Configuration
variable "enable_automation" {
  description = "Enable automated updates via EventBridge scheduling"
  type        = bool
  default     = true
}

variable "update_schedule" {
  description = "Cron expression for automated updates"
  type        = string
  default     = "cron(0 2 * * ? *)"  # Daily at 2 AM UTC
  
  validation {
    condition     = can(regex("^(rate\\(.*\\)|cron\\(.*\\))$", var.update_schedule))
    error_message = "Update schedule must be a valid EventBridge schedule expression (rate() or cron() format)."
  }
}

# Monitoring Configuration
variable "notification_email" {
  description = "Email address for update notifications"
  type        = string
  default     = ""
  
  validation {
    condition = var.notification_email == "" || can(regex("^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\\.[a-zA-Z]{2,}$", var.notification_email))
    error_message = "Notification email must be a valid email address or empty string."
  }
}

variable "log_retention_days" {
  description = "CloudWatch log retention period in days"
  type        = number
  default     = 14
  
  validation {
    condition = contains([
      1, 3, 5, 7, 14, 30, 60, 90, 120, 150, 180, 365, 400, 545, 731, 1827, 3653
    ], var.log_retention_days)
    error_message = "Log retention days must be a valid CloudWatch retention period."
  }
}

# Example Resources Configuration
variable "create_example_alb" {
  description = "Create example Application Load Balancer to demonstrate usage"
  type        = bool
  default     = false
}

variable "ssl_certificate_arn" {
  description = "ARN of SSL certificate for HTTPS listener (required if create_example_alb is true)"
  type        = string
  default     = ""
  
  validation {
    condition = var.create_example_alb == false || (
      var.ssl_certificate_arn != "" && 
      can(regex("^arn:aws:acm:[a-z0-9-]+:[0-9]{12}:certificate/[a-f0-9-]+$", var.ssl_certificate_arn))
    )
    error_message = "SSL certificate ARN must be provided and valid when create_example_alb is true."
  }
}

# Tagging
variable "tags" {
  description = "Additional tags to apply to resources"
  type        = map(string)
  default = {
    Project     = "CloudflareIntegration"
    Owner       = "DevOpsTeam"
    CostCenter  = "Infrastructure"
    Compliance  = "Required"
  }
  
  validation {
    condition = alltrue([
      for key, value in var.tags : 
      can(regex("^[a-zA-Z0-9-_:./=+@]+$", key)) && 
      can(regex("^[a-zA-Z0-9-_:./=+@\\s]+$", value))
    ])
    error_message = "Tag keys and values must contain only valid AWS tag characters."
  }
}