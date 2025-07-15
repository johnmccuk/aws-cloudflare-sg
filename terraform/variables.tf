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
  default     = "prod"
  
  validation {
    condition     = can(regex("^[a-zA-Z0-9-_]+$", var.environment))
    error_message = "Environment must contain only alphanumeric characters, hyphens, and underscores."
  }
}

variable "allowed_ports" {
  description = "List of ports to allow from Cloudflare IPs"
  type        = list(number)
  default     = [443]
  
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

variable "update_schedule" {
  description = "Cron expression for automated updates"
  type        = string
  default     = "cron(0 2 * * ? *)"
  
  validation {
    condition     = can(regex("^(rate\\(.*\\)|cron\\(.*\\))$", var.update_schedule))
    error_message = "Update schedule must be a valid EventBridge schedule expression (rate() or cron() format)."
  }
}

variable "enable_automation" {
  description = "Enable automated updates via EventBridge scheduling"
  type        = bool
  default     = true
}

variable "notification_email" {
  description = "Email address for update notifications"
  type        = string
  default     = ""
  
  validation {
    condition = var.notification_email == "" || can(regex("^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\\.[a-zA-Z]{2,}$", var.notification_email))
    error_message = "Notification email must be a valid email address or empty string."
  }
}

variable "tags" {
  description = "Additional tags to apply to resources"
  type        = map(string)
  default     = {}
}

# Terraform automation variables
variable "terraform_mode" {
  description = "Terraform execution mode: 'direct' for local execution, 'cloud' for Terraform Cloud"
  type        = string
  default     = "direct"
  
  validation {
    condition     = contains(["direct", "cloud"], var.terraform_mode)
    error_message = "Terraform mode must be either 'direct' or 'cloud'."
  }
}

variable "terraform_cloud_token" {
  description = "Terraform Cloud API token (required if terraform_mode is 'cloud')"
  type        = string
  default     = ""
  sensitive   = true
}

variable "terraform_workspace" {
  description = "Terraform Cloud workspace ID (required if terraform_mode is 'cloud')"
  type        = string
  default     = ""
}

variable "terraform_organization" {
  description = "Terraform Cloud organization name (required if terraform_mode is 'cloud')"
  type        = string
  default     = ""
}

variable "terraform_config_s3_bucket" {
  description = "S3 bucket containing Terraform configuration (required if terraform_mode is 'direct')"
  type        = string
  default     = ""
}

variable "terraform_config_s3_key" {
  description = "S3 key for Terraform configuration file (required if terraform_mode is 'direct')"
  type        = string
  default     = ""
}

variable "terraform_state_s3_bucket" {
  description = "S3 bucket for Terraform state storage (optional for direct mode)"
  type        = string
  default     = ""
}

variable "terraform_state_s3_key" {
  description = "S3 key for Terraform state file (optional for direct mode)"
  type        = string
  default     = ""
}