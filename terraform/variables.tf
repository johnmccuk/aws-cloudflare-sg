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

# State management and idempotency variables
variable "enable_state_validation" {
  description = "Enable enhanced state validation and drift detection"
  type        = bool
  default     = true
}

variable "enable_drift_detection" {
  description = "Enable drift detection between expected and actual security group state"
  type        = bool
  default     = true
}

variable "ip_change_threshold_percent" {
  description = "Percentage threshold for triggering replacement strategy when IP changes exceed this amount"
  type        = number
  default     = 30
  
  validation {
    condition     = var.ip_change_threshold_percent >= 10 && var.ip_change_threshold_percent <= 100
    error_message = "IP change threshold must be between 10 and 100 percent."
  }
}

variable "max_ip_changes_per_update" {
  description = "Maximum number of IP changes allowed per update before triggering replacement strategy"
  type        = number
  default     = 50
  
  validation {
    condition     = var.max_ip_changes_per_update >= 1 && var.max_ip_changes_per_update <= 200
    error_message = "Maximum IP changes per update must be between 1 and 200."
  }
}

variable "enable_enhanced_lifecycle" {
  description = "Enable enhanced lifecycle management with improved replacement strategies"
  type        = bool
  default     = false
}

# AWS service quota management variables
variable "enable_quota_checking" {
  description = "Enable AWS service quota checking and validation"
  type        = bool
  default     = true
}

variable "max_expected_cloudflare_ips" {
  description = "Maximum expected number of Cloudflare IP ranges (for validation)"
  type        = number
  default     = 200
  
  validation {
    condition     = var.max_expected_cloudflare_ips >= 50 && var.max_expected_cloudflare_ips <= 1000
    error_message = "Maximum expected Cloudflare IPs must be between 50 and 1000."
  }
}

variable "cost_center" {
  description = "Cost center for resource tagging and billing allocation"
  type        = string
  default     = ""
  
  validation {
    condition     = var.cost_center == "" || can(regex("^[a-zA-Z0-9-_]+$", var.cost_center))
    error_message = "Cost center must contain only alphanumeric characters, hyphens, and underscores, or be empty."
  }
}