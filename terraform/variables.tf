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