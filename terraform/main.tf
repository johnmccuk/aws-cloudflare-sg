# Main Terraform configuration for Cloudflare IP whitelist security group
# This file contains the core resources and data sources

# Local values for common tags and naming
locals {
  common_tags = merge(
    {
      Environment = var.environment
      Purpose     = "Cloudflare IP Whitelist"
      ManagedBy   = "Terraform"
      LastUpdated = timestamp()
    },
    var.tags
  )
  
  security_group_name = "cloudflare-whitelist-${var.environment}"
}

# Data sources and resources will be added in subsequent tasks
# This file serves as the main entry point for the Terraform configuration