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
  
  # Parse IPv4 ranges from Cloudflare API response
  cloudflare_ipv4_raw = split("\n", data.http.cloudflare_ips_v4.response_body)
  cloudflare_ipv4_filtered = [
    for ip in local.cloudflare_ipv4_raw : 
    trimspace(ip) if trimspace(ip) != "" && !startswith(trimspace(ip), "#")
  ]
  
  # Parse IPv6 ranges from Cloudflare API response
  cloudflare_ipv6_raw = split("\n", data.http.cloudflare_ips_v6.response_body)
  cloudflare_ipv6_filtered = [
    for ip in local.cloudflare_ipv6_raw : 
    trimspace(ip) if trimspace(ip) != "" && !startswith(trimspace(ip), "#")
  ]
  
  # Validate CIDR format for IPv4 addresses
  cloudflare_ipv4_validated = [
    for cidr in local.cloudflare_ipv4_filtered :
    cidr if can(cidrhost(cidr, 0))
  ]
  
  # Validate CIDR format for IPv6 addresses
  cloudflare_ipv6_validated = [
    for cidr in local.cloudflare_ipv6_filtered :
    cidr if can(cidrhost(cidr, 0))
  ]
  
  # Combine all validated Cloudflare IP ranges
  all_cloudflare_ips = concat(
    local.cloudflare_ipv4_validated,
    local.cloudflare_ipv6_validated
  )
}

# Data sources to fetch Cloudflare IP ranges
data "http" "cloudflare_ips_v4" {
  url = "https://www.cloudflare.com/ips-v4"
  
  request_headers = {
    Accept = "text/plain"
  }
  
  lifecycle {
    postcondition {
      condition     = self.status_code == 200
      error_message = "Failed to fetch Cloudflare IPv4 ranges. HTTP status: ${self.status_code}"
    }
  }
}

data "http" "cloudflare_ips_v6" {
  url = "https://www.cloudflare.com/ips-v6"
  
  request_headers = {
    Accept = "text/plain"
  }
  
  lifecycle {
    postcondition {
      condition     = self.status_code == 200
      error_message = "Failed to fetch Cloudflare IPv6 ranges. HTTP status: ${self.status_code}"
    }
  }
}