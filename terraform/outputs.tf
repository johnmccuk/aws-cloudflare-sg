# Output definitions for Cloudflare whitelist security group
# Resources referenced here will be created in subsequent tasks

# output "security_group_id" {
#   description = "ID of the created Cloudflare whitelist security group"
#   value       = aws_security_group.cloudflare_whitelist.id
# }

# output "security_group_arn" {
#   description = "ARN of the created Cloudflare whitelist security group"
#   value       = aws_security_group.cloudflare_whitelist.arn
# }

# output "security_group_name" {
#   description = "Name of the created Cloudflare whitelist security group"
#   value       = aws_security_group.cloudflare_whitelist.name
# }

# output "cloudflare_ip_count" {
#   description = "Number of Cloudflare IP ranges configured in the security group"
#   value       = length(local.all_cloudflare_ips)
# }

output "configured_ports" {
  description = "List of ports configured in the security group rules"
  value       = var.allowed_ports
}

output "protocol" {
  description = "Protocol configured for the security group rules"
  value       = var.protocol
}