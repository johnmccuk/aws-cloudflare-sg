# Validation rules and checks for enhanced state management
# This file contains validation logic to ensure proper configuration and state consistency

# Validation for state management configuration
check "state_management_config_valid" {
  assert {
    condition = !(var.enable_drift_detection && !var.enable_state_validation)
    error_message = "Drift detection requires state validation to be enabled. Set enable_state_validation = true when enable_drift_detection = true."
  }
}

check "replacement_strategy_thresholds_valid" {
  assert {
    condition = var.ip_change_threshold_percent >= 10 && var.ip_change_threshold_percent <= 100
    error_message = "IP change threshold percentage must be between 10 and 100."
  }
}

check "max_ip_changes_reasonable" {
  assert {
    condition = var.max_ip_changes_per_update >= 1 && var.max_ip_changes_per_update <= 200
    error_message = "Maximum IP changes per update must be between 1 and 200."
  }
}

# Validation for quota management
check "quota_checking_config_valid" {
  assert {
    condition = !var.enable_quota_checking || var.max_expected_cloudflare_ips > 0
    error_message = "When quota checking is enabled, max_expected_cloudflare_ips must be greater than 0."
  }
}

# Validation for Terraform automation mode
check "terraform_cloud_config_complete" {
  assert {
    condition = var.terraform_mode != "cloud" || (
      var.terraform_cloud_token != "" &&
      var.terraform_workspace != "" &&
      var.terraform_organization != ""
    )
    error_message = "When terraform_mode is 'cloud', terraform_cloud_token, terraform_workspace, and terraform_organization must all be provided."
  }
}

check "terraform_direct_config_valid" {
  assert {
    condition = var.terraform_mode != "direct" || var.terraform_config_s3_bucket != ""
    error_message = "When terraform_mode is 'direct', terraform_config_s3_bucket must be provided."
  }
}

# Validation for enhanced lifecycle management
check "enhanced_lifecycle_dependencies" {
  assert {
    condition = !var.enable_enhanced_lifecycle || (var.enable_state_validation && var.enable_drift_detection)
    error_message = "Enhanced lifecycle management requires both state validation and drift detection to be enabled."
  }
}

# Local validation for IP count and rule limits
locals {
  # Calculate total rules needed for validation
  total_ips_estimated = var.max_expected_cloudflare_ips
  total_ports_validation = length(var.allowed_ports)
  estimated_rules_needed = local.total_ips_estimated * local.total_ports_validation + 2  # +2 for egress rules
  
  # Validation flags
  rules_will_exceed_limit = local.estimated_rules_needed > 120  # AWS default limit
  multiple_groups_will_be_needed = local.rules_will_exceed_limit
}

# Warning outputs for configuration issues
output "configuration_warnings" {
  description = "Configuration warnings and recommendations"
  value = {
    rules_may_exceed_limit = local.rules_will_exceed_limit ? "WARNING: Estimated rules (${local.estimated_rules_needed}) may exceed AWS limit. Consider enabling quota checking." : "OK"
    multiple_groups_needed = local.multiple_groups_will_be_needed ? "INFO: Multiple security groups may be needed due to rule limits." : "Single security group sufficient"
    state_management_enabled = var.enable_state_validation ? "State validation enabled" : "WARNING: State validation disabled - consider enabling for production use"
    drift_detection_enabled = var.enable_drift_detection ? "Drift detection enabled" : "WARNING: Drift detection disabled - consider enabling for production use"
    quota_checking_enabled = var.enable_quota_checking ? "Quota checking enabled" : "WARNING: Quota checking disabled - consider enabling for production use"
  }
}

# Validation for notification configuration
check "notification_config_valid" {
  assert {
    condition = var.notification_email == "" || can(regex("^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\\.[a-zA-Z]{2,}$", var.notification_email))
    error_message = "If provided, notification_email must be a valid email address."
  }
}

# Pre-deployment validation check
resource "null_resource" "pre_deployment_validation" {
  triggers = {
    # Trigger validation when key configuration changes
    state_validation_enabled = var.enable_state_validation
    drift_detection_enabled = var.enable_drift_detection
    quota_checking_enabled = var.enable_quota_checking
    enhanced_lifecycle_enabled = var.enable_enhanced_lifecycle
    terraform_mode = var.terraform_mode
    vpc_id = var.vpc_id
  }

  provisioner "local-exec" {
    command = <<-EOT
      echo "=== Pre-deployment Validation ==="
      echo "VPC ID: ${var.vpc_id}"
      echo "Environment: ${var.environment}"
      echo "State Validation: ${var.enable_state_validation ? "Enabled" : "Disabled"}"
      echo "Drift Detection: ${var.enable_drift_detection ? "Enabled" : "Disabled"}"
      echo "Quota Checking: ${var.enable_quota_checking ? "Enabled" : "Disabled"}"
      echo "Enhanced Lifecycle: ${var.enable_enhanced_lifecycle ? "Enabled" : "Disabled"}"
      echo "Terraform Mode: ${var.terraform_mode}"
      echo "Allowed Ports: ${join(", ", var.allowed_ports)}"
      echo "Protocol: ${var.protocol}"
      echo "IP Change Threshold: ${var.ip_change_threshold_percent}%"
      echo "Max IP Changes Per Update: ${var.max_ip_changes_per_update}"
      echo "Max Expected Cloudflare IPs: ${var.max_expected_cloudflare_ips}"
      echo "Estimated Rules Needed: ${local.estimated_rules_needed}"
      echo "Multiple Groups Needed: ${local.multiple_groups_will_be_needed ? "Yes" : "No"}"
      echo "=== Validation Complete ==="
    EOT
  }
}

# Data source to validate VPC exists
data "aws_vpc" "target_vpc" {
  id = var.vpc_id
}

# Validation that VPC exists and is available
check "vpc_exists_and_available" {
  assert {
    condition = data.aws_vpc.target_vpc.state == "available"
    error_message = "Target VPC ${var.vpc_id} is not in 'available' state. Current state: ${data.aws_vpc.target_vpc.state}"
  }
}

# Output validation summary
output "validation_summary" {
  description = "Summary of validation checks and configuration"
  value = {
    vpc_validated = "VPC ${var.vpc_id} exists and is available"
    state_management = {
      state_validation = var.enable_state_validation
      drift_detection = var.enable_drift_detection
      enhanced_lifecycle = var.enable_enhanced_lifecycle
      ip_change_threshold = "${var.ip_change_threshold_percent}%"
      max_changes_per_update = var.max_ip_changes_per_update
    }
    quota_management = {
      quota_checking_enabled = var.enable_quota_checking
      max_expected_ips = var.max_expected_cloudflare_ips
      estimated_rules = local.estimated_rules_needed
      multiple_groups_needed = local.multiple_groups_will_be_needed
    }
    automation = {
      terraform_mode = var.terraform_mode
      automation_enabled = var.enable_automation
      update_schedule = var.update_schedule
      notifications_configured = var.notification_email != ""
    }
  }
}