# Validation checks for configuration requirements
# This file contains validation logic for different deployment scenarios

# Validation for Terraform Cloud mode requirements
locals {
  # Check if Terraform Cloud mode is properly configured
  terraform_cloud_valid = var.terraform_mode == "cloud" ? (
    var.terraform_cloud_token != "" &&
    var.terraform_workspace != "" &&
    var.terraform_organization != ""
  ) : true

  # Check if direct mode is properly configured
  terraform_direct_valid = var.terraform_mode == "direct" ? (
    var.terraform_config_s3_bucket != "" &&
    var.terraform_config_s3_key != ""
  ) : true

  # Validate notification configuration
  notification_valid = var.notification_email != "" ? (
    can(regex("^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\\.[a-zA-Z]{2,}$", var.notification_email))
  ) : true

  # Check for conflicting automation settings
  automation_config_valid = var.enable_automation ? (
    var.update_schedule != "" &&
    can(regex("^(rate\\(.*\\)|cron\\(.*\\))$", var.update_schedule))
  ) : true

  # Validate port and protocol combinations
  port_protocol_valid = var.protocol == "icmp" ? length(var.allowed_ports) == 0 : length(var.allowed_ports) > 0

  # Check for reasonable update schedule (not too frequent)
  schedule_reasonable = var.enable_automation ? (
    # Prevent schedules more frequent than every 15 minutes
    !can(regex("rate\\([1-9] minute[s]?\\)|rate\\(1[0-4] minute[s]?\\)", var.update_schedule))
  ) : true
}

# Validation checks using check blocks (Terraform 1.5+)
check "terraform_cloud_configuration" {
  assert {
    condition = local.terraform_cloud_valid
    error_message = "When terraform_mode is 'cloud', you must provide terraform_cloud_token, terraform_workspace, and terraform_organization."
  }
}

check "terraform_direct_configuration" {
  assert {
    condition = local.terraform_direct_valid
    error_message = "When terraform_mode is 'direct', you must provide terraform_config_s3_bucket and terraform_config_s3_key."
  }
}

check "notification_configuration" {
  assert {
    condition = local.notification_valid
    error_message = "If notification_email is provided, it must be a valid email address format."
  }
}

check "automation_configuration" {
  assert {
    condition = local.automation_config_valid
    error_message = "When enable_automation is true, update_schedule must be a valid EventBridge schedule expression."
  }
}

check "port_protocol_compatibility" {
  assert {
    condition = local.port_protocol_valid
    error_message = "When protocol is 'icmp', allowed_ports should be empty. For tcp/udp protocols, at least one port must be specified."
  }
}

check "reasonable_update_schedule" {
  assert {
    condition = local.schedule_reasonable
    error_message = "Update schedule should not be more frequent than every 15 minutes to avoid excessive API calls and costs."
  }
}

# Pre-deployment validation data sources
data "aws_vpc" "target" {
  id = var.vpc_id
}

# Validate VPC exists and is available
check "vpc_exists_and_available" {
  assert {
    condition = data.aws_vpc.target.state == "available"
    error_message = "The specified VPC (${var.vpc_id}) must exist and be in 'available' state."
  }
}

# Check AWS region supports required services
data "aws_region" "current" {}

locals {
  # List of AWS regions that support all required services
  supported_regions = [
    "us-east-1", "us-east-2", "us-west-1", "us-west-2",
    "eu-west-1", "eu-west-2", "eu-west-3", "eu-central-1",
    "ap-southeast-1", "ap-southeast-2", "ap-northeast-1",
    "ca-central-1", "sa-east-1"
  ]
  
  region_supported = contains(local.supported_regions, data.aws_region.current.name)
}

check "aws_region_support" {
  assert {
    condition = local.region_supported
    error_message = "The current AWS region (${data.aws_region.current.name}) may not support all required services. Supported regions: ${join(", ", local.supported_regions)}"
  }
}

# Validate AWS credentials have required permissions
data "aws_caller_identity" "current" {}

# Check if we can access required AWS services
data "aws_iam_policy_document" "required_permissions" {
  statement {
    effect = "Allow"
    actions = [
      "ec2:DescribeVpcs",
      "ec2:DescribeSecurityGroups",
      "ec2:CreateSecurityGroup",
      "ec2:AuthorizeSecurityGroupIngress",
      "ec2:RevokeSecurityGroupIngress",
      "lambda:CreateFunction",
      "lambda:UpdateFunctionCode",
      "lambda:UpdateFunctionConfiguration",
      "iam:CreateRole",
      "iam:AttachRolePolicy",
      "iam:PutRolePolicy",
      "events:PutRule",
      "events:PutTargets",
      "logs:CreateLogGroup",
      "cloudwatch:PutMetricAlarm",
      "sns:CreateTopic",
      "sns:Subscribe"
    ]
    resources = ["*"]
  }
}

# Validate S3 bucket access for Terraform state (if specified)
data "aws_s3_bucket" "terraform_state" {
  count  = var.terraform_state_s3_bucket != "" ? 1 : 0
  bucket = var.terraform_state_s3_bucket
}

check "terraform_state_bucket_access" {
  assert {
    condition = var.terraform_state_s3_bucket == "" || length(data.aws_s3_bucket.terraform_state) > 0
    error_message = "If terraform_state_s3_bucket is specified, the bucket must exist and be accessible."
  }
}

# Validate S3 bucket access for Terraform config (if specified)
data "aws_s3_bucket" "terraform_config" {
  count  = var.terraform_config_s3_bucket != "" ? 1 : 0
  bucket = var.terraform_config_s3_bucket
}

check "terraform_config_bucket_access" {
  assert {
    condition = var.terraform_config_s3_bucket == "" || length(data.aws_s3_bucket.terraform_config) > 0
    error_message = "If terraform_config_s3_bucket is specified, the bucket must exist and be accessible."
  }
}

# Output validation results for debugging
output "validation_results" {
  description = "Results of pre-deployment validation checks"
  value = {
    terraform_cloud_valid    = local.terraform_cloud_valid
    terraform_direct_valid   = local.terraform_direct_valid
    notification_valid       = local.notification_valid
    automation_config_valid  = local.automation_config_valid
    port_protocol_valid      = local.port_protocol_valid
    schedule_reasonable      = local.schedule_reasonable
    region_supported         = local.region_supported
    vpc_state               = data.aws_vpc.target.state
    aws_account_id          = data.aws_caller_identity.current.account_id
    aws_region              = data.aws_region.current.name
  }
}