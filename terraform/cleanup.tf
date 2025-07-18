# Cleanup and destroy functionality for Cloudflare IP security group infrastructure
# This file contains resources and logic for proper cleanup during terraform destroy

# Local values for cleanup operations
locals {
  # Resources that need special cleanup handling
  cleanup_resources = {
    security_groups = [
      aws_security_group.cloudflare_whitelist.id
    ]
    lambda_functions = concat(
      [aws_lambda_function.cloudflare_updater.function_name],
      var.enable_automation ? [aws_lambda_function.cleanup_function[0].function_name] : []
    )
    cloudwatch_log_groups = concat(
      [aws_cloudwatch_log_group.lambda_logs.name],
      var.enable_automation ? [aws_cloudwatch_log_group.cleanup_lambda_logs[0].name] : []
    )
    sns_topics = var.notification_email != "" ? [
      aws_sns_topic.notifications[0].arn
    ] : []
    eventbridge_rules = [
      aws_cloudwatch_event_rule.cloudflare_update_schedule.name
    ]
    cloudwatch_alarms = var.notification_email != "" ? [
      aws_cloudwatch_metric_alarm.lambda_error_alarm[0].alarm_name,
      aws_cloudwatch_metric_alarm.lambda_duration_alarm[0].alarm_name,
      aws_cloudwatch_metric_alarm.lambda_throttle_alarm[0].alarm_name,
      aws_cloudwatch_metric_alarm.lambda_success_alarm[0].alarm_name
    ] : []
    cloudwatch_dashboards = var.notification_email != "" ? [
      aws_cloudwatch_dashboard.cloudflare_updater[0].dashboard_name
    ] : []
    iam_roles = concat(
      [aws_iam_role.lambda_execution_role.name],
      var.enable_automation ? [aws_iam_role.cleanup_lambda_role[0].name] : []
    )
  }
  
  # Cleanup tags to identify resources for cleanup
  cleanup_tags = merge(
    local.common_tags,
    {
      CleanupGroup     = "cloudflare-ip-updater-${var.environment}"
      DestroyOrder     = "managed"
      ResourceType     = "automation"
      CleanupRequired  = "true"
    }
  )
}

# Null resource for pre-destroy cleanup operations
resource "null_resource" "pre_destroy_cleanup" {
  # This resource runs cleanup operations before destroying main resources
  triggers = {
    security_group_id = aws_security_group.cloudflare_whitelist.id
    lambda_function_name = aws_lambda_function.cloudflare_updater.function_name
    environment = var.environment
  }

  # Pre-destroy provisioner to clean up Lambda function state
  provisioner "local-exec" {
    when    = destroy
    command = <<-EOT
      echo "Starting pre-destroy cleanup for Cloudflare IP updater infrastructure..."
      echo "Environment: ${self.triggers.environment}"
      echo "Security Group ID: ${self.triggers.security_group_id}"
      echo "Lambda Function: ${self.triggers.lambda_function_name}"
      
      # Disable EventBridge rule to prevent new executions during cleanup
      aws events disable-rule --name "cloudflare-ip-update-${self.triggers.environment}" --region ${data.aws_region.current.name} || echo "EventBridge rule already disabled or doesn't exist"
      
      # Wait for any running Lambda executions to complete
      echo "Waiting for Lambda executions to complete..."
      sleep 30
      
      echo "Pre-destroy cleanup completed"
    EOT
    
    on_failure = continue
  }
}

# Lambda function for cleanup operations
resource "aws_lambda_function" "cleanup_function" {
  count = var.enable_automation ? 1 : 0
  
  filename         = data.archive_file.cleanup_lambda_zip[0].output_path
  function_name    = "cloudflare-ip-cleanup-${var.environment}"
  role            = aws_iam_role.cleanup_lambda_role[0].arn
  handler         = "cleanup_function.lambda_handler"
  runtime         = "python3.11"
  timeout         = 300
  memory_size     = 256
  source_code_hash = data.archive_file.cleanup_lambda_zip[0].output_base64sha256

  environment {
    variables = {
      ENVIRONMENT           = var.environment
      SECURITY_GROUP_ID     = aws_security_group.cloudflare_whitelist.id
      MAIN_LAMBDA_FUNCTION  = aws_lambda_function.cloudflare_updater.function_name
      LOG_GROUP_NAME        = aws_cloudwatch_log_group.lambda_logs.name
      SNS_TOPIC_ARN         = var.notification_email != "" ? aws_sns_topic.notifications[0].arn : ""
      EVENTBRIDGE_RULE_NAME = aws_cloudwatch_event_rule.cloudflare_update_schedule.name
      CLEANUP_MODE          = "graceful"
      # CloudWatch resources for cleanup
      CLOUDWATCH_DASHBOARD_NAME = var.notification_email != "" ? aws_cloudwatch_dashboard.cloudflare_updater[0].dashboard_name : ""
      CLOUDWATCH_ALARM_NAMES = var.notification_email != "" ? join(",", [
        aws_cloudwatch_metric_alarm.lambda_error_alarm[0].alarm_name,
        aws_cloudwatch_metric_alarm.lambda_duration_alarm[0].alarm_name,
        aws_cloudwatch_metric_alarm.lambda_throttle_alarm[0].alarm_name,
        aws_cloudwatch_metric_alarm.lambda_success_alarm[0].alarm_name
      ]) : ""
      # IAM resources for cleanup
      MAIN_IAM_ROLE_NAME = aws_iam_role.lambda_execution_role.name
      # Cleanup tags for resource identification
      CLEANUP_GROUP_TAG = "cloudflare-ip-updater-${var.environment}"
    }
  }

  depends_on = [
    aws_iam_role_policy.cleanup_lambda_policy,
    aws_cloudwatch_log_group.cleanup_lambda_logs
  ]

  tags = merge(
    local.cleanup_tags,
    {
      Name        = "cloudflare-ip-cleanup-${var.environment}"
      Description = "Lambda function for cleanup operations during destroy"
      Purpose     = "Cleanup"
    }
  )
}

# Create ZIP file for cleanup Lambda function
data "archive_file" "cleanup_lambda_zip" {
  count = var.enable_automation ? 1 : 0
  
  type        = "zip"
  source_file = "${path.module}/cleanup_function.py"
  output_path = "${path.module}/cleanup_function.zip"
}

# IAM role for cleanup Lambda function
resource "aws_iam_role" "cleanup_lambda_role" {
  count = var.enable_automation ? 1 : 0
  
  name_prefix = "cloudflare-cleanup-lambda-"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action = "sts:AssumeRole"
        Effect = "Allow"
        Principal = {
          Service = "lambda.amazonaws.com"
        }
      }
    ]
  })

  tags = local.cleanup_tags
}

# IAM policy for cleanup Lambda function
resource "aws_iam_role_policy" "cleanup_lambda_policy" {
  count = var.enable_automation ? 1 : 0
  
  name_prefix = "cloudflare-cleanup-policy-"
  role        = aws_iam_role.cleanup_lambda_role[0].id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Action = [
          "logs:CreateLogGroup",
          "logs:CreateLogStream",
          "logs:PutLogEvents",
          "logs:DescribeLogGroups",
          "logs:DescribeLogStreams"
        ]
        Resource = "arn:aws:logs:*:*:*"
      },
      {
        Effect = "Allow"
        Action = [
          "ec2:DescribeSecurityGroups",
          "ec2:DescribeSecurityGroupRules",
          "ec2:RevokeSecurityGroupIngress",
          "ec2:RevokeSecurityGroupEgress"
        ]
        Resource = "*"
      },
      {
        Effect = "Allow"
        Action = [
          "lambda:GetFunction",
          "lambda:ListEventSourceMappings",
          "lambda:DeleteEventSourceMapping",
          "lambda:UpdateFunctionConfiguration"
        ]
        Resource = "*"
      },
      {
        Effect = "Allow"
        Action = [
          "events:DescribeRule",
          "events:DisableRule",
          "events:ListTargetsByRule",
          "events:RemoveTargets"
        ]
        Resource = "*"
      },
      {
        Effect = "Allow"
        Action = [
          "sns:GetTopicAttributes",
          "sns:ListSubscriptionsByTopic",
          "sns:Unsubscribe"
        ]
        Resource = "*"
      },
      {
        Effect = "Allow"
        Action = [
          "cloudwatch:DescribeAlarms",
          "cloudwatch:DeleteAlarms",
          "cloudwatch:DescribeDashboards"
        ]
        Resource = "*"
      }
    ]
  })
}

# CloudWatch Log Group for cleanup Lambda
resource "aws_cloudwatch_log_group" "cleanup_lambda_logs" {
  count = var.enable_automation ? 1 : 0
  
  name              = "/aws/lambda/cloudflare-ip-cleanup-${var.environment}"
  retention_in_days = 7  # Shorter retention for cleanup logs
  
  tags = merge(
    local.cleanup_tags,
    {
      Name        = "cloudflare-ip-cleanup-logs-${var.environment}"
      Description = "CloudWatch log group for cleanup Lambda function"
    }
  )
}

# Lambda permission for manual cleanup invocation
resource "aws_lambda_permission" "cleanup_manual_invoke" {
  count = var.enable_automation ? 1 : 0
  
  statement_id  = "AllowManualCleanupInvocation"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.cleanup_function[0].function_name
  principal     = "arn:aws:iam::${data.aws_caller_identity.current.account_id}:root"
}

# Data source for current AWS account ID
data "aws_caller_identity" "current" {}

# Null resource for post-destroy verification
resource "null_resource" "post_destroy_verification" {
  depends_on = [
    null_resource.pre_destroy_cleanup
  ]

  # Post-destroy provisioner to verify cleanup
  provisioner "local-exec" {
    when    = destroy
    command = <<-EOT
      echo "Starting post-destroy verification..."
      
      # Verify security group is deleted (this will fail if dependencies exist)
      echo "Verifying security group cleanup..."
      
      # Check for any remaining CloudWatch alarms
      echo "Checking for remaining CloudWatch alarms..."
      aws cloudwatch describe-alarms --alarm-name-prefix "cloudflare-ip" --region ${data.aws_region.current.name} || echo "No remaining alarms found"
      
      # Check for any remaining log groups
      echo "Checking for remaining log groups..."
      aws logs describe-log-groups --log-group-name-prefix "/aws/lambda/cloudflare-ip" --region ${data.aws_region.current.name} || echo "No remaining log groups found"
      
      echo "Post-destroy verification completed"
    EOT
    
    on_failure = continue
  }
}

# Output cleanup information
output "cleanup_information" {
  description = "Information about cleanup resources and procedures"
  value = {
    cleanup_lambda_function = var.enable_automation ? aws_lambda_function.cleanup_function[0].function_name : null
    cleanup_resources = local.cleanup_resources
    cleanup_tags = local.cleanup_tags
    pre_destroy_cleanup_enabled = true
    post_destroy_verification_enabled = true
  }
}

# Output destroy order information
output "destroy_order_guide" {
  description = "Guide for proper resource destruction order"
  value = {
    step_1 = "Disable EventBridge rule to stop new Lambda executions"
    step_2 = "Wait for running Lambda executions to complete"
    step_3 = "Remove EventBridge targets and rules"
    step_4 = "Delete CloudWatch alarms and dashboards"
    step_5 = "Delete SNS subscriptions and topics"
    step_6 = "Delete Lambda functions and associated resources"
    step_7 = "Delete security group rules and security groups"
    step_8 = "Delete IAM roles and policies"
    step_9 = "Delete CloudWatch log groups"
    note = "Terraform will handle most of this automatically with proper depends_on relationships"
  }
}

# Enhanced destroy provisioner for comprehensive cleanup
resource "null_resource" "enhanced_destroy_cleanup" {
  # This resource ensures comprehensive cleanup during destroy operations
  triggers = {
    environment = var.environment
    security_group_id = aws_security_group.cloudflare_whitelist.id
    lambda_function_name = aws_lambda_function.cloudflare_updater.function_name
    cleanup_group_tag = "cloudflare-ip-updater-${var.environment}"
    # Include all major resource identifiers for cleanup tracking
    eventbridge_rule_name = aws_cloudwatch_event_rule.cloudflare_update_schedule.name
    sns_topic_arn = var.notification_email != "" ? aws_sns_topic.notifications[0].arn : ""
    log_group_name = aws_cloudwatch_log_group.lambda_logs.name
    iam_role_name = aws_iam_role.lambda_execution_role.name
    # CloudWatch resources
    cloudwatch_dashboard_name = var.notification_email != "" ? aws_cloudwatch_dashboard.cloudflare_updater[0].dashboard_name : ""
    # All CloudWatch alarms for comprehensive cleanup
    all_alarm_names = join(",", compact([
      var.notification_email != "" ? aws_cloudwatch_metric_alarm.lambda_error_alarm[0].alarm_name : "",
      var.notification_email != "" ? aws_cloudwatch_metric_alarm.lambda_duration_alarm[0].alarm_name : "",
      var.notification_email != "" ? aws_cloudwatch_metric_alarm.lambda_throttle_alarm[0].alarm_name : "",
      var.notification_email != "" ? aws_cloudwatch_metric_alarm.lambda_success_alarm[0].alarm_name : ""
    ]))
    # All log groups for cleanup
    all_log_groups = join(",", compact([
      aws_cloudwatch_log_group.lambda_logs.name,
      var.enable_automation ? aws_cloudwatch_log_group.cleanup_lambda_logs[0].name : ""
    ]))
    # All Lambda functions for cleanup
    all_lambda_functions = join(",", compact([
      aws_lambda_function.cloudflare_updater.function_name,
      var.enable_automation ? aws_lambda_function.cleanup_function[0].function_name : ""
    ]))
    # All IAM roles for cleanup
    all_iam_roles = join(",", compact([
      aws_iam_role.lambda_execution_role.name,
      var.enable_automation ? aws_iam_role.cleanup_lambda_role[0].name : ""
    ]))
  }

  # Enhanced pre-destroy provisioner with comprehensive cleanup using dedicated script
  provisioner "local-exec" {
    when    = destroy
    command = <<-EOT
      # Execute comprehensive cleanup script
      ${path.module}/scripts/cleanup.sh \
        "${self.triggers.environment}" \
        "${self.triggers.security_group_id}" \
        "${self.triggers.lambda_function_name}" \
        "${self.triggers.eventbridge_rule_name}" \
        "${self.triggers.sns_topic_arn}" \
        "${self.triggers.log_group_name}" \
        "${self.triggers.cleanup_group_tag}" \
        "${data.aws_region.current.name}"
    EOT
    
    on_failure = continue
  }

  depends_on = [
    aws_security_group.cloudflare_whitelist,
    aws_lambda_function.cloudflare_updater,
    aws_cloudwatch_event_rule.cloudflare_update_schedule
  ]
}

# Resource for tracking destroy operations
resource "null_resource" "destroy_tracking" {
  # This resource helps track destroy operations for audit purposes
  triggers = {
    destroy_timestamp = timestamp()
    environment = var.environment
    resources_to_destroy = jsonencode({
      security_group_id = aws_security_group.cloudflare_whitelist.id
      lambda_function_name = aws_lambda_function.cloudflare_updater.function_name
      eventbridge_rule_name = aws_cloudwatch_event_rule.cloudflare_update_schedule.name
      iam_role_name = aws_iam_role.lambda_execution_role.name
      log_group_name = aws_cloudwatch_log_group.lambda_logs.name
      sns_topic_arn = var.notification_email != "" ? aws_sns_topic.notifications[0].arn : ""
      cleanup_group_tag = "cloudflare-ip-updater-${var.environment}"
    })
  }

  # Post-destroy verification
  provisioner "local-exec" {
    when    = destroy
    command = <<-EOT
      echo "=== POST-DESTROY VERIFICATION START ==="
      echo "Environment: ${self.triggers.environment}"
      echo "Destroy timestamp: ${self.triggers.destroy_timestamp}"
      
      # Parse the resources that were supposed to be destroyed
      echo "Resources that were destroyed:"
      echo '${self.triggers.resources_to_destroy}' | jq '.' || echo "Failed to parse resource list"
      
      # Verify key resources are gone
      echo "Verifying resource cleanup..."
      
      # Check if security group still exists
      SG_ID=$(echo '${self.triggers.resources_to_destroy}' | jq -r '.security_group_id')
      if aws ec2 describe-security-groups --group-ids "$SG_ID" --region ${data.aws_region.current.name} >/dev/null 2>&1; then
        echo "WARNING: Security group $SG_ID still exists"
      else
        echo "SUCCESS: Security group $SG_ID has been deleted"
      fi
      
      # Check if Lambda function still exists
      LAMBDA_NAME=$(echo '${self.triggers.resources_to_destroy}' | jq -r '.lambda_function_name')
      if aws lambda get-function --function-name "$LAMBDA_NAME" --region ${data.aws_region.current.name} >/dev/null 2>&1; then
        echo "WARNING: Lambda function $LAMBDA_NAME still exists"
      else
        echo "SUCCESS: Lambda function $LAMBDA_NAME has been deleted"
      fi
      
      # Check if EventBridge rule still exists
      RULE_NAME=$(echo '${self.triggers.resources_to_destroy}' | jq -r '.eventbridge_rule_name')
      if aws events describe-rule --name "$RULE_NAME" --region ${data.aws_region.current.name} >/dev/null 2>&1; then
        echo "WARNING: EventBridge rule $RULE_NAME still exists"
      else
        echo "SUCCESS: EventBridge rule $RULE_NAME has been deleted"
      fi
      
      echo "=== POST-DESTROY VERIFICATION COMPLETED ==="
    EOT
    
    on_failure = continue
  }
}