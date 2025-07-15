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

# AWS Security Group for Cloudflare IP whitelist
resource "aws_security_group" "cloudflare_whitelist" {
  name_prefix = "${local.security_group_name}-"
  description = "Security group allowing traffic from Cloudflare IP ranges"
  vpc_id      = var.vpc_id

  # Dynamic ingress rules for each Cloudflare IP range and port combination
  dynamic "ingress" {
    for_each = setproduct(local.all_cloudflare_ips, var.allowed_ports)
    content {
      description      = "Cloudflare IP range ${ingress.value[0]} - Port ${ingress.value[1]}"
      from_port        = ingress.value[1]
      to_port          = ingress.value[1]
      protocol         = var.protocol
      cidr_blocks      = can(regex(":", ingress.value[0])) ? [] : [ingress.value[0]]
      ipv6_cidr_blocks = can(regex(":", ingress.value[0])) ? [ingress.value[0]] : []
    }
  }

  # Explicit egress rules (default allows all outbound)
  egress {
    description      = "All outbound traffic"
    from_port        = 0
    to_port          = 0
    protocol         = "-1"
    cidr_blocks      = ["0.0.0.0/0"]
    ipv6_cidr_blocks = ["::/0"]
  }

  tags = merge(
    local.common_tags,
    {
      Name        = local.security_group_name
      Description = "Cloudflare IP whitelist security group"
    }
  )

  lifecycle {
    create_before_destroy = true
  }
}

# IAM role for Lambda function
resource "aws_iam_role" "lambda_execution_role" {
  name_prefix = "cloudflare-updater-lambda-"

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

  tags = local.common_tags
}

# IAM policy for Lambda function
resource "aws_iam_role_policy" "lambda_policy" {
  name_prefix = "cloudflare-updater-policy-"
  role        = aws_iam_role.lambda_execution_role.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Action = [
          "logs:CreateLogGroup",
          "logs:CreateLogStream",
          "logs:PutLogEvents"
        ]
        Resource = "arn:aws:logs:*:*:*"
      },
      {
        Effect = "Allow"
        Action = [
          "ec2:DescribeSecurityGroups",
          "ec2:AuthorizeSecurityGroupIngress",
          "ec2:RevokeSecurityGroupIngress"
        ]
        Resource = "*"
      },
      {
        Effect = "Allow"
        Action = [
          "sns:Publish"
        ]
        Resource = var.notification_email != "" ? aws_sns_topic.notifications[0].arn : "*"
      },
      {
        Effect = "Allow"
        Action = [
          "s3:GetObject",
          "s3:PutObject",
          "s3:DeleteObject"
        ]
        Resource = [
          var.terraform_config_s3_bucket != "" ? "arn:aws:s3:::${var.terraform_config_s3_bucket}/*" : "arn:aws:s3:::*/*",
          var.terraform_state_s3_bucket != "" ? "arn:aws:s3:::${var.terraform_state_s3_bucket}/*" : "arn:aws:s3:::*/*"
        ]
      },
      {
        Effect = "Allow"
        Action = [
          "s3:ListBucket"
        ]
        Resource = [
          var.terraform_config_s3_bucket != "" ? "arn:aws:s3:::${var.terraform_config_s3_bucket}" : "arn:aws:s3:::*",
          var.terraform_state_s3_bucket != "" ? "arn:aws:s3:::${var.terraform_state_s3_bucket}" : "arn:aws:s3:::*"
        ]
      },
      {
        Effect = "Allow"
        Action = [
          "dynamodb:GetItem",
          "dynamodb:PutItem",
          "dynamodb:DeleteItem"
        ]
        Resource = "arn:aws:dynamodb:*:*:table/terraform-state-lock*"
      },
      {
        Effect = "Allow"
        Action = [
          "events:PutEvents"
        ]
        Resource = "*"
      }
    ]
  })
}

# CloudWatch Log Group for Lambda
resource "aws_cloudwatch_log_group" "lambda_logs" {
  name              = "/aws/lambda/cloudflare-ip-updater-${var.environment}"
  retention_in_days = 14
  tags              = local.common_tags
}

# SNS Topic for notifications (only if email is provided)
resource "aws_sns_topic" "notifications" {
  count = var.notification_email != "" ? 1 : 0
  name  = "cloudflare-ip-updates-${var.environment}"
  tags  = local.common_tags
}

# SNS Topic Subscription (only if email is provided)
resource "aws_sns_topic_subscription" "email_notification" {
  count     = var.notification_email != "" ? 1 : 0
  topic_arn = aws_sns_topic.notifications[0].arn
  protocol  = "email"
  endpoint  = var.notification_email
}

# Create ZIP file for Lambda function
data "archive_file" "lambda_zip" {
  type        = "zip"
  source_file = "${path.module}/lambda_function.py"
  output_path = "${path.module}/lambda_function.zip"
}

# Lambda function for automated updates
resource "aws_lambda_function" "cloudflare_updater" {
  filename         = data.archive_file.lambda_zip.output_path
  function_name    = "cloudflare-ip-updater-${var.environment}"
  role            = aws_iam_role.lambda_execution_role.arn
  handler         = "lambda_function.lambda_handler"
  runtime         = "python3.11"
  timeout         = 300
  memory_size     = 256
  source_code_hash = data.archive_file.lambda_zip.output_base64sha256

  environment {
    variables = {
      SECURITY_GROUP_ID           = aws_security_group.cloudflare_whitelist.id
      SNS_TOPIC_ARN              = var.notification_email != "" ? aws_sns_topic.notifications[0].arn : ""
      MAX_RETRIES                = "3"
      RETRY_DELAY                = "5"
      TERRAFORM_MODE             = var.terraform_mode
      TERRAFORM_CLOUD_TOKEN      = var.terraform_cloud_token
      TERRAFORM_WORKSPACE        = var.terraform_workspace
      TERRAFORM_ORGANIZATION     = var.terraform_organization
      TERRAFORM_CONFIG_S3_BUCKET = var.terraform_config_s3_bucket
      TERRAFORM_CONFIG_S3_KEY    = var.terraform_config_s3_key
      TERRAFORM_STATE_S3_BUCKET  = var.terraform_state_s3_bucket
      TERRAFORM_STATE_S3_KEY     = var.terraform_state_s3_key
    }
  }

  depends_on = [
    aws_iam_role_policy.lambda_policy,
    aws_cloudwatch_log_group.lambda_logs
  ]

  tags = merge(
    local.common_tags,
    {
      Name        = "cloudflare-ip-updater-${var.environment}"
      Description = "Lambda function to update Cloudflare IP ranges in security group"
    }
  )
}

# EventBridge rule for scheduled Lambda execution
resource "aws_cloudwatch_event_rule" "cloudflare_update_schedule" {
  name                = "cloudflare-ip-update-${var.environment}"
  description         = "Scheduled trigger for Cloudflare IP range updates"
  schedule_expression = var.update_schedule
  state               = var.enable_automation ? "ENABLED" : "DISABLED"

  tags = merge(
    local.common_tags,
    {
      Name        = "cloudflare-ip-update-${var.environment}"
      Description = "EventBridge rule for automated Cloudflare IP updates"
    }
  )
}

# EventBridge target to invoke Lambda function
resource "aws_cloudwatch_event_target" "lambda_target" {
  rule      = aws_cloudwatch_event_rule.cloudflare_update_schedule.name
  target_id = "CloudflareUpdaterLambdaTarget"
  arn       = aws_lambda_function.cloudflare_updater.arn

  input = jsonencode({
    source      = "eventbridge.scheduled"
    detail_type = "Scheduled Event"
    detail = {
      trigger = "automated_update"
      schedule = var.update_schedule
    }
  })
}

# Lambda permission for EventBridge to invoke the function
resource "aws_lambda_permission" "allow_eventbridge" {
  statement_id  = "AllowExecutionFromEventBridge"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.cloudflare_updater.function_name
  principal     = "events.amazonaws.com"
  source_arn    = aws_cloudwatch_event_rule.cloudflare_update_schedule.arn
}
