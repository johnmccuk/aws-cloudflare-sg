# Terraform Cloud Integration Example
# This example demonstrates using the Cloudflare AWS Security Group module with Terraform Cloud

terraform {
  required_version = ">= 1.5.0"
  
  # Terraform Cloud configuration
  cloud {
    organization = var.terraform_organization
    
    workspaces {
      name = var.terraform_workspace_name
    }
  }

  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
    http = {
      source  = "hashicorp/http"
      version = "~> 3.0"
    }
    archive = {
      source  = "hashicorp/archive"
      version = "~> 2.0"
    }
  }
}

# Configure AWS Provider
provider "aws" {
  region = var.aws_region

  default_tags {
    tags = {
      ManagedBy           = "Terraform"
      TerraformWorkspace  = var.terraform_workspace_name
      TerraformOrg        = var.terraform_organization
      Environment         = var.environment
      Project             = "CloudflareIntegration"
    }
  }
}

# Use the Cloudflare AWS Security Group module
module "cloudflare_security_group" {
  source = "../../"  # Path to the root module

  # Basic Configuration
  vpc_id      = var.vpc_id
  environment = var.environment

  # Network Configuration
  allowed_ports = var.allowed_ports
  protocol      = var.protocol

  # Terraform Cloud Configuration
  terraform_mode         = "cloud"
  terraform_cloud_token  = var.terraform_cloud_token
  terraform_organization = var.terraform_organization
  terraform_workspace    = var.terraform_workspace_id

  # Automation Configuration
  enable_automation = var.enable_automation
  update_schedule   = var.update_schedule

  # Monitoring Configuration
  notification_email = var.notification_email

  # Tagging
  tags = var.tags
}

# Additional security group for internal communication (example)
resource "aws_security_group" "internal_communication" {
  name_prefix = "internal-${var.environment}-"
  description = "Internal communication between services"
  vpc_id      = var.vpc_id

  # Allow communication from Cloudflare security group
  ingress {
    description     = "HTTP from Cloudflare security group"
    from_port       = 80
    to_port         = 80
    protocol        = "tcp"
    security_groups = [module.cloudflare_security_group.security_group_id]
  }

  ingress {
    description     = "HTTPS from Cloudflare security group"
    from_port       = 443
    to_port         = 443
    protocol        = "tcp"
    security_groups = [module.cloudflare_security_group.security_group_id]
  }

  # Allow internal VPC communication
  ingress {
    description = "Internal VPC communication"
    from_port   = 0
    to_port     = 65535
    protocol    = "tcp"
    cidr_blocks = [data.aws_vpc.target.cidr_block]
  }

  egress {
    description      = "All outbound traffic"
    from_port        = 0
    to_port          = 0
    protocol         = "-1"
    cidr_blocks      = ["0.0.0.0/0"]
    ipv6_cidr_blocks = ["::/0"]
  }

  tags = merge(var.tags, {
    Name        = "internal-communication-${var.environment}"
    Description = "Internal communication security group"
  })

  lifecycle {
    create_before_destroy = true
  }
}

# Data source for VPC information
data "aws_vpc" "target" {
  id = var.vpc_id
}

# Example Application Load Balancer using the security groups
resource "aws_lb" "example" {
  count              = var.create_example_alb ? 1 : 0
  name               = "cloudflare-example-${var.environment}"
  internal           = false
  load_balancer_type = "application"
  security_groups    = [
    module.cloudflare_security_group.security_group_id,
    aws_security_group.internal_communication.id
  ]
  subnets = var.public_subnet_ids

  enable_deletion_protection = var.environment == "production"

  tags = merge(var.tags, {
    Name        = "cloudflare-example-${var.environment}"
    Description = "Example ALB using Cloudflare security group"
  })
}

# Example target group for the ALB
resource "aws_lb_target_group" "example" {
  count    = var.create_example_alb ? 1 : 0
  name     = "cf-example-${var.environment}"
  port     = 80
  protocol = "HTTP"
  vpc_id   = var.vpc_id

  health_check {
    enabled             = true
    healthy_threshold   = 2
    interval            = 30
    matcher             = "200"
    path                = "/health"
    port                = "traffic-port"
    protocol            = "HTTP"
    timeout             = 5
    unhealthy_threshold = 2
  }

  tags = merge(var.tags, {
    Name        = "cloudflare-example-tg-${var.environment}"
    Description = "Example target group for Cloudflare integration"
  })
}

# Example listener for the ALB
resource "aws_lb_listener" "example" {
  count             = var.create_example_alb ? 1 : 0
  load_balancer_arn = aws_lb.example[0].arn
  port              = "443"
  protocol          = "HTTPS"
  ssl_policy        = "ELBSecurityPolicy-TLS-1-2-2017-01"
  certificate_arn   = var.ssl_certificate_arn

  default_action {
    type             = "forward"
    target_group_arn = aws_lb_target_group.example[0].arn
  }

  tags = merge(var.tags, {
    Name        = "cloudflare-example-listener-${var.environment}"
    Description = "Example HTTPS listener for Cloudflare integration"
  })
}

# CloudWatch Log Group for application logs (example)
resource "aws_cloudwatch_log_group" "application_logs" {
  name              = "/aws/application/cloudflare-example-${var.environment}"
  retention_in_days = var.log_retention_days

  tags = merge(var.tags, {
    Name        = "cloudflare-example-logs-${var.environment}"
    Description = "Application logs for Cloudflare integration example"
  })
}

# Custom CloudWatch metric filter for monitoring
resource "aws_cloudwatch_log_metric_filter" "error_count" {
  name           = "cloudflare-example-errors-${var.environment}"
  log_group_name = aws_cloudwatch_log_group.application_logs.name
  pattern        = "[timestamp, request_id, ERROR, ...]"

  metric_transformation {
    name      = "ErrorCount"
    namespace = "CloudflareExample"
    value     = "1"
    
    default_value = 0
  }
}

# CloudWatch alarm for application errors
resource "aws_cloudwatch_metric_alarm" "application_errors" {
  count               = var.notification_email != "" ? 1 : 0
  alarm_name          = "cloudflare-example-errors-${var.environment}"
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = "2"
  metric_name         = "ErrorCount"
  namespace           = "CloudflareExample"
  period              = "300"
  statistic           = "Sum"
  threshold           = "5"
  alarm_description   = "This metric monitors application errors"
  alarm_actions       = [module.cloudflare_security_group.sns_topic_arn]
  ok_actions          = [module.cloudflare_security_group.sns_topic_arn]
  treat_missing_data  = "notBreaching"

  tags = merge(var.tags, {
    Name        = "cloudflare-example-errors-${var.environment}"
    Description = "CloudWatch alarm for application errors"
  })
}