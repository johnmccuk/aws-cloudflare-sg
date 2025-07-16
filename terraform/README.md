# Cloudflare AWS Security Group Terraform Module

[![Terraform](https://img.shields.io/badge/terraform-%235835CC.svg?style=for-the-badge&logo=terraform&logoColor=white)](https://www.terraform.io/)
[![AWS](https://img.shields.io/badge/AWS-%23FF9900.svg?style=for-the-badge&logo=amazon-aws&logoColor=white)](https://aws.amazon.com/)

This Terraform module automatically creates and maintains an AWS Security Group with ingress rules that allow traffic from Cloudflare's IP address ranges. The module includes automated updates via AWS Lambda and EventBridge to keep the security group current with Cloudflare's changing IP ranges.

> **Note**: This is a production-ready Terraform module that can be used as a reusable component in your infrastructure. It follows Terraform best practices and includes comprehensive monitoring and automation capabilities.

## Features

- **Automatic IP Retrieval**: Fetches current Cloudflare IPv4 and IPv6 ranges from official APIs
- **Dynamic Security Group Rules**: Creates ingress rules for each Cloudflare IP range
- **Automated Updates**: Lambda function triggered by EventBridge to update IP ranges on schedule
- **Comprehensive Monitoring**: CloudWatch alarms, logs, and dashboard for monitoring automation health
- **Flexible Configuration**: Configurable ports, protocols, and update schedules
- **Notification Support**: SNS notifications for update status and errors
- **Multiple Terraform Modes**: Support for both direct execution and Terraform Cloud

## Architecture

```
┌─────────────────┐    ┌──────────────────┐    ┌─────────────────┐
│   Cloudflare    │    │   EventBridge    │    │  Lambda Function│
│   IP APIs       │◄───┤   Schedule       │───►│   (Updater)     │
└─────────────────┘    └──────────────────┘    └─────────────────┘
                                                        │
┌─────────────────┐    ┌──────────────────┐            │
│   CloudWatch    │    │  AWS Security    │◄───────────┘
│   Monitoring    │    │     Group        │
└─────────────────┘    └──────────────────┘
                                │
                       ┌──────────────────┐
                       │   SNS Topic      │
                       │ (Notifications)  │
                       └──────────────────┘
```

## Quick Start

1. **Clone or reference this module in your Terraform configuration**
2. **Set required variables**: `vpc_id` is the only required variable
3. **Apply the configuration**: The module will create a security group with Cloudflare IP ranges
4. **Monitor via CloudWatch**: Check the dashboard and logs for automation status

## Usage

### Module Source Options

```hcl
# Option 1: Local path (if module is in your repository)
module "cloudflare_security_group" {
  source = "./modules/cloudflare-aws-security-group"
  # ... variables
}

# Option 2: Git repository (recommended for reusability)
module "cloudflare_security_group" {
  source = "git::https://github.com/your-org/terraform-aws-cloudflare-security-group.git?ref=v1.0.0"
  # ... variables
}

# Option 3: Terraform Registry (if published)
module "cloudflare_security_group" {
  source  = "your-org/cloudflare-security-group/aws"
  version = "~> 1.0"
  # ... variables
}
```

### Basic Usage

```hcl
module "cloudflare_security_group" {
  source = "git::https://github.com/your-org/terraform-aws-cloudflare-security-group.git"
  
  vpc_id      = "vpc-12345678"
  environment = "production"
}
```

### Advanced Configuration

```hcl
module "cloudflare_security_group" {
  source = "./terraform"
  
  # Required
  vpc_id      = "vpc-12345678"
  environment = "production"
  
  # Security Group Configuration
  allowed_ports = [80, 443, 8080]
  protocol      = "tcp"
  
  # Automation Configuration
  enable_automation = true
  update_schedule   = "cron(0 2 * * ? *)"  # Daily at 2 AM UTC
  
  # Notifications
  notification_email = "devops@company.com"
  
  # Terraform Cloud Configuration (optional)
  terraform_mode         = "cloud"
  terraform_cloud_token  = var.terraform_cloud_token
  terraform_workspace    = "ws-abc123def456"
  terraform_organization = "my-org"
  
  # Additional Tags
  tags = {
    Project     = "web-infrastructure"
    Owner       = "devops-team"
    CostCenter  = "engineering"
  }
}
```

### Direct Terraform Execution Mode

```hcl
module "cloudflare_security_group" {
  source = "./terraform"
  
  vpc_id      = "vpc-12345678"
  environment = "staging"
  
  # Direct execution with S3 backend
  terraform_mode              = "direct"
  terraform_config_s3_bucket  = "my-terraform-configs"
  terraform_config_s3_key     = "cloudflare-sg/terraform.zip"
  terraform_state_s3_bucket   = "my-terraform-state"
  terraform_state_s3_key      = "cloudflare-sg/terraform.tfstate"
}
```

## Requirements

| Name | Version |
|------|---------|
| terraform | >= 1.0 |
| aws | ~> 5.0 |
| http | ~> 3.0 |
| archive | ~> 2.0 |
| null | ~> 3.0 |

## Providers

| Name | Version |
|------|---------|
| aws | ~> 5.0 |
| http | ~> 3.0 |
| archive | ~> 2.0 |

## Resources

| Name | Type |
|------|------|
| aws_security_group.cloudflare_whitelist | resource |
| aws_lambda_function.cloudflare_updater | resource |
| aws_iam_role.lambda_execution_role | resource |
| aws_iam_role_policy.lambda_policy | resource |
| aws_cloudwatch_log_group.lambda_logs | resource |
| aws_cloudwatch_event_rule.cloudflare_update_schedule | resource |
| aws_cloudwatch_event_target.lambda_target | resource |
| aws_lambda_permission.allow_eventbridge | resource |
| aws_sns_topic.notifications | resource |
| aws_sns_topic_subscription.email_notification | resource |
| aws_cloudwatch_metric_alarm.lambda_error_alarm | resource |
| aws_cloudwatch_metric_alarm.lambda_duration_alarm | resource |
| aws_cloudwatch_metric_alarm.lambda_throttle_alarm | resource |
| aws_cloudwatch_metric_alarm.lambda_success_alarm | resource |
| aws_cloudwatch_dashboard.cloudflare_updater | resource |

## Inputs

| Name | Description | Type | Default | Required |
|------|-------------|------|---------|:--------:|
| vpc_id | VPC ID where security group will be created | `string` | n/a | yes |
| environment | Environment name for resource naming and tagging | `string` | `"prod"` | no |
| allowed_ports | List of ports to allow from Cloudflare IPs | `list(number)` | `[443]` | no |
| protocol | Protocol for security group rules | `string` | `"tcp"` | no |
| update_schedule | Cron expression for automated updates | `string` | `"cron(0 2 * * ? *)"` | no |
| enable_automation | Enable automated updates via EventBridge scheduling | `bool` | `true` | no |
| notification_email | Email address for update notifications | `string` | `""` | no |
| tags | Additional tags to apply to resources | `map(string)` | `{}` | no |
| terraform_mode | Terraform execution mode: 'direct' for local execution, 'cloud' for Terraform Cloud | `string` | `"direct"` | no |
| terraform_cloud_token | Terraform Cloud API token (required if terraform_mode is 'cloud') | `string` | `""` | no |
| terraform_workspace | Terraform Cloud workspace ID (required if terraform_mode is 'cloud') | `string` | `""` | no |
| terraform_organization | Terraform Cloud organization name (required if terraform_mode is 'cloud') | `string` | `""` | no |
| terraform_config_s3_bucket | S3 bucket containing Terraform configuration (required if terraform_mode is 'direct') | `string` | `""` | no |
| terraform_config_s3_key | S3 key for Terraform configuration file (required if terraform_mode is 'direct') | `string` | `""` | no |
| terraform_state_s3_bucket | S3 bucket for Terraform state storage (optional for direct mode) | `string` | `""` | no |
| terraform_state_s3_key | S3 key for Terraform state file (optional for direct mode) | `string` | `""` | no |

## Outputs

| Name | Description |
|------|-------------|
| security_group_id | ID of the created Cloudflare whitelist security group |
| security_group_arn | ARN of the created Cloudflare whitelist security group |
| security_group_name | Name of the created Cloudflare whitelist security group |
| cloudflare_ip_count | Number of Cloudflare IP ranges configured in the security group |
| configured_ports | List of ports configured in the security group rules |
| protocol | Protocol configured for the security group rules |
| lambda_function_name | Name of the Lambda function for automated updates |
| lambda_function_arn | ARN of the Lambda function for automated updates |
| sns_topic_arn | ARN of the SNS topic for notifications (if configured) |
| eventbridge_rule_name | Name of the EventBridge rule for scheduled updates |
| eventbridge_rule_arn | ARN of the EventBridge rule for scheduled updates |
| update_schedule | Configured schedule expression for automated updates |
| automation_enabled | Whether automated updates are enabled |
| cloudwatch_log_group_name | Name of the CloudWatch log group for Lambda function |
| cloudwatch_log_group_arn | ARN of the CloudWatch log group for Lambda function |
| cloudwatch_dashboard_url | URL of the CloudWatch dashboard for monitoring (if configured) |

## Configuration Examples

### Production Environment with Full Monitoring

```hcl
module "cloudflare_security_group_prod" {
  source = "./terraform"
  
  vpc_id      = "vpc-prod123456"
  environment = "production"
  
  # Allow HTTP and HTTPS
  allowed_ports = [80, 443]
  protocol      = "tcp"
  
  # Daily updates at 2 AM UTC
  enable_automation = true
  update_schedule   = "cron(0 2 * * ? *)"
  
  # Enable notifications
  notification_email = "alerts@company.com"
  
  # Production tags
  tags = {
    Environment = "production"
    Project     = "web-frontend"
    Owner       = "platform-team"
    Backup      = "required"
  }
}
```

### Development Environment with Terraform Cloud

```hcl
module "cloudflare_security_group_dev" {
  source = "./terraform"
  
  vpc_id      = "vpc-dev789012"
  environment = "development"
  
  # Custom ports for development
  allowed_ports = [80, 443, 8080, 3000]
  
  # More frequent updates for testing
  update_schedule = "cron(0 */6 * * ? *)"  # Every 6 hours
  
  # Terraform Cloud configuration
  terraform_mode         = "cloud"
  terraform_cloud_token  = var.tfc_token
  terraform_workspace    = "ws-dev123abc"
  terraform_organization = "my-company"
  
  tags = {
    Environment = "development"
    AutoDelete  = "true"
  }
}
```

### Staging Environment with Direct Execution

```hcl
module "cloudflare_security_group_staging" {
  source = "./terraform"
  
  vpc_id      = "vpc-staging345"
  environment = "staging"
  
  # Direct execution mode
  terraform_mode              = "direct"
  terraform_config_s3_bucket  = "company-terraform-configs"
  terraform_config_s3_key     = "staging/cloudflare-sg.zip"
  terraform_state_s3_bucket   = "company-terraform-state"
  terraform_state_s3_key      = "staging/cloudflare-sg.tfstate"
  
  # Weekly updates for staging
  update_schedule = "cron(0 2 ? * SUN *)"  # Sundays at 2 AM
  
  notification_email = "staging-alerts@company.com"
}
```

## Monitoring and Alerting

The module creates comprehensive monitoring resources when `notification_email` is provided:

### CloudWatch Alarms

- **Lambda Errors**: Triggers when the updater function encounters errors
- **Lambda Duration**: Alerts when function execution approaches timeout
- **Lambda Throttles**: Monitors for function throttling
- **No Invocations**: Alerts when automation hasn't run for 3 days

### CloudWatch Dashboard

A dashboard is created with widgets showing:
- Lambda function metrics (duration, errors, invocations, throttles)
- Notification counts by type
- IP range update statistics
- Recent activity logs
- Error logs
- Terraform automation logs

### SNS Notifications

Email notifications are sent for:
- Successful IP range updates
- Update failures and errors
- CloudWatch alarm state changes

## Security Considerations

### IAM Permissions

The Lambda function is granted minimal required permissions:
- EC2 permissions for security group management
- CloudWatch permissions for logging and metrics
- SNS permissions for notifications
- S3 permissions for Terraform state/config (if using direct mode)
- DynamoDB permissions for state locking

### Network Security

- Security group rules are created only for specified ports and protocols
- IPv4 and IPv6 CIDR blocks are validated before rule creation
- All outbound traffic is allowed (standard AWS default)

### Secrets Management

- Terraform Cloud tokens are marked as sensitive variables
- AWS credentials should be provided via IAM roles, not hardcoded
- S3 bucket access uses IAM roles rather than access keys

## Troubleshooting

### Common Issues

1. **Cloudflare API Unavailable**
   - Check CloudWatch logs for HTTP errors
   - Verify internet connectivity from Lambda function
   - Review retry logic in function logs

2. **Security Group Rule Limits**
   - AWS limits security groups to 60 inbound rules by default
   - Monitor the `cloudflare_ip_count` output
   - Consider using multiple security groups for large IP lists

3. **Terraform Automation Failures**
   - Check Lambda function logs for Terraform execution errors
   - Verify S3 bucket permissions (direct mode)
   - Confirm Terraform Cloud credentials (cloud mode)

4. **Missing Notifications**
   - Confirm SNS topic subscription in AWS console
   - Check email spam/junk folders
   - Verify notification_email variable is set

### Debugging

Enable detailed logging by checking:
- CloudWatch log group: `/aws/lambda/cloudflare-ip-updater-{environment}`
- Lambda function environment variables
- EventBridge rule status and targets
- SNS topic subscriptions

## Module Best Practices

### Version Pinning
Always pin the module version in production:

```hcl
module "cloudflare_security_group" {
  source = "git::https://github.com/your-org/terraform-aws-cloudflare-security-group.git?ref=v1.2.0"
  # ... variables
}
```

### Environment Separation
Use different configurations for different environments:

```hcl
# environments/production/main.tf
module "cloudflare_security_group" {
  source = "../../modules/cloudflare-aws-security-group"
  
  vpc_id              = var.production_vpc_id
  environment         = "production"
  notification_email  = "production-alerts@company.com"
  update_schedule     = "cron(0 2 * * ? *)"  # Daily
}

# environments/development/main.tf  
module "cloudflare_security_group" {
  source = "../../modules/cloudflare-aws-security-group"
  
  vpc_id              = var.development_vpc_id
  environment         = "development"
  allowed_ports       = [80, 443, 8080, 3000]
  update_schedule     = "cron(0 */6 * * ? *)"  # Every 6 hours
}
```

### Resource Naming
The module uses consistent naming patterns:
- Security Group: `cloudflare-whitelist-{environment}`
- Lambda Function: `cloudflare-ip-updater-{environment}`
- CloudWatch Log Group: `/aws/lambda/cloudflare-ip-updater-{environment}`

### Tagging Strategy
The module applies consistent tags to all resources. You can extend with additional tags:

```hcl
module "cloudflare_security_group" {
  source = "./modules/cloudflare-aws-security-group"
  
  vpc_id      = var.vpc_id
  environment = var.environment
  
  tags = {
    Project      = "web-infrastructure"
    Owner        = "platform-team"
    CostCenter   = "engineering"
    Compliance   = "required"
    BackupPolicy = "7-days"
  }
}
```

## Module Development

### Local Testing
To test the module locally:

```bash
# Navigate to examples directory
cd examples/basic

# Initialize Terraform
terraform init

# Plan the deployment
terraform plan -var="vpc_id=vpc-your-vpc-id"

# Apply (be careful in production)
terraform apply -var="vpc_id=vpc-your-vpc-id"
```

### Validation
The module includes comprehensive input validation:
- VPC ID format validation
- Port range validation (1-65535)
- Protocol validation (tcp, udp, icmp)
- Email format validation
- Environment name validation

## Contributing

When contributing to this module:

1. **Follow Terraform best practices**
   - Use consistent formatting (`terraform fmt`)
   - Validate syntax (`terraform validate`)
   - Follow naming conventions

2. **Update documentation**
   - Update README.md for any new variables or outputs
   - Update examples if adding new functionality
   - Include validation rules documentation

3. **Testing requirements**
   - Test with both Terraform Cloud and direct execution modes
   - Test with different AWS regions
   - Verify all examples work correctly

4. **Version management**
   - Follow semantic versioning (MAJOR.MINOR.PATCH)
   - Update CHANGELOG.md with changes
   - Tag releases appropriately

## Security Considerations

- **IAM Permissions**: The module creates minimal IAM permissions required for operation
- **Network Security**: Only specified ports and protocols are allowed
- **Secrets Management**: Use environment variables or AWS Secrets Manager for sensitive values
- **Resource Isolation**: Each environment gets separate resources with proper naming

## Support and Maintenance

This module is actively maintained and follows these support guidelines:

- **Terraform Compatibility**: Supports Terraform >= 1.0
- **AWS Provider**: Compatible with AWS provider ~> 5.0
- **Updates**: Cloudflare IP ranges are updated automatically via Lambda function
- **Monitoring**: Comprehensive CloudWatch monitoring and alerting included

## License

This module is provided as-is for educational and operational use. Please review and test thoroughly before using in production environments.