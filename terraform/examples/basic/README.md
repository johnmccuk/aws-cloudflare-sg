# Basic Example - Cloudflare AWS Security Group Module

This example demonstrates a comprehensive yet easy-to-use configuration of the Cloudflare AWS Security Group Terraform module with all essential features enabled.

## What This Example Creates

- **AWS Security Group** with ingress rules for Cloudflare IP ranges (HTTP and HTTPS)
- **Lambda function** for automated IP range updates with enhanced state management
- **Cleanup Lambda function** for proper resource cleanup during destroy operations
- **EventBridge rule** for daily scheduled updates (2 AM UTC)
- **CloudWatch monitoring** with log groups, alarms, and dashboard (if email provided)
- **SNS notifications** for update status (if email provided)
- **IAM roles and policies** with least-privilege permissions
- **Comprehensive resource tagging** for cleanup and management

## Configuration Features

This example includes:
- **Ports**: 80 (HTTP) and 443 (HTTPS)
- **Protocol**: TCP
- **Update Schedule**: Daily at 2 AM UTC
- **Environment**: dev (customizable)
- **Automation**: Enabled with state validation and drift detection
- **Quota Management**: Enabled for AWS service limits monitoring
- **Cleanup Functionality**: Automated cleanup during terraform destroy
- **Default VPC Support**: Uses default VPC if none specified

## Prerequisites

1. **AWS CLI** configured with appropriate credentials
2. **Terraform >= 1.0** installed
3. **Valid AWS account** with required permissions
4. **VPC available** (will use default VPC if none specified)

## Required AWS Permissions

Your AWS credentials need the following permissions:

### Core Permissions
- `ec2:CreateSecurityGroup`, `ec2:DeleteSecurityGroup`
- `ec2:AuthorizeSecurityGroupIngress`, `ec2:RevokeSecurityGroupIngress`
- `ec2:DescribeSecurityGroups`, `ec2:DescribeVpcs`
- `lambda:CreateFunction`, `lambda:DeleteFunction`, `lambda:UpdateFunctionCode`
- `lambda:GetFunction`, `lambda:InvokeFunction`
- `iam:CreateRole`, `iam:DeleteRole`, `iam:AttachRolePolicy`, `iam:DetachRolePolicy`
- `iam:PassRole`, `iam:GetRole`, `iam:ListRoleTags`, `iam:TagRole`

### Monitoring and Automation
- `events:PutRule`, `events:DeleteRule`, `events:PutTargets`, `events:RemoveTargets`
- `logs:CreateLogGroup`, `logs:DeleteLogGroup`, `logs:PutRetentionPolicy`
- `cloudwatch:PutMetricAlarm`, `cloudwatch:DeleteAlarms`
- `sns:CreateTopic`, `sns:DeleteTopic`, `sns:Subscribe`, `sns:Unsubscribe`

## Quick Start

### 1. Simple Deployment (Default VPC)

```bash
# Navigate to the basic example directory
cd examples/basic/

# Initialize Terraform
terraform init

# Deploy with defaults (uses default VPC)
terraform apply
```

### 2. Custom VPC Deployment

```bash
# Deploy with specific VPC
terraform apply -var="vpc_id=vpc-12345678"
```

### 3. Full Configuration with Notifications

```bash
# Deploy with custom configuration
terraform apply \
  -var="vpc_id=vpc-12345678" \
  -var="environment=production" \
  -var="aws_region=eu-west-1" \
  -var="notification_email=admin@example.com"
```

## Configuration Variables

| Variable | Description | Default | Required |
|----------|-------------|---------|----------|
| `vpc_id` | VPC ID for security group | `""` (uses default VPC) | No |
| `aws_region` | AWS region for resources | `us-east-1` | No |
| `environment` | Environment name for tagging | `dev` | No |
| `notification_email` | Email for notifications | `""` (disabled) | No |

## Expected Outputs

After successful deployment, you'll see outputs like:

```hcl
security_group_id = "sg-0123456789abcdef0"
security_group_name = "cloudflare-whitelist-dev-20240101123456"
cloudflare_ip_count = 15
configured_ports = [80, 443]
lambda_function_name = "cloudflare-ip-updater-dev"
lambda_function_arn = "arn:aws:lambda:us-east-1:123456789012:function:cloudflare-ip-updater-dev"
eventbridge_rule_name = "cloudflare-ip-update-dev"
automation_enabled = true
update_schedule = "cron(0 2 * * ? *)"
cleanup_function_name = "cloudflare-ip-cleanup-dev"
```

## Verification and Testing

### 1. Verify Security Group Rules

```bash
# Get security group ID from outputs
SG_ID=$(terraform output -raw security_group_id)

# Check security group rules
aws ec2 describe-security-groups --group-ids $SG_ID --query 'SecurityGroups[0].IpPermissions'
```

### 2. Test Lambda Function

```bash
# Get Lambda function name from outputs
FUNCTION_NAME=$(terraform output -raw lambda_function_name)

# Invoke Lambda function manually
aws lambda invoke --function-name $FUNCTION_NAME response.json
cat response.json
```

### 3. Monitor CloudWatch Logs

```bash
# Get log group name from outputs
LOG_GROUP=$(terraform output -raw cloudwatch_log_group_name)

# Tail logs in real-time
aws logs tail $LOG_GROUP --follow
```

### 4. Check EventBridge Rule

```bash
# Get EventBridge rule name from outputs
RULE_NAME=$(terraform output -raw eventbridge_rule_name)

# Check rule configuration
aws events describe-rule --name $RULE_NAME
```

## Advanced Usage Examples

### Custom Port Configuration

Create a `terraform.tfvars` file:

```hcl
vpc_id = "vpc-12345678"
environment = "staging"
aws_region = "eu-west-1"
notification_email = "devops@company.com"
```

### Multiple Environments

```bash
# Development environment
terraform workspace new dev
terraform apply -var="environment=dev"

# Production environment
terraform workspace new prod
terraform apply -var="environment=prod" -var="notification_email=alerts@company.com"
```

## Monitoring and Maintenance

### CloudWatch Dashboard

If you provide a notification email, a CloudWatch dashboard will be created with:
- Lambda function metrics (duration, errors, invocations)
- IP range update statistics
- Recent activity logs
- Error logs and automation logs

### Automated Notifications

With email notifications enabled, you'll receive alerts for:
- Successful IP range updates
- Lambda function errors
- Long-running executions
- Automation health issues

### State Management Features

This example enables advanced state management:
- **State Validation**: Ensures security group state matches expectations
- **Drift Detection**: Identifies manual changes to security group rules
- **Quota Monitoring**: Tracks AWS service limits and usage

## Cleanup and Destroy

### Automated Cleanup

The module includes comprehensive cleanup functionality:

```bash
# Standard destroy with automated cleanup
terraform destroy
```

The cleanup process will:
1. Disable EventBridge rules to prevent new executions
2. Wait for running Lambda executions to complete
3. Clean up security group rules to avoid dependency conflicts
4. Remove SNS subscriptions
5. Execute Terraform destroy in proper order
6. Verify cleanup completion

### Manual Cleanup Validation

```bash
# Validate cleanup configuration before destroy
../../scripts/validate-cleanup.sh dev us-east-1

# Manual cleanup if needed
../../scripts/cleanup.sh dev $SG_ID $FUNCTION_NAME $RULE_NAME $SNS_TOPIC $LOG_GROUP "cloudflare-ip-updater-dev" us-east-1
```

## Troubleshooting

### Common Issues and Solutions

#### 1. Default VPC Not Found
```bash
# Error: No default VPC found
# Solution: Specify a VPC ID explicitly
terraform apply -var="vpc_id=vpc-12345678"
```

#### 2. Permission Denied
```bash
# Error: Access denied for specific AWS service
# Solution: Check IAM permissions and attach required policies
aws iam list-attached-user-policies --user-name your-username
```

#### 3. Resource Already Exists
```bash
# Error: Resource already exists
# Solution: Use a different environment name
terraform apply -var="environment=dev2"
```

#### 4. Lambda Function Timeout
```bash
# Check Lambda function logs for timeout issues
aws logs filter-log-events --log-group-name /aws/lambda/cloudflare-ip-updater-dev --filter-pattern "Task timed out"
```

### Debug Mode

Enable detailed logging:

```bash
# Set Terraform debug logging
export TF_LOG=DEBUG
terraform apply

# Check AWS CLI debug output
aws --debug lambda invoke --function-name cloudflare-ip-updater-dev response.json
```

## Integration Examples

### With Existing Infrastructure

```hcl
# In your main Terraform configuration
module "cloudflare_security" {
  source = "path/to/cloudflare-aws-security-group/examples/basic"
  
  vpc_id = data.aws_vpc.main.id
  environment = var.environment
  notification_email = var.ops_email
  
  # Pass through existing tags
  tags = local.common_tags
}

# Use the security group in other resources
resource "aws_instance" "web" {
  # ... other configuration
  vpc_security_group_ids = [module.cloudflare_security.security_group_id]
}
```

### CI/CD Pipeline Integration

```yaml
# GitHub Actions example
- name: Deploy Cloudflare Security Group
  run: |
    cd examples/basic
    terraform init
    terraform plan -var="vpc_id=${{ secrets.VPC_ID }}"
    terraform apply -auto-approve -var="vpc_id=${{ secrets.VPC_ID }}"
```

## Next Steps

After successfully deploying the basic example:

1. **Monitor Operations**: Check CloudWatch logs and dashboards
2. **Test Automation**: Wait for the first scheduled update or trigger manually
3. **Explore Advanced Features**: Try the [advanced example](../advanced/) for more complex scenarios
4. **Customize Configuration**: Modify ports, schedules, or notification settings
5. **Production Deployment**: Adapt the configuration for your production environment
6. **Integration**: Use the module in your existing Terraform infrastructure

## Support and Documentation

- **Main Module Documentation**: [../../README.md](../../README.md)
- **Cleanup Documentation**: [../../CLEANUP.md](../../CLEANUP.md)
- **Advanced Example**: [../advanced/README.md](../advanced/README.md)
- **Troubleshooting Guide**: [../../README.md#troubleshooting](../../README.md#troubleshooting)

For additional support, check the module's issue tracker or contact your infrastructure team.