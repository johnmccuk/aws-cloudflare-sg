# Terraform Cloud Integration Example

This example demonstrates how to configure the Cloudflare AWS Security Group module for use with Terraform Cloud, including proper automation setup and monitoring.

## Overview

This configuration is designed for teams using Terraform Cloud for infrastructure management. It includes:

- Terraform Cloud workspace integration
- Automated IP range updates via Lambda
- Comprehensive monitoring and alerting
- Production-ready security configurations

## Prerequisites

1. **Terraform Cloud Account**: Active Terraform Cloud account with a configured workspace
2. **AWS Credentials**: AWS credentials configured in Terraform Cloud workspace
3. **API Token**: Terraform Cloud API token with appropriate permissions
4. **VPC**: Existing AWS VPC where the security group will be created

## Configuration Files

### terraform.tfvars.example
Copy this file to `terraform.tfvars` and update with your values:

```hcl
# AWS Configuration
vpc_id      = "vpc-0123456789abcdef0"
environment = "production"

# Networking Configuration
allowed_ports = [443, 80]
protocol     = "tcp"

# Terraform Cloud Configuration
terraform_mode         = "cloud"
terraform_cloud_token  = "your-terraform-cloud-api-token"
terraform_organization = "your-org-name"
terraform_workspace    = "your-workspace-id"

# Automation Configuration
enable_automation = true
update_schedule   = "cron(0 2 * * ? *)"  # Daily at 2 AM UTC

# Monitoring Configuration
notification_email = "devops-team@yourcompany.com"

# Tagging
tags = {
  Project     = "CloudflareIntegration"
  Owner       = "DevOpsTeam"
  Environment = "Production"
  CostCenter  = "Infrastructure"
}
```

## Deployment Steps

### 1. Prepare Terraform Cloud Workspace

```bash
# Create workspace in Terraform Cloud UI or via API
# Configure AWS credentials as environment variables:
# - AWS_ACCESS_KEY_ID
# - AWS_SECRET_ACCESS_KEY
# - AWS_DEFAULT_REGION
```

### 2. Configure Variables

```bash
# Copy and customize the example variables file
cp terraform.tfvars.example terraform.tfvars

# Edit terraform.tfvars with your specific values
# Ensure terraform_cloud_token is kept secure
```

### 3. Initialize and Deploy

```bash
# Initialize Terraform
terraform init

# Validate configuration
terraform validate

# Plan deployment
terraform plan

# Apply configuration
terraform apply
```

### 4. Verify Deployment

```bash
# Check security group in AWS Console
aws ec2 describe-security-groups --group-ids $(terraform output -raw security_group_id)

# Verify Lambda function
aws lambda get-function --function-name $(terraform output -raw lambda_function_name)

# Check EventBridge rule
aws events describe-rule --name $(terraform output -raw eventbridge_rule_name)
```

## Terraform Cloud Specific Features

### Workspace Configuration

This example assumes your Terraform Cloud workspace is configured with:

- **Execution Mode**: Remote
- **Terraform Version**: >= 1.5.0
- **Auto Apply**: Disabled (recommended for production)
- **VCS Integration**: Optional but recommended

### Environment Variables

Set these in your Terraform Cloud workspace:

```bash
# AWS Credentials (Environment Variables)
AWS_ACCESS_KEY_ID=your-access-key
AWS_SECRET_ACCESS_KEY=your-secret-key
AWS_DEFAULT_REGION=us-west-2

# Terraform Cloud Token (Terraform Variable - Sensitive)
TF_VAR_terraform_cloud_token=your-api-token
```

### Variable Sets

Consider using Terraform Cloud Variable Sets for:

- Common AWS credentials across workspaces
- Standard tagging policies
- Environment-specific configurations

## Automation Workflow

### Lambda Function Behavior

The Lambda function will:

1. **Fetch Current IPs**: Retrieve latest Cloudflare IP ranges
2. **Compare Changes**: Check against existing security group rules
3. **Trigger Update**: Use Terraform Cloud API to trigger workspace run
4. **Monitor Results**: Send notifications on success/failure

### Terraform Cloud Integration

```python
# Lambda function uses Terraform Cloud API to:
# 1. Create configuration version
# 2. Upload configuration files
# 3. Queue plan/apply run
# 4. Monitor run status
# 5. Report results
```

## Monitoring and Alerting

### CloudWatch Dashboards

Access your monitoring dashboard:
```bash
echo "Dashboard URL: $(terraform output -raw cloudwatch_dashboard_url)"
```

### SNS Notifications

The system sends notifications for:

- **Successful Updates**: When IP ranges are updated
- **Failures**: When automation encounters errors
- **Health Checks**: When automation hasn't run as expected

### Custom Metrics

The Lambda function publishes custom metrics:

- `CloudflareIPUpdater.IPRangesUpdated`
- `CloudflareIPUpdater.SecurityGroupRulesCount`
- `CloudflareIPUpdater.NotificationsSent`

## Security Considerations

### IAM Permissions

The Lambda function requires these permissions:

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": [
        "ec2:DescribeSecurityGroups",
        "ec2:AuthorizeSecurityGroupIngress",
        "ec2:RevokeSecurityGroupIngress"
      ],
      "Resource": "*"
    }
  ]
}
```

### Terraform Cloud Token Security

- Store the API token as a sensitive variable
- Use workspace-specific tokens when possible
- Rotate tokens regularly
- Monitor token usage in Terraform Cloud audit logs

### Network Security

- Security group rules are automatically managed
- Only Cloudflare IP ranges are allowed
- Rules are updated automatically when IPs change

## Troubleshooting

### Common Issues

1. **Terraform Cloud Authentication Failed**
   ```
   Error: Invalid or expired Terraform Cloud token
   ```
   **Solution**: Verify token is valid and has workspace permissions

2. **Workspace Not Found**
   ```
   Error: Workspace not found or not accessible
   ```
   **Solution**: Check workspace ID and organization name

3. **AWS Permissions Denied**
   ```
   Error: AccessDenied when creating security group
   ```
   **Solution**: Verify AWS credentials have required EC2 permissions

### Debugging Steps

```bash
# Check Terraform Cloud workspace status
curl -H "Authorization: Bearer $TF_CLOUD_TOKEN" \
     https://app.terraform.io/api/v2/workspaces/$WORKSPACE_ID

# Verify AWS credentials
aws sts get-caller-identity

# Check Lambda function logs
aws logs tail /aws/lambda/cloudflare-ip-updater-production --follow

# Test Cloudflare API access
curl -s https://www.cloudflare.com/ips-v4
```

## Cost Optimization

### Terraform Cloud Costs

- Use appropriate workspace tier for your needs
- Monitor run frequency to optimize costs
- Consider using Terraform Cloud agents for high-frequency updates

### AWS Costs

- Lambda function runs are minimal cost
- CloudWatch logs retention set to 14 days
- EventBridge rules have minimal cost impact
- SNS notifications cost depends on volume

## Maintenance

### Regular Tasks

1. **Token Rotation**: Rotate Terraform Cloud tokens quarterly
2. **Permission Review**: Review IAM permissions annually
3. **Update Schedule**: Adjust automation frequency based on needs
4. **Monitoring Review**: Review and update alerting thresholds

### Updates

```bash
# Update module version
terraform init -upgrade

# Plan and apply updates
terraform plan
terraform apply
```

## Next Steps

After successful deployment:

1. **Test Automation**: Trigger a manual Lambda execution
2. **Verify Notifications**: Confirm SNS notifications are received
3. **Monitor Dashboard**: Check CloudWatch dashboard for metrics
4. **Document Configuration**: Save working configuration for team reference
5. **Set Up Alerts**: Configure additional monitoring as needed