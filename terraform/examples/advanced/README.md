# Advanced Example - Cloudflare AWS Security Group Module

This example demonstrates advanced features and comprehensive configuration of the Cloudflare AWS Security Group Terraform module, including Terraform Cloud integration, comprehensive monitoring, and additional security group configurations.

## What This Example Creates

### Core Module Resources
- AWS Security Group with ingress rules for Cloudflare IP ranges (multiple ports)
- Lambda function for automated IP range updates
- EventBridge rule for twice-daily scheduled updates
- CloudWatch log group, alarms, and dashboard
- SNS topic and email subscription for notifications
- IAM role and comprehensive policies for Lambda function

### Additional Resources
- Secondary security group for internal communication
- VPC data source for additional context
- Comprehensive tagging strategy
- Production-ready monitoring and alerting

## Configuration Features

This advanced example includes:
- **Multiple Ports**: 80, 443, 8080, 8443 (HTTP, HTTPS, and custom ports)
- **Protocol**: TCP
- **Update Schedule**: Twice daily (2 AM and 2 PM UTC)
- **Environment**: Configurable (production by default)
- **Automation**: Enabled with comprehensive monitoring
- **Notifications**: Email alerts for all events
- **Terraform Mode**: Cloud integration
- **Monitoring**: Full CloudWatch dashboard and alarms

## Prerequisites

1. AWS CLI configured with appropriate credentials
2. Terraform >= 1.0 installed
3. Valid AWS VPC ID in your target region
4. Terraform Cloud account and workspace (for cloud mode)
5. Valid email address for notifications

## Required Permissions

Your AWS credentials need comprehensive permissions including:
- All permissions from basic example
- `sns:CreateTopic`, `sns:Subscribe`, `sns:Publish`
- `cloudwatch:PutMetricAlarm`, `cloudwatch:PutDashboard`
- `events:*` for EventBridge management
- `s3:*` for Terraform state management (if using S3 backend)

## Configuration

1. **Copy the example terraform.tfvars file**
   ```bash
   cp terraform.tfvars.example terraform.tfvars
   ```

2. **Edit terraform.tfvars with your values**
   ```hcl
   # Required variables
   vpc_id      = "vpc-your-actual-vpc-id"
   environment = "production"
   notification_email = "your-email@company.com"
   
   # Terraform Cloud configuration
   terraform_cloud_token  = "your-terraform-cloud-token"
   terraform_workspace    = "ws-your-workspace-id"
   terraform_organization = "your-organization"
   ```

3. **Set environment variables for sensitive values**
   ```bash
   export TF_VAR_terraform_cloud_token="your-terraform-cloud-token"
   ```

## Usage

1. **Navigate to the advanced example directory**
   ```bash
   cd examples/advanced/
   ```

2. **Initialize Terraform**
   ```bash
   terraform init
   ```

3. **Plan the deployment**
   ```bash
   terraform plan
   ```

4. **Apply the configuration**
   ```bash
   terraform apply
   ```

5. **Confirm email subscription**
   Check your email and confirm the SNS subscription

## Expected Outputs

After successful deployment:

```
security_group_id = "sg-0123456789abcdef0"
security_group_arn = "arn:aws:ec2:us-west-2:123456789012:security-group/sg-0123456789abcdef0"
cloudflare_ip_count = 15
configured_ports = [80, 443, 8080, 8443]
lambda_function_name = "cloudflare-ip-updater-production"
sns_topic_arn = "arn:aws:sns:us-west-2:123456789012:cloudflare-ip-updates-production"
cloudwatch_dashboard_url = "https://us-west-2.console.aws.amazon.com/cloudwatch/home?region=us-west-2#dashboards:name=cloudflare-ip-updater-production"
internal_security_group_id = "sg-0987654321fedcba0"
deployment_summary = {
  automation_enabled = true
  cloudflare_ports = [80, 443, 8080, 8443]
  environment = "production"
  monitoring_enabled = true
  terraform_mode = "cloud"
  vpc_id = "vpc-12345678"
}
```

## Monitoring and Alerting

This example creates comprehensive monitoring:

### CloudWatch Alarms
- **Lambda Errors**: Alerts on function errors
- **Lambda Duration**: Alerts when execution time is high
- **Lambda Throttles**: Monitors function throttling
- **No Invocations**: Alerts if automation stops working

### CloudWatch Dashboard
Access the dashboard using the `cloudwatch_dashboard_url` output to monitor:
- Lambda function metrics
- Notification statistics
- IP range update history
- Error logs and automation logs

### SNS Notifications
You'll receive email notifications for:
- Successful IP range updates
- Update failures and errors
- CloudWatch alarm state changes

## Testing the Advanced Features

### 1. Test Lambda Function
```bash
aws lambda invoke --function-name cloudflare-ip-updater-production response.json
cat response.json
```

### 2. Monitor CloudWatch Logs
```bash
aws logs tail /aws/lambda/cloudflare-ip-updater-production --follow
```

### 3. Test SNS Notifications
```bash
aws sns publish --topic-arn "arn:aws:sns:region:account:cloudflare-ip-updates-production" --message "Test notification"
```

### 4. View CloudWatch Dashboard
Use the dashboard URL from the outputs to access the monitoring dashboard.

## Terraform Cloud Integration

This example demonstrates Terraform Cloud integration:

1. **Workspace Configuration**: Uses Terraform Cloud workspace for state management
2. **Remote Execution**: Lambda function can trigger Terraform Cloud runs
3. **Secure Variables**: Sensitive variables are managed securely
4. **Team Collaboration**: Multiple team members can collaborate on infrastructure

### Setting Up Terraform Cloud

1. Create a Terraform Cloud account
2. Create an organization and workspace
3. Generate an API token
4. Configure workspace variables if needed
5. Update terraform.tfvars with your Terraform Cloud details

## Customization Examples

### Different Update Schedules
```hcl
# Hourly updates (for testing)
update_schedule = "cron(0 * * * ? *)"

# Weekly updates (Sundays at 2 AM)
update_schedule = "cron(0 2 ? * SUN *)"

# Business hours only (weekdays 9 AM and 5 PM)
update_schedule = "cron(0 9,17 ? * MON-FRI *)"
```

### Custom Port Configurations
```hcl
# Web services
allowed_ports = [80, 443, 8080, 8443]

# Database access (be careful with this)
allowed_ports = [3306, 5432, 1433]

# Custom application ports
allowed_ports = [3000, 4000, 5000]
```

### Environment-Specific Tags
```hcl
# Production tags
tags = {
  Environment  = "production"
  Criticality  = "high"
  Backup       = "required"
  Monitoring   = "enhanced"
  Compliance   = "sox"
  CostCenter   = "engineering"
}

# Development tags
tags = {
  Environment = "development"
  AutoDelete  = "true"
  Owner       = "dev-team"
  Project     = "web-app"
}
```

## Security Considerations

### Network Security
- The internal security group demonstrates secure communication patterns
- Only necessary ports are opened to Cloudflare IPs
- Proper security group referencing for internal communication

### IAM Security
- Lambda function has minimal required permissions
- Terraform Cloud integration uses secure token management
- No hardcoded credentials in configuration

### Monitoring Security
- All automation activities are logged
- Alerts are configured for security-relevant events
- Dashboard provides visibility into all operations

## Cleanup

To remove all resources:

```bash
terraform destroy
```

Note: You may need to manually delete the SNS subscription confirmation email.

## Next Steps

After successfully deploying the advanced example:

1. **Customize for your environment**: Modify ports, schedules, and tags
2. **Integrate with existing infrastructure**: Reference the security group in other resources
3. **Set up team access**: Configure Terraform Cloud workspace permissions
4. **Monitor operations**: Regularly check the CloudWatch dashboard
5. **Optimize costs**: Adjust update frequency and monitoring based on needs

## Troubleshooting

### Terraform Cloud Issues
- Verify API token has correct permissions
- Check workspace ID and organization name
- Ensure workspace has necessary AWS credentials configured

### SNS Notification Issues
- Check email address format
- Confirm SNS subscription in email
- Verify SNS topic permissions

### CloudWatch Dashboard Issues
- Ensure CloudWatch permissions are granted
- Check if dashboard name conflicts exist
- Verify region consistency across resources

For additional help, refer to the main module [troubleshooting guide](../../README.md#troubleshooting).