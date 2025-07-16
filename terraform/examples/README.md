# Cloudflare AWS Security Group Module Examples

This directory contains example configurations demonstrating different ways to use the Cloudflare AWS Security Group Terraform module.

## Available Examples

### [Basic Example](./basic/)
Demonstrates the minimal configuration required to use the module:
- Simple security group creation with default settings
- HTTPS (port 443) access from Cloudflare IPs
- Basic automation enabled
- Minimal outputs

**Use Case**: Quick setup for standard web applications behind Cloudflare

### [Advanced Example](./advanced/)
Demonstrates advanced features and comprehensive configuration:
- Multiple ports and custom protocols
- Terraform Cloud integration
- Comprehensive monitoring and alerting
- Custom tagging strategy
- Additional security group for internal communication

**Use Case**: Production environments requiring full monitoring and automation

## Running the Examples

### Prerequisites
1. AWS CLI configured with appropriate credentials
2. Terraform >= 1.0 installed
3. Valid AWS VPC ID for your target region

### Basic Example
```bash
cd basic/
terraform init
terraform plan -var="vpc_id=vpc-your-vpc-id"
terraform apply -var="vpc_id=vpc-your-vpc-id"
```

### Advanced Example
```bash
cd advanced/
cp terraform.tfvars.example terraform.tfvars
# Edit terraform.tfvars with your values
terraform init
terraform plan
terraform apply
```

## Configuration Tips

### Environment-Specific Configurations

#### Development
- Use more frequent update schedules for testing
- Include additional ports for development tools
- Enable automation but with shorter intervals
- Use descriptive tags for resource identification

#### Staging
- Mirror production configuration but with staging-specific values
- Use weekly update schedules to reduce API calls
- Enable notifications to staging team
- Test Terraform Cloud integration if used in production

#### Production
- Use conservative update schedules (daily or twice daily)
- Enable comprehensive monitoring and alerting
- Use Terraform Cloud for better collaboration
- Implement proper tagging for cost allocation and compliance

### Security Considerations

1. **VPC Selection**: Ensure you're using the correct VPC for your environment
2. **Port Configuration**: Only open ports that are actually needed
3. **Notification Emails**: Use distribution lists rather than individual emails
4. **Terraform State**: Use remote state storage for team collaboration

### Cost Optimization

1. **Update Frequency**: Balance security with API costs by choosing appropriate schedules
2. **Monitoring**: Disable detailed monitoring in development environments
3. **Retention**: Adjust CloudWatch log retention based on compliance requirements
4. **Notifications**: Use SNS topics efficiently to avoid duplicate notifications

## Troubleshooting Examples

### Common Issues

1. **VPC Not Found**
   ```
   Error: Invalid VPC ID
   ```
   **Solution**: Verify the VPC ID exists in your target AWS region

2. **Insufficient Permissions**
   ```
   Error: AccessDenied
   ```
   **Solution**: Ensure your AWS credentials have the required permissions for EC2, Lambda, CloudWatch, and SNS

3. **Terraform Cloud Authentication**
   ```
   Error: Invalid Terraform Cloud token
   ```
   **Solution**: Verify your Terraform Cloud token is valid and has appropriate workspace permissions

### Validation Commands

Before applying, validate your configuration:

```bash
# Validate Terraform syntax
terraform validate

# Format Terraform files
terraform fmt -recursive

# Plan with variable validation
terraform plan -var-file="terraform.tfvars"

# Check for security issues (if using tfsec)
tfsec .
```

## Example Outputs

After successful deployment, you'll see outputs similar to:

```
Outputs:

cloudflare_ip_count = 15
lambda_function_name = "cloudflare-ip-updater-production"
security_group_id = "sg-0123456789abcdef0"
cloudwatch_dashboard_url = "https://us-west-2.console.aws.amazon.com/cloudwatch/home?region=us-west-2#dashboards:name=cloudflare-ip-updater-production"
```

## Next Steps

After running an example:

1. **Verify Resources**: Check the AWS console to confirm resources were created
2. **Test Automation**: Wait for the first scheduled update or trigger manually
3. **Monitor Logs**: Check CloudWatch logs for any issues
4. **Set Up Alerts**: Confirm SNS notifications are working
5. **Document Configuration**: Save your working configuration for future reference

## Contributing Examples

To contribute new examples:

1. Create a new directory under `examples/`
2. Include a complete Terraform configuration
3. Add a README.md explaining the use case
4. Include a terraform.tfvars.example file
5. Test the example thoroughly
6. Update this main examples README.md