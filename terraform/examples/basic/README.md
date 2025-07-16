# Basic Example - Cloudflare AWS Security Group Module

This example demonstrates the minimal configuration required to use the Cloudflare AWS Security Group Terraform module.

## What This Example Creates

- AWS Security Group with ingress rules for Cloudflare IP ranges
- Lambda function for automated IP range updates
- EventBridge rule for daily scheduled updates (2 AM UTC)
- CloudWatch log group for Lambda function logs
- IAM role and policies for Lambda function execution

## Configuration

The example uses minimal configuration with these defaults:
- **Ports**: 443 (HTTPS)
- **Protocol**: TCP
- **Update Schedule**: Daily at 2 AM UTC
- **Environment**: production
- **Automation**: Enabled
- **Notifications**: Disabled (no email provided)

## Prerequisites

1. AWS CLI configured with appropriate credentials
2. Terraform >= 1.0 installed
3. Valid AWS VPC ID in your target region

## Required Permissions

Your AWS credentials need the following permissions:
- `ec2:CreateSecurityGroup`
- `ec2:AuthorizeSecurityGroupIngress`
- `ec2:DescribeSecurityGroups`
- `lambda:CreateFunction`
- `lambda:UpdateFunctionCode`
- `iam:CreateRole`
- `iam:AttachRolePolicy`
- `events:PutRule`
- `events:PutTargets`
- `logs:CreateLogGroup`

## Usage

1. **Clone or download this example**
2. **Navigate to the basic example directory**
   ```bash
   cd examples/basic/
   ```

3. **Initialize Terraform**
   ```bash
   terraform init
   ```

4. **Plan the deployment**
   ```bash
   terraform plan -var="vpc_id=vpc-your-actual-vpc-id"
   ```

5. **Apply the configuration**
   ```bash
   terraform apply -var="vpc_id=vpc-your-actual-vpc-id"
   ```

6. **Verify the deployment**
   Check the outputs and verify resources in AWS console

## Customization

You can customize the basic example by modifying variables:

```bash
# Custom environment name
terraform apply -var="vpc_id=vpc-12345678" -var="environment=development"

# Different AWS region (update provider configuration)
# Edit main.tf to change the region in the provider block
```

## Expected Outputs

After successful deployment:

```
security_group_id = "sg-0123456789abcdef0"
cloudflare_ip_count = 15
lambda_function_name = "cloudflare-ip-updater-production"
```

## Verification Steps

1. **Check Security Group**
   ```bash
   aws ec2 describe-security-groups --group-ids sg-0123456789abcdef0
   ```

2. **Verify Lambda Function**
   ```bash
   aws lambda get-function --function-name cloudflare-ip-updater-production
   ```

3. **Check EventBridge Rule**
   ```bash
   aws events describe-rule --name cloudflare-ip-update-production
   ```

4. **View CloudWatch Logs**
   ```bash
   aws logs describe-log-groups --log-group-name-prefix /aws/lambda/cloudflare-ip-updater
   ```

## Testing the Automation

To test the automated update functionality:

1. **Trigger Lambda manually**
   ```bash
   aws lambda invoke --function-name cloudflare-ip-updater-production response.json
   cat response.json
   ```

2. **Check CloudWatch logs**
   ```bash
   aws logs tail /aws/lambda/cloudflare-ip-updater-production --follow
   ```

## Cleanup

To remove all resources created by this example:

```bash
terraform destroy -var="vpc_id=vpc-your-actual-vpc-id"
```

## Next Steps

After successfully deploying the basic example:

1. **Monitor the automation**: Check CloudWatch logs after the first scheduled run
2. **Explore advanced features**: Try the [advanced example](../advanced/) for more features
3. **Customize for your needs**: Modify ports, schedules, or add notifications
4. **Integrate with your infrastructure**: Use the module in your main Terraform configurations

## Troubleshooting

### Common Issues

1. **VPC not found**
   - Verify the VPC ID exists in your current AWS region
   - Check your AWS CLI region configuration

2. **Permission denied**
   - Ensure your AWS credentials have the required permissions
   - Check IAM policies attached to your user/role

3. **Resource already exists**
   - Check if resources with similar names already exist
   - Use a different environment name to avoid conflicts

### Getting Help

- Check the main module [README](../../README.md) for detailed documentation
- Review [troubleshooting section](../../README.md#troubleshooting) in the main documentation
- Check AWS CloudWatch logs for Lambda function errors