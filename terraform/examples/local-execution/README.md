# Local Execution Example

This example demonstrates how to configure the Cloudflare AWS Security Group module for local Terraform execution with S3 backend for state management.

## Overview

This configuration is designed for teams using local Terraform execution with remote state storage. It includes:

- Local Terraform execution with S3 backend
- Automated IP range updates via Lambda with direct Terraform execution
- Basic monitoring and alerting
- Development and testing friendly configuration

## Prerequisites

1. **AWS CLI**: Configured with appropriate credentials
2. **Terraform**: Version >= 1.5.0 installed locally
3. **S3 Bucket**: For Terraform state storage (optional but recommended)
4. **DynamoDB Table**: For state locking (optional but recommended)
5. **VPC**: Existing AWS VPC where the security group will be created

## Configuration Files

### terraform.tfvars.example
Copy this file to `terraform.tfvars` and update with your values:

```hcl
# AWS Configuration
vpc_id      = "vpc-0123456789abcdef0"
environment = "development"

# Networking Configuration
allowed_ports = [443, 80, 8080]
protocol     = "tcp"

# Local Execution Configuration
terraform_mode              = "direct"
terraform_config_s3_bucket  = "your-terraform-configs-bucket"
terraform_config_s3_key     = "cloudflare-sg/terraform.zip"
terraform_state_s3_bucket   = "your-terraform-state-bucket"
terraform_state_s3_key      = "cloudflare-sg/terraform.tfstate"

# Automation Configuration
enable_automation = true
update_schedule   = "cron(0 */6 * * ? *)"  # Every 6 hours

# Monitoring Configuration
notification_email = "developer@yourcompany.com"

# Tagging
tags = {
  Project     = "CloudflareIntegration"
  Owner       = "DeveloperTeam"
  Environment = "Development"
}
```

## Setup Instructions

### 1. Prepare S3 Backend (Recommended)

```bash
# Create S3 bucket for state storage
aws s3 mb s3://your-terraform-state-bucket

# Create S3 bucket for configuration storage
aws s3 mb s3://your-terraform-configs-bucket

# Create DynamoDB table for state locking
aws dynamodb create-table \
    --table-name terraform-state-lock \
    --attribute-definitions AttributeName=LockID,AttributeType=S \
    --key-schema AttributeName=LockID,KeyType=HASH \
    --provisioned-throughput ReadCapacityUnits=5,WriteCapacityUnits=5
```

### 2. Configure Backend

Create or update `backend.tf`:

```hcl
terraform {
  backend "s3" {
    bucket         = "your-terraform-state-bucket"
    key            = "cloudflare-sg/terraform.tfstate"
    region         = "us-west-2"
    dynamodb_table = "terraform-state-lock"
    encrypt        = true
  }
}
```

### 3. Initialize and Deploy

```bash
# Copy and customize variables
cp terraform.tfvars.example terraform.tfvars

# Initialize Terraform
terraform init

# Validate configuration
terraform validate

# Plan deployment
terraform plan

# Apply configuration
terraform apply
```

### 4. Upload Configuration for Automation

```bash
# Create configuration archive for Lambda automation
zip -r terraform-config.zip *.tf *.tfvars

# Upload to S3
aws s3 cp terraform-config.zip s3://your-terraform-configs-bucket/cloudflare-sg/terraform.zip
```

## Local Execution Features

### Direct Terraform Execution

The Lambda function will:

1. **Download Config**: Retrieve Terraform configuration from S3
2. **Execute Locally**: Run terraform commands directly in Lambda environment
3. **Update State**: Store updated state back to S3
4. **Handle Locking**: Use DynamoDB for state locking

### Development Workflow

```bash
# Make changes locally
terraform plan

# Apply changes
terraform apply

# Update automation configuration
zip -r terraform-config.zip *.tf *.tfvars
aws s3 cp terraform-config.zip s3://your-terraform-configs-bucket/cloudflare-sg/terraform.zip

# Test automation
aws lambda invoke \
    --function-name cloudflare-ip-updater-development \
    --payload '{"source": "manual-test"}' \
    response.json
```

### State Management

```bash
# View current state
terraform show

# List resources
terraform state list

# Import existing resources (if needed)
terraform import aws_security_group.cloudflare_whitelist sg-existing-id

# Refresh state
terraform refresh
```

## Automation Configuration

### Lambda Function Environment

The Lambda function uses these environment variables for local execution:

```python
# Environment variables for direct mode
TERRAFORM_MODE = "direct"
TERRAFORM_CONFIG_S3_BUCKET = "your-terraform-configs-bucket"
TERRAFORM_CONFIG_S3_KEY = "cloudflare-sg/terraform.zip"
TERRAFORM_STATE_S3_BUCKET = "your-terraform-state-bucket"
TERRAFORM_STATE_S3_KEY = "cloudflare-sg/terraform.tfstate"
```

### Terraform Binary

The Lambda function includes a statically compiled Terraform binary:

```bash
# Download Terraform for Lambda (Linux AMD64)
wget https://releases.hashicorp.com/terraform/1.6.0/terraform_1.6.0_linux_amd64.zip
unzip terraform_1.6.0_linux_amd64.zip
chmod +x terraform

# Include in Lambda deployment package
zip -r lambda-function.zip lambda_function.py terraform
```

## Monitoring and Debugging

### CloudWatch Logs

```bash
# View Lambda logs
aws logs tail /aws/lambda/cloudflare-ip-updater-development --follow

# Filter for errors
aws logs filter-log-events \
    --log-group-name /aws/lambda/cloudflare-ip-updater-development \
    --filter-pattern "ERROR"

# View Terraform execution logs
aws logs filter-log-events \
    --log-group-name /aws/lambda/cloudflare-ip-updater-development \
    --filter-pattern "terraform"
```

### Manual Testing

```bash
# Test Cloudflare API access
curl -s https://www.cloudflare.com/ips-v4

# Test Lambda function
aws lambda invoke \
    --function-name cloudflare-ip-updater-development \
    --payload '{"source": "manual-test", "debug": true}' \
    response.json

cat response.json
```

### State Inspection

```bash
# Download and inspect state
aws s3 cp s3://your-terraform-state-bucket/cloudflare-sg/terraform.tfstate .
terraform show terraform.tfstate

# Check state lock
aws dynamodb get-item \
    --table-name terraform-state-lock \
    --key '{"LockID":{"S":"your-terraform-state-bucket/cloudflare-sg/terraform.tfstate-md5"}}'
```

## Security Considerations

### IAM Permissions

The Lambda function requires these permissions for local execution:

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": [
        "s3:GetObject",
        "s3:PutObject",
        "s3:DeleteObject"
      ],
      "Resource": [
        "arn:aws:s3:::your-terraform-configs-bucket/*",
        "arn:aws:s3:::your-terraform-state-bucket/*"
      ]
    },
    {
      "Effect": "Allow",
      "Action": [
        "dynamodb:GetItem",
        "dynamodb:PutItem",
        "dynamodb:DeleteItem"
      ],
      "Resource": "arn:aws:dynamodb:*:*:table/terraform-state-lock"
    },
    {
      "Effect": "Allow",
      "Action": [
        "ec2:*",
        "lambda:*",
        "iam:*",
        "events:*",
        "logs:*",
        "cloudwatch:*",
        "sns:*"
      ],
      "Resource": "*"
    }
  ]
}
```

### State Security

- Enable S3 bucket encryption
- Use versioning for state files
- Restrict access to state bucket
- Use DynamoDB encryption at rest

```bash
# Enable S3 encryption
aws s3api put-bucket-encryption \
    --bucket your-terraform-state-bucket \
    --server-side-encryption-configuration '{
        "Rules": [{
            "ApplyServerSideEncryptionByDefault": {
                "SSEAlgorithm": "AES256"
            }
        }]
    }'

# Enable versioning
aws s3api put-bucket-versioning \
    --bucket your-terraform-state-bucket \
    --versioning-configuration Status=Enabled
```

## Troubleshooting

### Common Issues

1. **State Lock Conflicts**
   ```
   Error: Error acquiring the state lock
   ```
   **Solution**: Check and clear DynamoDB lock table if needed

2. **S3 Access Denied**
   ```
   Error: AccessDenied when accessing S3 bucket
   ```
   **Solution**: Verify Lambda IAM role has S3 permissions

3. **Terraform Binary Not Found**
   ```
   Error: terraform: command not found
   ```
   **Solution**: Ensure Terraform binary is included in Lambda package

### Debugging Steps

```bash
# Check S3 bucket contents
aws s3 ls s3://your-terraform-configs-bucket/cloudflare-sg/

# Verify DynamoDB table
aws dynamodb describe-table --table-name terraform-state-lock

# Test Lambda permissions
aws lambda get-function --function-name cloudflare-ip-updater-development

# Check CloudWatch logs
aws logs describe-log-groups --log-group-name-prefix /aws/lambda/cloudflare-ip-updater
```

## Cost Optimization

### Development Environment

- Use smaller Lambda memory allocation (128MB)
- Shorter log retention (7 days)
- Less frequent update schedule
- Disable detailed monitoring

### Resource Cleanup

```bash
# Clean up test resources
terraform destroy

# Remove S3 objects
aws s3 rm s3://your-terraform-configs-bucket/cloudflare-sg/ --recursive
aws s3 rm s3://your-terraform-state-bucket/cloudflare-sg/ --recursive

# Delete DynamoDB table (if not shared)
aws dynamodb delete-table --table-name terraform-state-lock
```

## Development Tips

### Local Testing

```bash
# Test configuration locally before automation
terraform plan -var-file="terraform.tfvars"

# Validate all files
terraform validate
terraform fmt -check

# Test with different environments
terraform workspace new development
terraform workspace new staging
```

### Configuration Management

```bash
# Use environment-specific variable files
terraform plan -var-file="environments/development.tfvars"
terraform plan -var-file="environments/staging.tfvars"

# Version control your configurations
git add *.tf *.tfvars.example
git commit -m "Add Cloudflare security group configuration"
```

## Next Steps

After successful deployment:

1. **Test Automation**: Trigger Lambda function manually
2. **Monitor Logs**: Check CloudWatch for any issues
3. **Verify Updates**: Confirm security group rules are updated
4. **Set Up CI/CD**: Integrate with your deployment pipeline
5. **Scale Up**: Move to production with appropriate settings