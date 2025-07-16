# Configuration Validation Examples

This directory contains examples demonstrating different validation scenarios and configuration patterns for the Cloudflare AWS Security Group module.

## Overview

These examples show how to:

- Validate Terraform Cloud vs local execution requirements
- Implement pre-deployment validation checks
- Handle different deployment scenarios
- Test configuration edge cases
- Validate AWS resource requirements

## Validation Scenarios

### 1. Terraform Cloud Validation
- **File**: `terraform-cloud-validation.tfvars`
- **Purpose**: Validates all required Terraform Cloud parameters
- **Use Case**: Teams using Terraform Cloud for infrastructure management

### 2. Local Execution Validation
- **File**: `local-execution-validation.tfvars`
- **Purpose**: Validates S3 backend and local execution requirements
- **Use Case**: Teams using local Terraform with remote state

### 3. Minimal Configuration Validation
- **File**: `minimal-config-validation.tfvars`
- **Purpose**: Tests the absolute minimum required configuration
- **Use Case**: Quick setup with default values

### 4. Maximum Configuration Validation
- **File**: `maximum-config-validation.tfvars`
- **Purpose**: Tests all available configuration options
- **Use Case**: Comprehensive feature testing

### 5. Edge Case Validation
- **File**: `edge-cases-validation.tfvars`
- **Purpose**: Tests boundary conditions and edge cases
- **Use Case**: Robustness testing

## Running Validation Tests

### Prerequisites
```bash
# Ensure validation script is executable
chmod +x ../../scripts/validate-deployment.sh

# Set required environment variables
export VPC_ID="vpc-your-vpc-id"
export ENVIRONMENT="validation"
```

### Test All Scenarios
```bash
# Run comprehensive validation
./run-all-validations.sh

# Or test individual scenarios
./test-scenario.sh terraform-cloud-validation
./test-scenario.sh local-execution-validation
./test-scenario.sh minimal-config-validation
```

### Manual Validation
```bash
# Test specific configuration
terraform init
terraform validate
terraform plan -var-file="terraform-cloud-validation.tfvars"

# Run pre-deployment validation
../../scripts/validate-deployment.sh
```

## Validation Checklist

### Pre-Deployment Validation
- [ ] Terraform version >= 1.5.0
- [ ] AWS CLI configured with valid credentials
- [ ] Required AWS permissions available
- [ ] VPC exists and is accessible
- [ ] Cloudflare API endpoints are reachable
- [ ] S3 buckets exist (for local execution)
- [ ] Terraform Cloud token valid (for cloud execution)

### Configuration Validation
- [ ] All required variables are set
- [ ] Variable types and constraints are satisfied
- [ ] Terraform Cloud vs local execution requirements met
- [ ] Network configuration is valid
- [ ] Automation settings are reasonable
- [ ] Monitoring configuration is complete

### Post-Deployment Validation
- [ ] Security group created successfully
- [ ] Lambda function deployed and functional
- [ ] EventBridge rule configured correctly
- [ ] CloudWatch monitoring active
- [ ] SNS notifications working
- [ ] Automation triggers properly

## Common Validation Errors

### 1. Missing Required Variables
```
Error: Missing required variable
```
**Solution**: Ensure all required variables are set in your .tfvars file

### 2. Invalid VPC ID
```
Error: Invalid VPC ID format
```
**Solution**: Use correct AWS VPC ID format (vpc-xxxxxxxx)

### 3. Terraform Cloud Authentication
```
Error: Invalid Terraform Cloud token
```
**Solution**: Verify token is valid and has appropriate permissions

### 4. AWS Permissions
```
Error: AccessDenied
```
**Solution**: Ensure AWS credentials have required permissions

### 5. Network Connectivity
```
Error: Failed to fetch Cloudflare IP ranges
```
**Solution**: Check network connectivity and firewall rules

## Validation Scripts

### Automated Validation
The `validate-deployment.sh` script performs comprehensive pre-deployment validation:

```bash
# Run full validation
../../scripts/validate-deployment.sh

# Run quiet validation (errors only)
../../scripts/validate-deployment.sh --quiet

# Get help
../../scripts/validate-deployment.sh --help
```

### Custom Validation
Create custom validation scripts for specific requirements:

```bash
#!/bin/bash
# custom-validation.sh

# Validate custom requirements
validate_custom_requirements() {
    # Add your custom validation logic here
    echo "Running custom validation..."
}

validate_custom_requirements
```

## Integration with CI/CD

### GitHub Actions Example
```yaml
name: Validate Configuration

on:
  pull_request:
    paths:
      - 'terraform/**'

jobs:
  validate:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3
      
      - name: Setup Terraform
        uses: hashicorp/setup-terraform@v2
        
      - name: Run Validation
        run: |
          cd terraform/examples/validation-scenarios
          ./run-all-validations.sh
```

### GitLab CI Example
```yaml
validate-terraform:
  stage: validate
  script:
    - cd terraform/examples/validation-scenarios
    - ./run-all-validations.sh
  only:
    changes:
      - terraform/**
```

## Best Practices

### 1. Always Validate Before Deployment
- Run validation scripts before any deployment
- Test configuration changes in development first
- Use automated validation in CI/CD pipelines

### 2. Environment-Specific Validation
- Create validation profiles for each environment
- Test with realistic data and configurations
- Validate against actual AWS resources

### 3. Comprehensive Testing
- Test both success and failure scenarios
- Validate edge cases and boundary conditions
- Include performance and security testing

### 4. Documentation
- Document validation requirements clearly
- Maintain up-to-date validation scripts
- Share validation results with team members

## Troubleshooting

### Debug Mode
Enable debug mode for detailed validation output:

```bash
export TF_LOG=DEBUG
export AWS_CLI_DEBUG=1
../../scripts/validate-deployment.sh
```

### Validation Logs
Check validation logs for detailed information:

```bash
# View validation log
cat /tmp/cloudflare-sg-validation.log

# View validation report
cat /tmp/cloudflare-sg-validation-report.txt
```

### Common Issues
1. **Network timeouts**: Check firewall and proxy settings
2. **Permission errors**: Verify AWS IAM permissions
3. **State conflicts**: Check Terraform state and locks
4. **Version mismatches**: Ensure compatible tool versions

## Contributing

To add new validation scenarios:

1. Create a new .tfvars file with your scenario
2. Add validation logic to test scripts
3. Update documentation
4. Test thoroughly
5. Submit pull request

## Support

For validation issues:

1. Check the troubleshooting section
2. Review validation logs
3. Test with minimal configuration
4. Contact team for assistance