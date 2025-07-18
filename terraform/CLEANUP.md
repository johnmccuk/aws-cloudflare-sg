# Cloudflare IP Updater - Cleanup and Destroy Functionality

This document describes the comprehensive cleanup and destroy functionality implemented for the Cloudflare IP updater infrastructure.

## Overview

The cleanup functionality ensures that all AWS resources created by this Terraform module are properly cleaned up during destroy operations, preventing resource dependencies and ensuring complete infrastructure teardown.

## Cleanup Components

### 1. Terraform Cleanup Configuration (`cleanup.tf`)

The main cleanup configuration includes:

- **Pre-destroy provisioners**: Execute cleanup operations before Terraform destroys resources
- **Post-destroy verification**: Validate that cleanup operations completed successfully
- **Cleanup Lambda function**: Automated cleanup operations for complex scenarios
- **Resource tagging**: Comprehensive tagging for resource identification during cleanup

### 2. Cleanup Scripts

#### Main Cleanup Script (`scripts/cleanup.sh`)
- Comprehensive bash script for cleanup operations
- Handles EventBridge rule disabling
- Manages security group rule cleanup
- Cleans up SNS subscriptions
- Validates cleanup completion

#### Validation Script (`scripts/validate-cleanup.sh`)
- Validates that all resources are properly tagged for cleanup
- Checks cleanup script availability and permissions
- Generates cleanup validation reports
- Verifies Terraform cleanup configuration

### 3. Lambda Cleanup Function (`cleanup_function.py`)

Automated cleanup operations including:
- Security group rule cleanup
- EventBridge rule management
- SNS subscription cleanup
- CloudWatch resource cleanup
- Resource state validation

## Resource Tagging Strategy

All resources are tagged with comprehensive cleanup identification tags:

```hcl
{
  CleanupGroup         = "cloudflare-ip-updater-${environment}"
  TerraformManaged     = "true"
  AutoCleanup          = "enabled"
  CleanupPriority      = "high"
  ResourceIdentifier   = "cloudflare-ip-updater"
  CleanupEnabled       = "true"
  CleanupMethod        = "automated"
  CleanupScript        = "cleanup.sh"
  DeploymentId         = "cloudflare-${environment}"
  ServiceName          = "cloudflare-ip-automation"
}
```

## Cleanup Process

### Automatic Cleanup (Terraform Destroy)

1. **Pre-destroy Phase**:
   - Disable EventBridge rules to prevent new Lambda executions
   - Wait for running Lambda executions to complete
   - Clean up security group rules to avoid dependency conflicts
   - Remove SNS subscriptions
   - Execute comprehensive cleanup script

2. **Terraform Destroy Phase**:
   - Terraform destroys resources in proper dependency order
   - Resources are cleaned up based on their dependency relationships

3. **Post-destroy Verification**:
   - Validate that key resources have been properly cleaned up
   - Generate cleanup completion reports

### Manual Cleanup

You can also trigger manual cleanup operations:

```bash
# Execute main cleanup script
./terraform/scripts/cleanup.sh <environment> <security_group_id> <lambda_function> <eventbridge_rule> <sns_topic> <log_group> <cleanup_tag> <aws_region>

# Validate cleanup configuration
./terraform/scripts/validate-cleanup.sh <environment> <aws_region>
```

### Lambda-based Cleanup

The cleanup Lambda function can be invoked for specific cleanup operations:

```json
{
  "source": "terraform.destroy",
  "cleanup_type": "terraform_destroy",
  "environment": "prod"
}
```

## Cleanup Operations

### Security Group Cleanup
- Removes all ingress rules from Cloudflare IP security groups
- Preserves default egress rules
- Handles multiple security groups if configured

### EventBridge Cleanup
- Disables EventBridge rules to prevent new executions
- Removes targets from rules
- Validates rule state after cleanup

### SNS Cleanup
- Unsubscribes all active subscriptions from SNS topics
- Handles pending confirmations gracefully
- Validates subscription cleanup

### CloudWatch Cleanup
- Removes CloudWatch alarms related to the automation
- Cleans up CloudWatch dashboards
- Handles log group cleanup for old streams

### Lambda Cleanup
- Updates Lambda function configurations to remove resource references
- Waits for running executions to complete
- Validates function state after cleanup

## Validation and Monitoring

### Cleanup Validation
- Validates that all resources have required cleanup tags
- Checks cleanup script availability and permissions
- Verifies Terraform cleanup configuration
- Generates comprehensive validation reports

### Monitoring
- CloudWatch logs for all cleanup operations
- SNS notifications for cleanup status
- Detailed cleanup operation results
- Error handling and retry logic

## Best Practices

### Before Destroy
1. **Validate Configuration**: Run the validation script to ensure all resources are properly tagged
2. **Check Dependencies**: Verify that no external resources depend on the infrastructure
3. **Backup Important Data**: Ensure any important logs or configurations are backed up

### During Destroy
1. **Monitor Progress**: Watch CloudWatch logs for cleanup operation progress
2. **Handle Errors**: Address any cleanup errors before proceeding with destroy
3. **Verify Completion**: Ensure all cleanup operations complete successfully

### After Destroy
1. **Validate Cleanup**: Run post-destroy validation to confirm resource cleanup
2. **Check Billing**: Verify that all resources have been removed from AWS billing
3. **Update Documentation**: Update any documentation that references the destroyed infrastructure

## Troubleshooting

### Common Issues

#### Security Group Dependencies
- **Issue**: Security group cannot be deleted due to dependencies
- **Solution**: The cleanup script removes all rules before Terraform destroy

#### Lambda Execution Conflicts
- **Issue**: Lambda functions still running during destroy
- **Solution**: EventBridge rules are disabled and wait periods are implemented

#### SNS Subscription Conflicts
- **Issue**: SNS topics cannot be deleted due to active subscriptions
- **Solution**: All subscriptions are automatically unsubscribed during cleanup

### Error Recovery

If cleanup fails:

1. **Check Logs**: Review CloudWatch logs for detailed error information
2. **Manual Cleanup**: Use the manual cleanup scripts to address specific issues
3. **Retry Operations**: Most cleanup operations are idempotent and can be retried
4. **Contact Support**: For persistent issues, contact AWS support

## Configuration Options

### Cleanup Behavior
- `enable_automation`: Controls whether cleanup Lambda function is deployed
- `cleanup_mode`: Configures cleanup behavior (graceful, aggressive, etc.)

### Validation Settings
- Cleanup tag validation
- Resource dependency checking
- Script availability verification

### Monitoring Configuration
- CloudWatch log retention for cleanup operations
- SNS notification settings for cleanup status
- Alarm configuration for cleanup failures

## Security Considerations

### IAM Permissions
The cleanup Lambda function requires specific IAM permissions:
- EC2: Security group management
- Events: EventBridge rule management
- SNS: Subscription management
- CloudWatch: Resource cleanup
- Logs: Log stream management

### Resource Access
- Cleanup operations are scoped to resources with specific tags
- Cross-account access is not supported
- Regional resource cleanup only

## Integration with CI/CD

### Automated Deployment
- Include cleanup validation in deployment pipelines
- Verify cleanup configuration before production deployment
- Test cleanup procedures in staging environments

### Monitoring Integration
- Integrate cleanup status with monitoring systems
- Set up alerts for cleanup failures
- Include cleanup metrics in operational dashboards

## Support and Maintenance

### Regular Maintenance
- Review cleanup logs regularly
- Update cleanup scripts as needed
- Validate cleanup configuration after infrastructure changes

### Version Updates
- Test cleanup functionality with new Terraform versions
- Update cleanup scripts for new AWS service features
- Maintain compatibility with AWS API changes

For additional support or questions about the cleanup functionality, refer to the main module documentation or contact the infrastructure team.