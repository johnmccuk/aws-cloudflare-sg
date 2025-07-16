# Multi-Environment Configuration Example

This example demonstrates how to configure the Cloudflare AWS Security Group module for multiple environments (development, staging, production) with environment-specific settings.

## Overview

This configuration shows best practices for:

- Environment-specific variable files
- Shared configuration with environment overrides
- Different automation schedules per environment
- Environment-appropriate monitoring and alerting
- Cost optimization strategies per environment

## Directory Structure

```
multi-environment/
├── README.md
├── main.tf                    # Shared configuration
├── variables.tf               # Variable definitions
├── outputs.tf                 # Output definitions
├── environments/
│   ├── development.tfvars     # Development environment
│   ├── staging.tfvars         # Staging environment
│   └── production.tfvars      # Production environment
└── scripts/
    ├── deploy-dev.sh          # Development deployment
    ├── deploy-staging.sh      # Staging deployment
    └── deploy-prod.sh         # Production deployment
```

## Environment Configurations

### Development Environment
- More frequent updates for testing (every 2 hours)
- Additional ports for development tools
- Shorter log retention
- Basic monitoring

### Staging Environment
- Production-like configuration
- Weekly updates to reduce costs
- Extended monitoring
- Notification to staging team

### Production Environment
- Conservative update schedule (daily)
- Comprehensive monitoring and alerting
- Long log retention for compliance
- Multiple notification channels

## Usage

### Deploy to Development
```bash
# Deploy development environment
./scripts/deploy-dev.sh

# Or manually
terraform workspace select development || terraform workspace new development
terraform plan -var-file="environments/development.tfvars"
terraform apply -var-file="environments/development.tfvars"
```

### Deploy to Staging
```bash
# Deploy staging environment
./scripts/deploy-staging.sh

# Or manually
terraform workspace select staging || terraform workspace new staging
terraform plan -var-file="environments/staging.tfvars"
terraform apply -var-file="environments/staging.tfvars"
```

### Deploy to Production
```bash
# Deploy production environment
./scripts/deploy-prod.sh

# Or manually
terraform workspace select production || terraform workspace new production
terraform plan -var-file="environments/production.tfvars"
terraform apply -var-file="environments/production.tfvars"
```

## Environment-Specific Features

### Development
- **Update Schedule**: Every 2 hours for rapid testing
- **Ports**: 80, 443, 8080, 3000 (includes dev server ports)
- **Monitoring**: Basic CloudWatch logs only
- **Notifications**: Developer email only
- **Cost**: Optimized for minimal cost

### Staging
- **Update Schedule**: Weekly to mirror production cadence
- **Ports**: 80, 443 (production-like)
- **Monitoring**: Full monitoring without detailed dashboards
- **Notifications**: Staging team distribution list
- **Cost**: Balanced between cost and functionality

### Production
- **Update Schedule**: Daily at 2 AM UTC
- **Ports**: 443 only (security-focused)
- **Monitoring**: Comprehensive monitoring with dashboards
- **Notifications**: Multiple channels (email, Slack, PagerDuty)
- **Cost**: Full functionality regardless of cost

## Configuration Management

### Shared Variables
Common settings across all environments are defined in `variables.tf` with sensible defaults.

### Environment Overrides
Each environment file (`environments/*.tfvars`) overrides only the necessary variables for that specific environment.

### Workspace Isolation
Each environment uses a separate Terraform workspace to maintain state isolation.

## Security Considerations

### Environment Separation
- Separate AWS accounts recommended for production
- Different IAM roles per environment
- Isolated VPCs and networking

### Secrets Management
- Use AWS Secrets Manager for sensitive values
- Environment-specific Terraform Cloud workspaces
- Separate API tokens per environment

### Access Control
- Restrict production deployments to authorized personnel
- Use approval workflows for production changes
- Audit all production modifications

## Monitoring Strategy

### Development
```hcl
# Minimal monitoring
notification_email = "developer@company.com"
log_retention_days = 7
enable_detailed_monitoring = false
```

### Staging
```hcl
# Production-like monitoring
notification_email = "staging-team@company.com"
log_retention_days = 30
enable_detailed_monitoring = true
create_dashboard = false
```

### Production
```hcl
# Comprehensive monitoring
notification_email = "ops-team@company.com"
log_retention_days = 90
enable_detailed_monitoring = true
create_dashboard = true
enable_pagerduty = true
```

## Cost Optimization

### Development Environment
- Lambda: 128MB memory, 1-minute timeout
- Logs: 7-day retention
- Updates: Every 2 hours (for testing)
- Monitoring: Basic only

**Estimated Monthly Cost**: < $2

### Staging Environment
- Lambda: 256MB memory, 3-minute timeout
- Logs: 30-day retention
- Updates: Weekly
- Monitoring: Standard

**Estimated Monthly Cost**: < $5

### Production Environment
- Lambda: 512MB memory, 5-minute timeout
- Logs: 90-day retention
- Updates: Daily
- Monitoring: Comprehensive

**Estimated Monthly Cost**: < $15

## Deployment Automation

### CI/CD Pipeline Example

```yaml
# .github/workflows/deploy.yml
name: Deploy Cloudflare Security Group

on:
  push:
    branches:
      - main
      - staging
      - development

jobs:
  deploy:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3
      
      - name: Setup Terraform
        uses: hashicorp/setup-terraform@v2
        with:
          terraform_version: 1.6.0
          
      - name: Deploy to Development
        if: github.ref == 'refs/heads/development'
        run: |
          cd terraform/examples/multi-environment
          terraform init
          terraform workspace select development || terraform workspace new development
          terraform plan -var-file="environments/development.tfvars"
          terraform apply -auto-approve -var-file="environments/development.tfvars"
          
      - name: Deploy to Staging
        if: github.ref == 'refs/heads/staging'
        run: |
          cd terraform/examples/multi-environment
          terraform init
          terraform workspace select staging || terraform workspace new staging
          terraform plan -var-file="environments/staging.tfvars"
          terraform apply -auto-approve -var-file="environments/staging.tfvars"
          
      - name: Deploy to Production
        if: github.ref == 'refs/heads/main'
        run: |
          cd terraform/examples/multi-environment
          terraform init
          terraform workspace select production || terraform workspace new production
          terraform plan -var-file="environments/production.tfvars"
          # Production requires manual approval
          terraform apply -var-file="environments/production.tfvars"
```

## Testing Strategy

### Development Testing
```bash
# Test configuration changes
terraform plan -var-file="environments/development.tfvars"

# Test Lambda function
aws lambda invoke \
    --function-name cloudflare-ip-updater-development \
    --payload '{"source": "test"}' \
    response.json

# Verify security group rules
aws ec2 describe-security-groups \
    --group-ids $(terraform output -raw security_group_id)
```

### Staging Validation
```bash
# Validate staging matches production config
diff environments/staging.tfvars environments/production.tfvars

# Test automation end-to-end
./scripts/test-automation.sh staging

# Performance testing
./scripts/load-test.sh staging
```

### Production Readiness
```bash
# Pre-production checklist
./scripts/production-readiness-check.sh

# Backup current state
terraform state pull > backup-$(date +%Y%m%d).tfstate

# Deploy with extra validation
terraform plan -detailed-exitcode -var-file="environments/production.tfvars"
```

## Troubleshooting

### Environment-Specific Issues

1. **Wrong Environment Deployed**
   ```bash
   # Check current workspace
   terraform workspace show
   
   # Switch to correct workspace
   terraform workspace select production
   ```

2. **Configuration Drift Between Environments**
   ```bash
   # Compare configurations
   diff environments/staging.tfvars environments/production.tfvars
   
   # Validate consistency
   ./scripts/validate-environments.sh
   ```

3. **State File Conflicts**
   ```bash
   # List workspaces
   terraform workspace list
   
   # Check state
   terraform state list
   
   # Fix state issues
   terraform state rm aws_security_group.duplicate
   ```

## Maintenance

### Regular Tasks

1. **Weekly**: Review development environment for issues
2. **Monthly**: Update staging to match production configuration
3. **Quarterly**: Review and optimize costs across environments
4. **Annually**: Audit security configurations and access

### Updates

```bash
# Update all environments
for env in development staging production; do
    terraform workspace select $env
    terraform plan -var-file="environments/${env}.tfvars"
    terraform apply -var-file="environments/${env}.tfvars"
done
```

## Best Practices

1. **Always test in development first**
2. **Use staging as production validation**
3. **Never skip production approval processes**
4. **Monitor costs across all environments**
5. **Keep environment configurations in sync where appropriate**
6. **Document all environment-specific decisions**
7. **Use infrastructure as code for all changes**
8. **Implement proper backup and recovery procedures**