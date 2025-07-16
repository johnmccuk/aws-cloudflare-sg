# Changelog

All notable changes to this Terraform module will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
- Initial release of Cloudflare AWS Security Group Terraform module
- Automatic retrieval of Cloudflare IPv4 and IPv6 IP ranges
- Dynamic AWS Security Group creation with ingress rules
- Lambda function for automated IP range updates
- EventBridge scheduling for periodic updates
- Comprehensive CloudWatch monitoring and alerting
- SNS notifications for update status
- Support for both Terraform Cloud and direct execution modes
- Configurable ports, protocols, and update schedules
- Input validation for all variables
- Comprehensive documentation and examples

### Features
- **Security Group Management**: Automatically creates and maintains AWS Security Group with Cloudflare IP ranges
- **Automation**: Lambda function triggered by EventBridge for scheduled updates
- **Monitoring**: CloudWatch alarms, logs, and dashboard for comprehensive monitoring
- **Notifications**: SNS email notifications for update status and errors
- **Flexibility**: Configurable ports, protocols, schedules, and execution modes
- **Validation**: Input validation for VPC IDs, ports, protocols, and email addresses
- **Tagging**: Consistent resource tagging with customizable additional tags

### Documentation
- Complete README.md with usage examples and configuration options
- Terraform.tfvars.example with multiple deployment scenarios
- Basic and advanced example configurations
- Troubleshooting guide and best practices
- Module development and contribution guidelines

## [1.0.0] - 2025-01-15

### Added
- Initial stable release
- Production-ready Terraform module for Cloudflare IP whitelisting
- Comprehensive automation and monitoring capabilities
- Full documentation and examples

### Security
- Minimal IAM permissions for Lambda function
- Input validation for all user-provided variables
- Secure handling of sensitive variables (Terraform Cloud tokens)
- Network security with specific port and protocol restrictions

### Infrastructure
- AWS Security Group with dynamic ingress rules
- Lambda function for automated updates (Python 3.11)
- EventBridge rule for scheduled execution
- CloudWatch log group with 14-day retention
- SNS topic and subscription for notifications
- CloudWatch alarms for error monitoring
- CloudWatch dashboard for operational visibility

### Compatibility
- Terraform >= 1.0
- AWS Provider ~> 5.0
- HTTP Provider ~> 3.0
- Archive Provider ~> 2.0
- Null Provider ~> 3.0

---

## Version History

### Version Numbering
This module follows semantic versioning:
- **MAJOR**: Incompatible API changes
- **MINOR**: Backwards-compatible functionality additions
- **PATCH**: Backwards-compatible bug fixes

### Upgrade Path
When upgrading between versions:
1. Review the changelog for breaking changes
2. Update your module source reference
3. Run `terraform plan` to review changes
4. Apply changes in a controlled manner

### Support Policy
- **Current Version**: Full support and active development
- **Previous Major Version**: Security updates and critical bug fixes
- **Older Versions**: Community support only

---

## Contributing

To contribute to this changelog:
1. Add entries under the "Unreleased" section
2. Use the categories: Added, Changed, Deprecated, Removed, Fixed, Security
3. Include relevant details and context for changes
4. Move entries to a version section when releasing