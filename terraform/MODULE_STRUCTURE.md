# Terraform Module Structure

This document describes the organization and structure of the Cloudflare AWS Security Group Terraform module.

## Directory Structure

```
terraform/
├── README.md                           # Main module documentation
├── CHANGELOG.md                        # Version history and changes
├── MODULE_STRUCTURE.md                 # This file - module organization
├── .terraform-docs.yml                 # Configuration for terraform-docs
├── main.tf                            # Main module configuration
├── variables.tf                       # Input variable definitions
├── outputs.tf                         # Output value definitions
├── versions.tf                        # Provider version constraints
├── terraform.tfvars.example           # Example variable configurations
├── lambda_function.py                 # Lambda function source code
├── lambda_function.zip                # Lambda deployment package
├── requirements.txt                   # Python dependencies for Lambda
├── test_lambda.py                     # Lambda function tests
├── build_lambda.sh                    # Script to build Lambda package
└── examples/                          # Usage examples
    ├── README.md                      # Examples overview
    ├── basic/                         # Basic usage example
    │   ├── README.md                  # Basic example documentation
    │   └── main.tf                    # Basic example configuration
    └── advanced/                      # Advanced usage example
        ├── README.md                  # Advanced example documentation
        ├── main.tf                    # Advanced example configuration
        ├── variables.tf               # Advanced example variables
        ├── outputs.tf                 # Advanced example outputs
        └── terraform.tfvars.example   # Advanced example variable values
```

## File Descriptions

### Core Module Files

#### `main.tf`
- **Purpose**: Main Terraform configuration containing all resources
- **Contents**: 
  - Local values for data processing and tagging
  - HTTP data sources for Cloudflare IP ranges
  - AWS Security Group with dynamic ingress rules
  - Lambda function and related IAM resources
  - EventBridge scheduling configuration
  - CloudWatch monitoring and SNS notifications
- **Dependencies**: variables.tf, versions.tf

#### `variables.tf`
- **Purpose**: Input variable definitions with validation rules
- **Contents**:
  - Required variables (vpc_id)
  - Optional configuration variables with defaults
  - Terraform execution mode variables
  - Comprehensive validation rules
- **Validation**: Format validation for VPC IDs, emails, ports, protocols

#### `outputs.tf`
- **Purpose**: Output value definitions for module consumers
- **Contents**:
  - Security group information (ID, ARN, name)
  - Lambda function details
  - Monitoring resource information
  - Automation configuration status
- **Usage**: Allows other Terraform configurations to reference created resources

#### `versions.tf`
- **Purpose**: Provider version constraints and requirements
- **Contents**:
  - Terraform version requirement (>= 1.0)
  - AWS provider version constraint (~> 5.0)
  - HTTP, Archive, and Null provider constraints
- **Compatibility**: Ensures consistent provider behavior across deployments

### Documentation Files

#### `README.md`
- **Purpose**: Comprehensive module documentation
- **Contents**:
  - Module overview and features
  - Architecture diagrams
  - Usage examples and best practices
  - Input/output documentation
  - Troubleshooting guide
- **Audience**: Module users and contributors

#### `CHANGELOG.md`
- **Purpose**: Version history and change tracking
- **Contents**:
  - Semantic versioning information
  - Feature additions and changes
  - Bug fixes and security updates
  - Upgrade instructions
- **Format**: Follows Keep a Changelog standard

#### `MODULE_STRUCTURE.md`
- **Purpose**: Module organization documentation (this file)
- **Contents**:
  - Directory structure explanation
  - File purpose descriptions
  - Development guidelines
- **Audience**: Module developers and maintainers

### Configuration Files

#### `terraform.tfvars.example`
- **Purpose**: Example variable configurations for different scenarios
- **Contents**:
  - Basic deployment configuration
  - Production environment setup
  - Development environment setup
  - Terraform Cloud integration examples
  - Multi-protocol deployment examples
- **Usage**: Copy and customize for specific deployments

#### `.terraform-docs.yml`
- **Purpose**: Configuration for terraform-docs tool
- **Contents**:
  - Documentation generation settings
  - Output format configuration
  - Section organization preferences
- **Usage**: Automated documentation generation

### Lambda Function Files

#### `lambda_function.py`
- **Purpose**: Python source code for automated IP range updates
- **Contents**:
  - Cloudflare IP range retrieval logic
  - AWS Security Group update functionality
  - Error handling and retry logic
  - Terraform automation integration
- **Runtime**: Python 3.11

#### `lambda_function.zip`
- **Purpose**: Deployment package for Lambda function
- **Contents**: Compiled Python code and dependencies
- **Generation**: Created by build_lambda.sh script

#### `requirements.txt`
- **Purpose**: Python dependencies for Lambda function
- **Contents**: Required Python packages and versions
- **Usage**: Used by build script to install dependencies

#### `test_lambda.py`
- **Purpose**: Unit tests for Lambda function
- **Contents**: Test cases for various scenarios and error conditions
- **Framework**: Python unittest module

#### `build_lambda.sh`
- **Purpose**: Script to build Lambda deployment package
- **Contents**: Commands to install dependencies and create ZIP file
- **Usage**: Run before deploying to update Lambda code

### Examples Directory

#### `examples/README.md`
- **Purpose**: Overview of available examples
- **Contents**:
  - Example descriptions and use cases
  - Usage instructions
  - Configuration tips
  - Troubleshooting guidance

#### `examples/basic/`
- **Purpose**: Minimal configuration example
- **Files**:
  - `main.tf`: Basic module usage
  - `README.md`: Basic example documentation
- **Use Case**: Quick setup for standard web applications

#### `examples/advanced/`
- **Purpose**: Comprehensive configuration example
- **Files**:
  - `main.tf`: Advanced module usage with additional resources
  - `variables.tf`: Input variables for advanced example
  - `outputs.tf`: Output values for advanced example
  - `terraform.tfvars.example`: Example variable values
  - `README.md`: Advanced example documentation
- **Use Case**: Production environments with full monitoring

## Module Design Principles

### 1. Reusability
- Self-contained module with minimal external dependencies
- Configurable through input variables
- Consistent resource naming and tagging
- Compatible with different deployment scenarios

### 2. Maintainability
- Clear separation of concerns across files
- Comprehensive documentation and examples
- Version tracking and change management
- Automated testing and validation

### 3. Security
- Minimal IAM permissions for Lambda function
- Input validation for all user-provided values
- Secure handling of sensitive variables
- Network security best practices

### 4. Observability
- Comprehensive CloudWatch monitoring
- Structured logging in Lambda function
- Alerting for error conditions
- Operational dashboard for visibility

### 5. Flexibility
- Multiple deployment modes (direct, Terraform Cloud)
- Configurable automation schedules
- Customizable ports and protocols
- Extensible tagging system

## Development Guidelines

### Adding New Features
1. Update `main.tf` with new resources
2. Add corresponding variables to `variables.tf`
3. Include outputs in `outputs.tf`
4. Update documentation in `README.md`
5. Add examples if applicable
6. Update `CHANGELOG.md`

### Modifying Existing Features
1. Ensure backward compatibility
2. Update validation rules if needed
3. Modify examples to reflect changes
4. Update documentation
5. Test with both basic and advanced examples

### Version Management
1. Follow semantic versioning (MAJOR.MINOR.PATCH)
2. Update `CHANGELOG.md` with changes
3. Tag releases appropriately
4. Update compatibility information

### Testing
1. Validate Terraform syntax (`terraform validate`)
2. Format code consistently (`terraform fmt`)
3. Test with example configurations
4. Verify Lambda function tests pass
5. Check documentation generation

## Usage Patterns

### As a Git Submodule
```hcl
module "cloudflare_security_group" {
  source = "./modules/cloudflare-aws-security-group"
  # ... variables
}
```

### As a Git Repository Reference
```hcl
module "cloudflare_security_group" {
  source = "git::https://github.com/org/terraform-aws-cloudflare-security-group.git?ref=v1.0.0"
  # ... variables
}
```

### As a Terraform Registry Module
```hcl
module "cloudflare_security_group" {
  source  = "org/cloudflare-security-group/aws"
  version = "~> 1.0"
  # ... variables
}
```

## Maintenance Tasks

### Regular Maintenance
- Update provider version constraints as needed
- Review and update Lambda function dependencies
- Monitor Cloudflare API changes
- Update documentation for new AWS features

### Security Updates
- Review IAM permissions periodically
- Update Lambda runtime versions
- Monitor for security advisories
- Update dependency versions

### Performance Optimization
- Monitor Lambda function execution times
- Optimize CloudWatch log retention
- Review automation frequency
- Analyze cost implications

This module structure provides a solid foundation for a production-ready, reusable Terraform module that follows best practices and provides comprehensive functionality for managing Cloudflare IP whitelisting in AWS environments.