#!/bin/bash

# Cloudflare AWS Security Group - Pre-deployment Validation Script
# This script validates the configuration and environment before deployment

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Configuration
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
TERRAFORM_DIR="$(dirname "$SCRIPT_DIR")"
REQUIRED_TERRAFORM_VERSION="1.5.0"
VALIDATION_LOG="/tmp/cloudflare-sg-validation.log"

# Initialize log file
echo "Cloudflare AWS Security Group - Validation Log" > "$VALIDATION_LOG"
echo "Started at: $(date)" >> "$VALIDATION_LOG"
echo "----------------------------------------" >> "$VALIDATION_LOG"

# Helper functions
log_info() {
    echo -e "${BLUE}[INFO]${NC} $1"
    echo "[INFO] $1" >> "$VALIDATION_LOG"
}

log_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
    echo "[SUCCESS] $1" >> "$VALIDATION_LOG"
}

log_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
    echo "[WARNING] $1" >> "$VALIDATION_LOG"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1"
    echo "[ERROR] $1" >> "$VALIDATION_LOG"
}

check_command() {
    if command -v "$1" &> /dev/null; then
        log_success "$1 is installed"
        return 0
    else
        log_error "$1 is not installed or not in PATH"
        return 1
    fi
}

version_compare() {
    # Compare version strings (returns 0 if $1 >= $2)
    printf '%s\n%s\n' "$2" "$1" | sort -V -C
}

# Main validation functions
validate_prerequisites() {
    log_info "Validating prerequisites..."
    
    local errors=0
    
    # Check required commands
    if ! check_command "terraform"; then
        errors=$((errors + 1))
    else
        # Check Terraform version
        local terraform_version
        terraform_version=$(terraform version -json | jq -r '.terraform_version' 2>/dev/null || terraform version | head -n1 | cut -d' ' -f2 | sed 's/v//')
        
        if version_compare "$terraform_version" "$REQUIRED_TERRAFORM_VERSION"; then
            log_success "Terraform version $terraform_version meets requirement (>= $REQUIRED_TERRAFORM_VERSION)"
        else
            log_error "Terraform version $terraform_version is below required version $REQUIRED_TERRAFORM_VERSION"
            errors=$((errors + 1))
        fi
    fi
    
    if ! check_command "aws"; then
        errors=$((errors + 1))
    else
        # Check AWS CLI configuration
        if aws sts get-caller-identity &> /dev/null; then
            local account_id
            account_id=$(aws sts get-caller-identity --query Account --output text)
            log_success "AWS CLI configured for account: $account_id"
        else
            log_error "AWS CLI not configured or credentials invalid"
            errors=$((errors + 1))
        fi
    fi
    
    if ! check_command "curl"; then
        log_warning "curl not found - some network tests will be skipped"
    fi
    
    if ! check_command "jq"; then
        log_warning "jq not found - JSON parsing will be limited"
    fi
    
    return $errors
}

validate_terraform_configuration() {
    log_info "Validating Terraform configuration..."
    
    local errors=0
    
    # Change to Terraform directory
    cd "$TERRAFORM_DIR"
    
    # Check if terraform files exist
    if [[ ! -f "main.tf" ]]; then
        log_error "main.tf not found in $TERRAFORM_DIR"
        errors=$((errors + 1))
    fi
    
    if [[ ! -f "variables.tf" ]]; then
        log_error "variables.tf not found in $TERRAFORM_DIR"
        errors=$((errors + 1))
    fi
    
    # Initialize Terraform (if not already initialized)
    if [[ ! -d ".terraform" ]]; then
        log_info "Initializing Terraform..."
        if terraform init -input=false >> "$VALIDATION_LOG" 2>&1; then
            log_success "Terraform initialized successfully"
        else
            log_error "Terraform initialization failed"
            errors=$((errors + 1))
            return $errors
        fi
    fi
    
    # Validate Terraform configuration
    if terraform validate >> "$VALIDATION_LOG" 2>&1; then
        log_success "Terraform configuration is valid"
    else
        log_error "Terraform configuration validation failed"
        errors=$((errors + 1))
    fi
    
    # Format check
    if terraform fmt -check >> "$VALIDATION_LOG" 2>&1; then
        log_success "Terraform files are properly formatted"
    else
        log_warning "Terraform files need formatting (run 'terraform fmt')"
    fi
    
    return $errors
}

validate_aws_permissions() {
    log_info "Validating AWS permissions..."
    
    local errors=0
    local required_actions=(
        "ec2:DescribeVpcs"
        "ec2:DescribeSecurityGroups"
        "ec2:CreateSecurityGroup"
        "ec2:AuthorizeSecurityGroupIngress"
        "lambda:CreateFunction"
        "iam:CreateRole"
        "events:PutRule"
        "logs:CreateLogGroup"
        "sns:CreateTopic"
    )
    
    # Test basic AWS access
    if ! aws sts get-caller-identity &> /dev/null; then
        log_error "Cannot access AWS - check credentials"
        return 1
    fi
    
    # Get current region
    local region
    region=$(aws configure get region 2>/dev/null || echo "us-west-2")
    log_info "Using AWS region: $region"
    
    # Test VPC access (if VPC_ID is set)
    if [[ -n "${VPC_ID:-}" ]]; then
        if aws ec2 describe-vpcs --vpc-ids "$VPC_ID" &> /dev/null; then
            log_success "VPC $VPC_ID is accessible"
        else
            log_error "Cannot access VPC $VPC_ID"
            errors=$((errors + 1))
        fi
    else
        log_warning "VPC_ID not set - skipping VPC validation"
    fi
    
    # Test S3 access (if buckets are specified)
    if [[ -n "${TERRAFORM_STATE_S3_BUCKET:-}" ]]; then
        if aws s3 ls "s3://$TERRAFORM_STATE_S3_BUCKET" &> /dev/null; then
            log_success "S3 bucket $TERRAFORM_STATE_S3_BUCKET is accessible"
        else
            log_error "Cannot access S3 bucket $TERRAFORM_STATE_S3_BUCKET"
            errors=$((errors + 1))
        fi
    fi
    
    return $errors
}

validate_network_connectivity() {
    log_info "Validating network connectivity..."
    
    local errors=0
    
    # Test Cloudflare API endpoints
    local cloudflare_ipv4_url="https://www.cloudflare.com/ips-v4"
    local cloudflare_ipv6_url="https://www.cloudflare.com/ips-v6"
    
    if command -v curl &> /dev/null; then
        if curl -s --max-time 10 "$cloudflare_ipv4_url" > /dev/null; then
            log_success "Cloudflare IPv4 API is accessible"
        else
            log_error "Cannot access Cloudflare IPv4 API at $cloudflare_ipv4_url"
            errors=$((errors + 1))
        fi
        
        if curl -s --max-time 10 "$cloudflare_ipv6_url" > /dev/null; then
            log_success "Cloudflare IPv6 API is accessible"
        else
            log_error "Cannot access Cloudflare IPv6 API at $cloudflare_ipv6_url"
            errors=$((errors + 1))
        fi
        
        # Test AWS API endpoints
        local aws_region
        aws_region=$(aws configure get region 2>/dev/null || echo "us-west-2")
        local ec2_endpoint="https://ec2.$aws_region.amazonaws.com"
        
        if curl -s --max-time 10 "$ec2_endpoint" > /dev/null; then
            log_success "AWS EC2 API endpoint is accessible"
        else
            log_warning "AWS EC2 API endpoint may not be accessible (this might be normal)"
        fi
    else
        log_warning "curl not available - skipping network connectivity tests"
    fi
    
    return $errors
}

validate_terraform_cloud_config() {
    log_info "Validating Terraform Cloud configuration (if applicable)..."
    
    local errors=0
    
    # Check if Terraform Cloud variables are set
    if [[ -n "${TERRAFORM_CLOUD_TOKEN:-}" ]]; then
        log_info "Terraform Cloud token is set"
        
        if [[ -n "${TERRAFORM_ORGANIZATION:-}" ]]; then
            log_success "Terraform organization is set: $TERRAFORM_ORGANIZATION"
        else
            log_error "TERRAFORM_ORGANIZATION not set but TERRAFORM_CLOUD_TOKEN is provided"
            errors=$((errors + 1))
        fi
        
        if [[ -n "${TERRAFORM_WORKSPACE:-}" ]]; then
            log_success "Terraform workspace is set: $TERRAFORM_WORKSPACE"
        else
            log_error "TERRAFORM_WORKSPACE not set but TERRAFORM_CLOUD_TOKEN is provided"
            errors=$((errors + 1))
        fi
        
        # Test Terraform Cloud API access
        if command -v curl &> /dev/null; then
            local tfc_api_url="https://app.terraform.io/api/v2/account/details"
            if curl -s -H "Authorization: Bearer $TERRAFORM_CLOUD_TOKEN" "$tfc_api_url" > /dev/null; then
                log_success "Terraform Cloud API is accessible"
            else
                log_error "Cannot access Terraform Cloud API - check token"
                errors=$((errors + 1))
            fi
        fi
    else
        log_info "Terraform Cloud token not set - assuming local execution"
    fi
    
    return $errors
}

validate_configuration_files() {
    log_info "Validating configuration files..."
    
    local errors=0
    
    cd "$TERRAFORM_DIR"
    
    # Check for terraform.tfvars or terraform.tfvars.json
    if [[ -f "terraform.tfvars" ]] || [[ -f "terraform.tfvars.json" ]]; then
        log_success "Terraform variables file found"
        
        # Basic validation of required variables
        if [[ -f "terraform.tfvars" ]]; then
            if grep -q "vpc_id" terraform.tfvars; then
                log_success "vpc_id variable is set"
            else
                log_warning "vpc_id variable not found in terraform.tfvars"
            fi
        fi
    else
        log_warning "No terraform.tfvars file found - variables must be provided via other means"
    fi
    
    # Check example files exist
    local example_dirs=("examples/basic" "examples/advanced" "examples/terraform-cloud" "examples/local-execution")
    for dir in "${example_dirs[@]}"; do
        if [[ -d "$dir" ]]; then
            log_success "Example directory exists: $dir"
        else
            log_warning "Example directory missing: $dir"
        fi
    done
    
    return $errors
}

generate_validation_report() {
    log_info "Generating validation report..."
    
    local report_file="/tmp/cloudflare-sg-validation-report.txt"
    
    cat > "$report_file" << EOF
Cloudflare AWS Security Group - Validation Report
================================================
Generated at: $(date)

Environment Information:
- Operating System: $(uname -s)
- Terraform Version: $(terraform version | head -n1 | cut -d' ' -f2 2>/dev/null || "Not available")
- AWS CLI Version: $(aws --version 2>/dev/null | cut -d' ' -f1 || "Not available")
- AWS Account: $(aws sts get-caller-identity --query Account --output text 2>/dev/null || "Not available")
- AWS Region: $(aws configure get region 2>/dev/null || "Not configured")

Configuration Status:
- Terraform Cloud Token: $([ -n "${TERRAFORM_CLOUD_TOKEN:-}" ] && echo "Set" || echo "Not set")
- VPC ID: ${VPC_ID:-"Not set"}
- Environment: ${ENVIRONMENT:-"Not set"}

Validation Results:
$(cat "$VALIDATION_LOG" | grep -E "\[(SUCCESS|ERROR|WARNING)\]" | sort)

Full Log:
$(cat "$VALIDATION_LOG")
EOF
    
    log_success "Validation report generated: $report_file"
    echo -e "\n${BLUE}Validation Report Location:${NC} $report_file"
}

print_next_steps() {
    echo -e "\n${BLUE}Next Steps:${NC}"
    echo "1. Review the validation report for any errors or warnings"
    echo "2. Fix any configuration issues identified"
    echo "3. Set required environment variables:"
    echo "   export VPC_ID='vpc-xxxxxxxxx'"
    echo "   export ENVIRONMENT='development'"
    echo "4. Run terraform plan to preview changes"
    echo "5. Run terraform apply to deploy the infrastructure"
    echo ""
    echo "For Terraform Cloud:"
    echo "   export TERRAFORM_CLOUD_TOKEN='your-token'"
    echo "   export TERRAFORM_ORGANIZATION='your-org'"
    echo "   export TERRAFORM_WORKSPACE='your-workspace'"
    echo ""
    echo "Example deployment commands:"
    echo "   cd $TERRAFORM_DIR"
    echo "   terraform plan -var=\"vpc_id=\$VPC_ID\" -var=\"environment=\$ENVIRONMENT\""
    echo "   terraform apply -var=\"vpc_id=\$VPC_ID\" -var=\"environment=\$ENVIRONMENT\""
}

# Main execution
main() {
    echo -e "${BLUE}Cloudflare AWS Security Group - Pre-deployment Validation${NC}"
    echo "========================================================"
    
    local total_errors=0
    
    # Run all validation checks
    validate_prerequisites || total_errors=$((total_errors + $?))
    validate_terraform_configuration || total_errors=$((total_errors + $?))
    validate_aws_permissions || total_errors=$((total_errors + $?))
    validate_network_connectivity || total_errors=$((total_errors + $?))
    validate_terraform_cloud_config || total_errors=$((total_errors + $?))
    validate_configuration_files || total_errors=$((total_errors + $?))
    
    # Generate report
    generate_validation_report
    
    # Print summary
    echo -e "\n${BLUE}Validation Summary:${NC}"
    if [[ $total_errors -eq 0 ]]; then
        log_success "All validation checks passed! Ready for deployment."
    else
        log_error "Validation completed with $total_errors error(s). Please fix issues before deployment."
    fi
    
    print_next_steps
    
    return $total_errors
}

# Handle script arguments
case "${1:-}" in
    --help|-h)
        echo "Usage: $0 [options]"
        echo ""
        echo "Options:"
        echo "  --help, -h     Show this help message"
        echo "  --quiet, -q    Suppress non-error output"
        echo ""
        echo "Environment Variables:"
        echo "  VPC_ID                    AWS VPC ID for validation"
        echo "  ENVIRONMENT              Environment name (dev, staging, prod)"
        echo "  TERRAFORM_CLOUD_TOKEN    Terraform Cloud API token"
        echo "  TERRAFORM_ORGANIZATION   Terraform Cloud organization"
        echo "  TERRAFORM_WORKSPACE      Terraform Cloud workspace"
        echo "  TERRAFORM_STATE_S3_BUCKET S3 bucket for state storage"
        exit 0
        ;;
    --quiet|-q)
        exec > /dev/null
        ;;
esac

# Run main function
main "$@"