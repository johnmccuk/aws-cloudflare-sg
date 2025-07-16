#!/bin/bash

# Development Environment Deployment Script
# This script deploys the Cloudflare AWS Security Group to the development environment

set -e

# Configuration
ENVIRONMENT="development"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"
TFVARS_FILE="environments/${ENVIRONMENT}.tfvars"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

log_info() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

log_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

log_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# Change to project directory
cd "$PROJECT_DIR"

log_info "Deploying Cloudflare AWS Security Group to Development Environment"
echo "=================================================================="

# Validate prerequisites
log_info "Validating prerequisites..."

if ! command -v terraform &> /dev/null; then
    log_error "Terraform is not installed or not in PATH"
    exit 1
fi

if ! command -v aws &> /dev/null; then
    log_error "AWS CLI is not installed or not in PATH"
    exit 1
fi

# Check AWS credentials
if ! aws sts get-caller-identity &> /dev/null; then
    log_error "AWS credentials not configured or invalid"
    exit 1
fi

log_success "Prerequisites validated"

# Check if tfvars file exists
if [[ ! -f "$TFVARS_FILE" ]]; then
    log_error "Configuration file not found: $TFVARS_FILE"
    log_info "Please copy and customize the example file:"
    log_info "cp environments/development.tfvars.example $TFVARS_FILE"
    exit 1
fi

# Initialize Terraform
log_info "Initializing Terraform..."
if terraform init; then
    log_success "Terraform initialized"
else
    log_error "Terraform initialization failed"
    exit 1
fi

# Select or create workspace
log_info "Setting up Terraform workspace: $ENVIRONMENT"
if terraform workspace select "$ENVIRONMENT" 2>/dev/null; then
    log_success "Switched to existing workspace: $ENVIRONMENT"
else
    log_info "Creating new workspace: $ENVIRONMENT"
    if terraform workspace new "$ENVIRONMENT"; then
        log_success "Created new workspace: $ENVIRONMENT"
    else
        log_error "Failed to create workspace: $ENVIRONMENT"
        exit 1
    fi
fi

# Validate configuration
log_info "Validating Terraform configuration..."
if terraform validate; then
    log_success "Configuration is valid"
else
    log_error "Configuration validation failed"
    exit 1
fi

# Plan deployment
log_info "Planning deployment..."
if terraform plan -var-file="$TFVARS_FILE" -out=tfplan; then
    log_success "Plan completed successfully"
else
    log_error "Planning failed"
    exit 1
fi

# Ask for confirmation (can be skipped with --auto-approve)
if [[ "$1" != "--auto-approve" ]]; then
    echo ""
    log_warning "This will deploy to the DEVELOPMENT environment"
    read -p "Do you want to continue? (y/N): " -n 1 -r
    echo ""
    if [[ ! $REPLY =~ ^[Yy]$ ]]; then
        log_info "Deployment cancelled"
        rm -f tfplan
        exit 0
    fi
fi

# Apply deployment
log_info "Applying deployment..."
if terraform apply tfplan; then
    log_success "Deployment completed successfully"
else
    log_error "Deployment failed"
    rm -f tfplan
    exit 1
fi

# Clean up plan file
rm -f tfplan

# Display outputs
log_info "Deployment outputs:"
terraform output

# Post-deployment validation
log_info "Running post-deployment validation..."

# Get security group ID
SECURITY_GROUP_ID=$(terraform output -raw security_group_id 2>/dev/null || echo "")
if [[ -n "$SECURITY_GROUP_ID" ]]; then
    log_success "Security group created: $SECURITY_GROUP_ID"
    
    # Verify security group exists
    if aws ec2 describe-security-groups --group-ids "$SECURITY_GROUP_ID" &>/dev/null; then
        log_success "Security group is accessible in AWS"
    else
        log_warning "Security group not found in AWS (may take a moment to propagate)"
    fi
else
    log_warning "Could not retrieve security group ID from outputs"
fi

# Get Lambda function name
LAMBDA_FUNCTION_NAME=$(terraform output -raw lambda_function_name 2>/dev/null || echo "")
if [[ -n "$LAMBDA_FUNCTION_NAME" ]]; then
    log_success "Lambda function created: $LAMBDA_FUNCTION_NAME"
    
    # Test Lambda function
    log_info "Testing Lambda function..."
    if aws lambda invoke \
        --function-name "$LAMBDA_FUNCTION_NAME" \
        --payload '{"source": "deployment-test", "test": true}' \
        /tmp/lambda-response.json &>/dev/null; then
        log_success "Lambda function test completed"
    else
        log_warning "Lambda function test failed (this may be normal for first deployment)"
    fi
else
    log_warning "Could not retrieve Lambda function name from outputs"
fi

# Development-specific post-deployment tasks
log_info "Running development-specific tasks..."

# Set up local development helpers
cat > /tmp/dev-helpers.sh << 'EOF'
#!/bin/bash
# Development helper functions

# Function to trigger Lambda manually
trigger_lambda() {
    local function_name="$1"
    aws lambda invoke \
        --function-name "$function_name" \
        --payload '{"source": "manual-trigger", "debug": true}' \
        /tmp/lambda-response.json
    cat /tmp/lambda-response.json
}

# Function to view Lambda logs
view_logs() {
    local function_name="$1"
    aws logs tail "/aws/lambda/$function_name" --follow
}

# Function to check security group rules
check_sg_rules() {
    local sg_id="$1"
    aws ec2 describe-security-groups --group-ids "$sg_id" \
        --query 'SecurityGroups[0].IpPermissions[*].[FromPort,ToPort,IpProtocol,IpRanges[*].CidrIp]' \
        --output table
}

echo "Development helper functions loaded:"
echo "  trigger_lambda <function-name>"
echo "  view_logs <function-name>"
echo "  check_sg_rules <security-group-id>"
EOF

log_success "Development helper script created: /tmp/dev-helpers.sh"
log_info "Source it with: source /tmp/dev-helpers.sh"

# Final summary
echo ""
log_success "Development deployment completed successfully!"
echo ""
echo "Next steps:"
echo "1. Test the security group with your application"
echo "2. Monitor Lambda function logs for any issues"
echo "3. Verify automation is working as expected"
echo "4. Use helper functions for development tasks"
echo ""
echo "Useful commands:"
echo "  terraform output                    # View all outputs"
echo "  terraform show                      # View current state"
echo "  terraform destroy -var-file=$TFVARS_FILE  # Clean up resources"
echo ""
echo "Development environment is ready for testing!"