#!/bin/bash

# Validation script for Cloudflare IP updater cleanup functionality
# This script validates that all resources are properly tagged and cleanup mechanisms are in place

set -e

# Configuration
ENVIRONMENT="${1:-${ENVIRONMENT:-prod}}"
AWS_REGION="${2:-${AWS_REGION:-us-east-1}}"
CLEANUP_GROUP_TAG="cloudflare-ip-updater-${ENVIRONMENT}"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Logging functions
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

# Function to check if AWS CLI is available and configured
check_aws_cli() {
    if ! command -v aws &> /dev/null; then
        log_error "AWS CLI is not installed or not in PATH"
        return 1
    fi
    
    if ! aws sts get-caller-identity &> /dev/null; then
        log_error "AWS CLI is not configured or credentials are invalid"
        return 1
    fi
    
    log_success "AWS CLI is available and configured"
    return 0
}

# Function to validate security group tagging
validate_security_group_tags() {
    log_info "Validating security group tags..."
    
    local security_groups
    security_groups=$(aws ec2 describe-security-groups \
        --filters "Name=tag:CleanupGroup,Values=${CLEANUP_GROUP_TAG}" \
        --region "$AWS_REGION" \
        --query 'SecurityGroups[].GroupId' \
        --output text 2>/dev/null || echo "")
    
    if [ -z "$security_groups" ]; then
        log_warning "No security groups found with CleanupGroup tag: $CLEANUP_GROUP_TAG"
        return 1
    fi
    
    local sg_count=0
    for sg_id in $security_groups; do
        sg_count=$((sg_count + 1))
        log_info "Found security group: $sg_id"
        
        # Validate required tags
        local tags
        tags=$(aws ec2 describe-security-groups \
            --group-ids "$sg_id" \
            --region "$AWS_REGION" \
            --query 'SecurityGroups[0].Tags' \
            --output json)
        
        local required_tags=("CleanupGroup" "TerraformManaged" "AutoCleanup" "ResourceIdentifier" "CleanupEnabled")
        for tag in "${required_tags[@]}"; do
            if echo "$tags" | jq -e ".[] | select(.Key == \"$tag\")" > /dev/null; then
                log_success "Security group $sg_id has required tag: $tag"
            else
                log_error "Security group $sg_id missing required tag: $tag"
            fi
        done
    done
    
    log_success "Validated $sg_count security group(s)"
    return 0
}

# Function to validate Lambda function tagging
validate_lambda_function_tags() {
    log_info "Validating Lambda function tags..."
    
    local lambda_functions
    lambda_functions=$(aws lambda list-functions \
        --region "$AWS_REGION" \
        --query "Functions[?contains(FunctionName, 'cloudflare-ip')].FunctionName" \
        --output text 2>/dev/null || echo "")
    
    if [ -z "$lambda_functions" ]; then
        log_warning "No Lambda functions found with 'cloudflare-ip' in name"
        return 1
    fi
    
    local func_count=0
    for func_name in $lambda_functions; do
        func_count=$((func_count + 1))
        log_info "Found Lambda function: $func_name"
        
        # Validate required tags
        local tags
        tags=$(aws lambda list-tags \
            --resource "arn:aws:lambda:${AWS_REGION}:$(aws sts get-caller-identity --query Account --output text):function:${func_name}" \
            --region "$AWS_REGION" \
            --query 'Tags' \
            --output json 2>/dev/null || echo "{}")
        
        local required_tags=("CleanupGroup" "TerraformManaged" "AutoCleanup" "ResourceIdentifier" "CleanupEnabled")
        for tag in "${required_tags[@]}"; do
            if echo "$tags" | jq -e "has(\"$tag\")" > /dev/null; then
                log_success "Lambda function $func_name has required tag: $tag"
            else
                log_error "Lambda function $func_name missing required tag: $tag"
            fi
        done
    done
    
    log_success "Validated $func_count Lambda function(s)"
    return 0
}

# Function to validate CloudWatch resources tagging
validate_cloudwatch_tags() {
    log_info "Validating CloudWatch resources tags..."
    
    # Validate CloudWatch alarms
    local alarms
    alarms=$(aws cloudwatch describe-alarms \
        --alarm-name-prefix "cloudflare-ip" \
        --region "$AWS_REGION" \
        --query 'MetricAlarms[].AlarmName' \
        --output text 2>/dev/null || echo "")
    
    local alarm_count=0
    if [ -n "$alarms" ]; then
        for alarm_name in $alarms; do
            alarm_count=$((alarm_count + 1))
            log_info "Found CloudWatch alarm: $alarm_name"
            
            # Validate alarm tags
            local tags
            tags=$(aws cloudwatch list-tags-for-resource \
                --resource-arn "arn:aws:cloudwatch:${AWS_REGION}:$(aws sts get-caller-identity --query Account --output text):alarm:${alarm_name}" \
                --region "$AWS_REGION" \
                --query 'Tags' \
                --output json 2>/dev/null || echo "[]")
            
            local required_tags=("CleanupGroup" "TerraformManaged" "AutoCleanup")
            for tag in "${required_tags[@]}"; do
                if echo "$tags" | jq -e ".[] | select(.Key == \"$tag\")" > /dev/null; then
                    log_success "CloudWatch alarm $alarm_name has required tag: $tag"
                else
                    log_warning "CloudWatch alarm $alarm_name missing tag: $tag"
                fi
            done
        done
    fi
    
    # Validate CloudWatch dashboards
    local dashboards
    dashboards=$(aws cloudwatch list-dashboards \
        --dashboard-name-prefix "cloudflare-ip" \
        --region "$AWS_REGION" \
        --query 'DashboardEntries[].DashboardName' \
        --output text 2>/dev/null || echo "")
    
    local dashboard_count=0
    if [ -n "$dashboards" ]; then
        for dashboard_name in $dashboards; do
            dashboard_count=$((dashboard_count + 1))
            log_info "Found CloudWatch dashboard: $dashboard_name"
            # Note: CloudWatch dashboards don't support tags in all regions
            log_info "CloudWatch dashboard validation completed (tags not supported for dashboards)"
        done
    fi
    
    log_success "Validated $alarm_count CloudWatch alarm(s) and $dashboard_count dashboard(s)"
    return 0
}

# Function to validate SNS topic tagging
validate_sns_tags() {
    log_info "Validating SNS topic tags..."
    
    local topics
    topics=$(aws sns list-topics \
        --region "$AWS_REGION" \
        --query "Topics[?contains(TopicArn, 'cloudflare-ip')].TopicArn" \
        --output text 2>/dev/null || echo "")
    
    if [ -z "$topics" ]; then
        log_warning "No SNS topics found with 'cloudflare-ip' in ARN"
        return 0
    fi
    
    local topic_count=0
    for topic_arn in $topics; do
        topic_count=$((topic_count + 1))
        log_info "Found SNS topic: $topic_arn"
        
        # Validate required tags
        local tags
        tags=$(aws sns list-tags-for-resource \
            --resource-arn "$topic_arn" \
            --region "$AWS_REGION" \
            --query 'Tags' \
            --output json 2>/dev/null || echo "[]")
        
        local required_tags=("CleanupGroup" "TerraformManaged" "AutoCleanup" "ResourceIdentifier" "CleanupEnabled")
        for tag in "${required_tags[@]}"; do
            if echo "$tags" | jq -e ".[] | select(.Key == \"$tag\")" > /dev/null; then
                log_success "SNS topic has required tag: $tag"
            else
                log_error "SNS topic missing required tag: $tag"
            fi
        done
    done
    
    log_success "Validated $topic_count SNS topic(s)"
    return 0
}

# Function to validate EventBridge rules tagging
validate_eventbridge_tags() {
    log_info "Validating EventBridge rules tags..."
    
    local rules
    rules=$(aws events list-rules \
        --name-prefix "cloudflare-ip" \
        --region "$AWS_REGION" \
        --query 'Rules[].Name' \
        --output text 2>/dev/null || echo "")
    
    if [ -z "$rules" ]; then
        log_warning "No EventBridge rules found with 'cloudflare-ip' prefix"
        return 0
    fi
    
    local rule_count=0
    for rule_name in $rules; do
        rule_count=$((rule_count + 1))
        log_info "Found EventBridge rule: $rule_name"
        
        # Validate required tags
        local tags
        tags=$(aws events list-tags-for-resource \
            --resource-arn "arn:aws:events:${AWS_REGION}:$(aws sts get-caller-identity --query Account --output text):rule/${rule_name}" \
            --region "$AWS_REGION" \
            --query 'Tags' \
            --output json 2>/dev/null || echo "[]")
        
        local required_tags=("CleanupGroup" "TerraformManaged" "AutoCleanup" "ResourceIdentifier" "CleanupEnabled")
        for tag in "${required_tags[@]}"; do
            if echo "$tags" | jq -e ".[] | select(.Key == \"$tag\")" > /dev/null; then
                log_success "EventBridge rule $rule_name has required tag: $tag"
            else
                log_error "EventBridge rule $rule_name missing required tag: $tag"
            fi
        done
    done
    
    log_success "Validated $rule_count EventBridge rule(s)"
    return 0
}

# Function to validate IAM roles tagging
validate_iam_tags() {
    log_info "Validating IAM roles tags..."
    
    local roles
    roles=$(aws iam list-roles \
        --query "Roles[?contains(RoleName, 'cloudflare')].RoleName" \
        --output text 2>/dev/null || echo "")
    
    if [ -z "$roles" ]; then
        log_warning "No IAM roles found with 'cloudflare' in name"
        return 0
    fi
    
    local role_count=0
    for role_name in $roles; do
        role_count=$((role_count + 1))
        log_info "Found IAM role: $role_name"
        
        # Validate required tags
        local tags
        tags=$(aws iam list-role-tags \
            --role-name "$role_name" \
            --query 'Tags' \
            --output json 2>/dev/null || echo "[]")
        
        local required_tags=("CleanupGroup" "TerraformManaged" "AutoCleanup" "ResourceIdentifier" "CleanupEnabled")
        for tag in "${required_tags[@]}"; do
            if echo "$tags" | jq -e ".[] | select(.Key == \"$tag\")" > /dev/null; then
                log_success "IAM role $role_name has required tag: $tag"
            else
                log_error "IAM role $role_name missing required tag: $tag"
            fi
        done
    done
    
    log_success "Validated $role_count IAM role(s)"
    return 0
}

# Function to validate cleanup scripts exist
validate_cleanup_scripts() {
    log_info "Validating cleanup scripts..."
    
    local script_dir="$(dirname "$0")"
    local cleanup_script="${script_dir}/cleanup.sh"
    
    if [ -f "$cleanup_script" ]; then
        log_success "Cleanup script found: $cleanup_script"
        
        if [ -x "$cleanup_script" ]; then
            log_success "Cleanup script is executable"
        else
            log_error "Cleanup script is not executable"
            return 1
        fi
    else
        log_error "Cleanup script not found: $cleanup_script"
        return 1
    fi
    
    return 0
}

# Function to validate Terraform cleanup configuration
validate_terraform_cleanup() {
    log_info "Validating Terraform cleanup configuration..."
    
    local terraform_dir="$(dirname "$(dirname "$0")")"
    local cleanup_tf="${terraform_dir}/cleanup.tf"
    
    if [ -f "$cleanup_tf" ]; then
        log_success "Terraform cleanup configuration found: $cleanup_tf"
        
        # Check for key cleanup resources
        if grep -q "null_resource.*cleanup" "$cleanup_tf"; then
            log_success "Cleanup null resources found in Terraform configuration"
        else
            log_warning "No cleanup null resources found in Terraform configuration"
        fi
        
        if grep -q "provisioner.*local-exec" "$cleanup_tf"; then
            log_success "Local-exec provisioners found for cleanup"
        else
            log_warning "No local-exec provisioners found for cleanup"
        fi
    else
        log_error "Terraform cleanup configuration not found: $cleanup_tf"
        return 1
    fi
    
    return 0
}

# Function to generate cleanup validation report
generate_validation_report() {
    log_info "Generating cleanup validation report..."
    
    local report_file="/tmp/cloudflare-cleanup-validation-${ENVIRONMENT}-$(date +%Y%m%d-%H%M%S).json"
    
    cat > "$report_file" << EOF
{
  "validation_timestamp": "$(date -u +%Y-%m-%dT%H:%M:%SZ)",
  "environment": "$ENVIRONMENT",
  "aws_region": "$AWS_REGION",
  "cleanup_group_tag": "$CLEANUP_GROUP_TAG",
  "validation_results": {
    "security_groups": "$(validate_security_group_tags &>/dev/null && echo "PASS" || echo "FAIL")",
    "lambda_functions": "$(validate_lambda_function_tags &>/dev/null && echo "PASS" || echo "FAIL")",
    "cloudwatch_resources": "$(validate_cloudwatch_tags &>/dev/null && echo "PASS" || echo "FAIL")",
    "sns_topics": "$(validate_sns_tags &>/dev/null && echo "PASS" || echo "FAIL")",
    "eventbridge_rules": "$(validate_eventbridge_tags &>/dev/null && echo "PASS" || echo "FAIL")",
    "iam_roles": "$(validate_iam_tags &>/dev/null && echo "PASS" || echo "FAIL")",
    "cleanup_scripts": "$(validate_cleanup_scripts &>/dev/null && echo "PASS" || echo "FAIL")",
    "terraform_cleanup": "$(validate_terraform_cleanup &>/dev/null && echo "PASS" || echo "FAIL")"
  },
  "recommendations": [
    "Ensure all resources have required cleanup tags",
    "Verify cleanup scripts are executable and accessible",
    "Test cleanup procedures in non-production environment",
    "Monitor cleanup operations through CloudWatch logs"
  ]
}
EOF
    
    log_success "Validation report generated: $report_file"
    cat "$report_file"
    
    return 0
}

# Main validation function
main() {
    log_info "=== CLOUDFLARE IP UPDATER CLEANUP VALIDATION START ==="
    log_info "Environment: $ENVIRONMENT"
    log_info "AWS Region: $AWS_REGION"
    log_info "Cleanup Group Tag: $CLEANUP_GROUP_TAG"
    log_info "Timestamp: $(date)"
    
    # Check prerequisites
    if ! check_aws_cli; then
        log_error "Prerequisites not met, exiting"
        exit 1
    fi
    
    local validation_errors=0
    
    # Run all validations
    log_info "Step 1: Validating security group tags..."
    validate_security_group_tags || validation_errors=$((validation_errors + 1))
    
    log_info "Step 2: Validating Lambda function tags..."
    validate_lambda_function_tags || validation_errors=$((validation_errors + 1))
    
    log_info "Step 3: Validating CloudWatch resources tags..."
    validate_cloudwatch_tags || validation_errors=$((validation_errors + 1))
    
    log_info "Step 4: Validating SNS topic tags..."
    validate_sns_tags || validation_errors=$((validation_errors + 1))
    
    log_info "Step 5: Validating EventBridge rules tags..."
    validate_eventbridge_tags || validation_errors=$((validation_errors + 1))
    
    log_info "Step 6: Validating IAM roles tags..."
    validate_iam_tags || validation_errors=$((validation_errors + 1))
    
    log_info "Step 7: Validating cleanup scripts..."
    validate_cleanup_scripts || validation_errors=$((validation_errors + 1))
    
    log_info "Step 8: Validating Terraform cleanup configuration..."
    validate_terraform_cleanup || validation_errors=$((validation_errors + 1))
    
    log_info "Step 9: Generating validation report..."
    generate_validation_report
    
    if [ $validation_errors -eq 0 ]; then
        log_success "=== CLEANUP VALIDATION COMPLETED SUCCESSFULLY ==="
        exit 0
    else
        log_error "=== CLEANUP VALIDATION COMPLETED WITH $validation_errors ERROR(S) ==="
        exit 1
    fi
}

# Execute main function if script is run directly
if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    main "$@"
fi