#!/bin/bash

# Validation script for the basic Cloudflare AWS Security Group example
# This script helps verify that the deployment was successful

set -e

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

# Function to check if required tools are available
check_prerequisites() {
    log_info "Checking prerequisites..."
    
    if ! command -v terraform &> /dev/null; then
        log_error "Terraform is not installed or not in PATH"
        return 1
    fi
    
    if ! command -v aws &> /dev/null; then
        log_error "AWS CLI is not installed or not in PATH"
        return 1
    fi
    
    if ! aws sts get-caller-identity &> /dev/null; then
        log_error "AWS CLI is not configured or credentials are invalid"
        return 1
    fi
    
    log_success "Prerequisites check passed"
    return 0
}

# Function to get Terraform outputs
get_terraform_outputs() {
    log_info "Getting Terraform outputs..."
    
    if [ ! -f "terraform.tfstate" ]; then
        log_error "terraform.tfstate file not found. Have you run 'terraform apply'?"
        return 1
    fi
    
    # Get key outputs
    SECURITY_GROUP_ID=$(terraform output -raw security_group_id 2>/dev/null || echo "")
    LAMBDA_FUNCTION_NAME=$(terraform output -raw lambda_function_name 2>/dev/null || echo "")
    EVENTBRIDGE_RULE_NAME=$(terraform output -raw eventbridge_rule_name 2>/dev/null || echo "")
    LOG_GROUP_NAME=$(terraform output -raw cloudwatch_log_group_name 2>/dev/null || echo "")
    SNS_TOPIC_ARN=$(terraform output -raw sns_topic_arn 2>/dev/null || echo "")
    CLOUDFLARE_IP_COUNT=$(terraform output -raw cloudflare_ip_count 2>/dev/null || echo "0")
    
    if [ -z "$SECURITY_GROUP_ID" ]; then
        log_error "Could not retrieve security group ID from Terraform outputs"
        return 1
    fi
    
    log_success "Retrieved Terraform outputs"
    return 0
}

# Function to validate security group
validate_security_group() {
    log_info "Validating security group: $SECURITY_GROUP_ID"
    
    # Check if security group exists
    if ! aws ec2 describe-security-groups --group-ids "$SECURITY_GROUP_ID" &> /dev/null; then
        log_error "Security group $SECURITY_GROUP_ID not found"
        return 1
    fi
    
    # Get security group details
    local sg_details
    sg_details=$(aws ec2 describe-security-groups --group-ids "$SECURITY_GROUP_ID" --output json)
    
    # Check ingress rules
    local ingress_count
    ingress_count=$(echo "$sg_details" | jq '.SecurityGroups[0].IpPermissions | length')
    
    if [ "$ingress_count" -eq 0 ]; then
        log_warning "Security group has no ingress rules"
    else
        log_success "Security group has $ingress_count ingress rule(s)"
        
        # Check for HTTP and HTTPS ports
        local http_rules
        local https_rules
        http_rules=$(echo "$sg_details" | jq '.SecurityGroups[0].IpPermissions[] | select(.FromPort == 80)' | jq -s 'length')
        https_rules=$(echo "$sg_details" | jq '.SecurityGroups[0].IpPermissions[] | select(.FromPort == 443)' | jq -s 'length')
        
        if [ "$http_rules" -gt 0 ]; then
            log_success "HTTP (port 80) rules configured"
        fi
        
        if [ "$https_rules" -gt 0 ]; then
            log_success "HTTPS (port 443) rules configured"
        fi
    fi
    
    # Check tags
    local cleanup_tag
    cleanup_tag=$(echo "$sg_details" | jq -r '.SecurityGroups[0].Tags[]? | select(.Key == "CleanupGroup") | .Value')
    
    if [ -n "$cleanup_tag" ]; then
        log_success "Security group has cleanup tag: $cleanup_tag"
    else
        log_warning "Security group missing cleanup tag"
    fi
    
    return 0
}

# Function to validate Lambda function
validate_lambda_function() {
    if [ -z "$LAMBDA_FUNCTION_NAME" ]; then
        log_warning "Lambda function name not available, skipping validation"
        return 0
    fi
    
    log_info "Validating Lambda function: $LAMBDA_FUNCTION_NAME"
    
    # Check if Lambda function exists
    if ! aws lambda get-function --function-name "$LAMBDA_FUNCTION_NAME" &> /dev/null; then
        log_error "Lambda function $LAMBDA_FUNCTION_NAME not found"
        return 1
    fi
    
    # Get function details
    local func_details
    func_details=$(aws lambda get-function --function-name "$LAMBDA_FUNCTION_NAME" --output json)
    
    # Check function state
    local state
    state=$(echo "$func_details" | jq -r '.Configuration.State')
    
    if [ "$state" = "Active" ]; then
        log_success "Lambda function is active"
    else
        log_warning "Lambda function state: $state"
    fi
    
    # Check runtime
    local runtime
    runtime=$(echo "$func_details" | jq -r '.Configuration.Runtime')
    log_info "Lambda runtime: $runtime"
    
    # Test function invocation
    log_info "Testing Lambda function invocation..."
    local invoke_result
    if invoke_result=$(aws lambda invoke --function-name "$LAMBDA_FUNCTION_NAME" --payload '{"test": true}' /tmp/lambda_response.json 2>&1); then
        local status_code
        status_code=$(echo "$invoke_result" | jq -r '.StatusCode')
        
        if [ "$status_code" = "200" ]; then
            log_success "Lambda function invocation successful"
        else
            log_warning "Lambda function returned status code: $status_code"
        fi
    else
        log_error "Lambda function invocation failed: $invoke_result"
    fi
    
    # Clean up test response
    rm -f /tmp/lambda_response.json
    
    return 0
}

# Function to validate EventBridge rule
validate_eventbridge_rule() {
    if [ -z "$EVENTBRIDGE_RULE_NAME" ]; then
        log_warning "EventBridge rule name not available, skipping validation"
        return 0
    fi
    
    log_info "Validating EventBridge rule: $EVENTBRIDGE_RULE_NAME"
    
    # Check if rule exists
    if ! aws events describe-rule --name "$EVENTBRIDGE_RULE_NAME" &> /dev/null; then
        log_error "EventBridge rule $EVENTBRIDGE_RULE_NAME not found"
        return 1
    fi
    
    # Get rule details
    local rule_details
    rule_details=$(aws events describe-rule --name "$EVENTBRIDGE_RULE_NAME" --output json)
    
    # Check rule state
    local state
    state=$(echo "$rule_details" | jq -r '.State')
    
    if [ "$state" = "ENABLED" ]; then
        log_success "EventBridge rule is enabled"
    else
        log_warning "EventBridge rule state: $state"
    fi
    
    # Check schedule
    local schedule
    schedule=$(echo "$rule_details" | jq -r '.ScheduleExpression')
    log_info "Update schedule: $schedule"
    
    # Check targets
    local targets
    targets=$(aws events list-targets-by-rule --rule "$EVENTBRIDGE_RULE_NAME" --output json)
    local target_count
    target_count=$(echo "$targets" | jq '.Targets | length')
    
    if [ "$target_count" -gt 0 ]; then
        log_success "EventBridge rule has $target_count target(s)"
    else
        log_warning "EventBridge rule has no targets"
    fi
    
    return 0
}

# Function to validate CloudWatch logs
validate_cloudwatch_logs() {
    if [ -z "$LOG_GROUP_NAME" ]; then
        log_warning "Log group name not available, skipping validation"
        return 0
    fi
    
    log_info "Validating CloudWatch log group: $LOG_GROUP_NAME"
    
    # Check if log group exists
    if ! aws logs describe-log-groups --log-group-name-prefix "$LOG_GROUP_NAME" | jq -e '.logGroups | length > 0' &> /dev/null; then
        log_error "CloudWatch log group $LOG_GROUP_NAME not found"
        return 1
    fi
    
    log_success "CloudWatch log group exists"
    
    # Check for recent log streams
    local streams
    streams=$(aws logs describe-log-streams --log-group-name "$LOG_GROUP_NAME" --order-by LastEventTime --descending --max-items 5 --output json)
    local stream_count
    stream_count=$(echo "$streams" | jq '.logStreams | length')
    
    if [ "$stream_count" -gt 0 ]; then
        log_success "Found $stream_count log stream(s)"
        
        # Show most recent log stream
        local latest_stream
        latest_stream=$(echo "$streams" | jq -r '.logStreams[0].logStreamName')
        log_info "Latest log stream: $latest_stream"
    else
        log_info "No log streams found (function may not have been invoked yet)"
    fi
    
    return 0
}

# Function to validate SNS topic (if configured)
validate_sns_topic() {
    if [ -z "$SNS_TOPIC_ARN" ] || [ "$SNS_TOPIC_ARN" = "null" ]; then
        log_info "SNS notifications not configured, skipping validation"
        return 0
    fi
    
    log_info "Validating SNS topic: $SNS_TOPIC_ARN"
    
    # Check if topic exists
    if ! aws sns get-topic-attributes --topic-arn "$SNS_TOPIC_ARN" &> /dev/null; then
        log_error "SNS topic $SNS_TOPIC_ARN not found"
        return 1
    fi
    
    log_success "SNS topic exists"
    
    # Check subscriptions
    local subscriptions
    subscriptions=$(aws sns list-subscriptions-by-topic --topic-arn "$SNS_TOPIC_ARN" --output json)
    local sub_count
    sub_count=$(echo "$subscriptions" | jq '.Subscriptions | length')
    
    if [ "$sub_count" -gt 0 ]; then
        log_success "SNS topic has $sub_count subscription(s)"
    else
        log_warning "SNS topic has no subscriptions"
    fi
    
    return 0
}

# Function to display deployment summary
display_summary() {
    log_info "=== DEPLOYMENT SUMMARY ==="
    echo
    echo "Security Group ID: $SECURITY_GROUP_ID"
    echo "Lambda Function: $LAMBDA_FUNCTION_NAME"
    echo "EventBridge Rule: $EVENTBRIDGE_RULE_NAME"
    echo "CloudWatch Log Group: $LOG_GROUP_NAME"
    echo "SNS Topic: ${SNS_TOPIC_ARN:-"Not configured"}"
    echo "Cloudflare IP Count: $CLOUDFLARE_IP_COUNT"
    echo
    
    # Display useful commands
    log_info "=== USEFUL COMMANDS ==="
    echo
    echo "View security group rules:"
    echo "  aws ec2 describe-security-groups --group-ids $SECURITY_GROUP_ID"
    echo
    echo "Invoke Lambda function manually:"
    echo "  aws lambda invoke --function-name $LAMBDA_FUNCTION_NAME response.json"
    echo
    echo "View CloudWatch logs:"
    echo "  aws logs tail $LOG_GROUP_NAME --follow"
    echo
    echo "Check EventBridge rule:"
    echo "  aws events describe-rule --name $EVENTBRIDGE_RULE_NAME"
    echo
}

# Main validation function
main() {
    log_info "=== CLOUDFLARE AWS SECURITY GROUP DEPLOYMENT VALIDATION ==="
    echo
    
    local validation_errors=0
    
    # Check prerequisites
    if ! check_prerequisites; then
        log_error "Prerequisites check failed"
        exit 1
    fi
    
    # Get Terraform outputs
    if ! get_terraform_outputs; then
        log_error "Failed to get Terraform outputs"
        exit 1
    fi
    
    # Run validations
    log_info "Running deployment validations..."
    echo
    
    validate_security_group || validation_errors=$((validation_errors + 1))
    echo
    
    validate_lambda_function || validation_errors=$((validation_errors + 1))
    echo
    
    validate_eventbridge_rule || validation_errors=$((validation_errors + 1))
    echo
    
    validate_cloudwatch_logs || validation_errors=$((validation_errors + 1))
    echo
    
    validate_sns_topic || validation_errors=$((validation_errors + 1))
    echo
    
    # Display summary
    display_summary
    
    # Final result
    if [ $validation_errors -eq 0 ]; then
        log_success "=== ALL VALIDATIONS PASSED ==="
        log_info "Your Cloudflare AWS Security Group deployment is working correctly!"
        exit 0
    else
        log_error "=== VALIDATION COMPLETED WITH $validation_errors ERROR(S) ==="
        log_info "Please review the errors above and check your deployment."
        exit 1
    fi
}

# Execute main function if script is run directly
if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    main "$@"
fi