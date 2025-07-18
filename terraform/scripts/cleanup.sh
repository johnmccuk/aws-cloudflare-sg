#!/bin/bash

# Comprehensive cleanup script for Cloudflare IP updater infrastructure
# This script handles graceful cleanup of resources during terraform destroy operations

set -e

# Configuration from environment variables or parameters
ENVIRONMENT="${1:-${ENVIRONMENT:-unknown}}"
SECURITY_GROUP_ID="${2:-${SECURITY_GROUP_ID:-}}"
LAMBDA_FUNCTION_NAME="${3:-${LAMBDA_FUNCTION_NAME:-}}"
EVENTBRIDGE_RULE_NAME="${4:-${EVENTBRIDGE_RULE_NAME:-}}"
SNS_TOPIC_ARN="${5:-${SNS_TOPIC_ARN:-}}"
LOG_GROUP_NAME="${6:-${LOG_GROUP_NAME:-}}"
CLEANUP_GROUP_TAG="${7:-${CLEANUP_GROUP_TAG:-}}"
AWS_REGION="${8:-${AWS_REGION:-us-east-1}}"

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

# Function to disable EventBridge rule
disable_eventbridge_rule() {
    local rule_name="$1"
    
    if [ -z "$rule_name" ]; then
        log_warning "EventBridge rule name not provided, skipping"
        return 0
    fi
    
    log_info "Disabling EventBridge rule: $rule_name"
    
    # Check if rule exists
    if ! aws events describe-rule --name "$rule_name" --region "$AWS_REGION" &> /dev/null; then
        log_warning "EventBridge rule $rule_name does not exist"
        return 0
    fi
    
    # Disable the rule
    if aws events disable-rule --name "$rule_name" --region "$AWS_REGION"; then
        log_success "EventBridge rule $rule_name disabled"
    else
        log_error "Failed to disable EventBridge rule $rule_name"
        return 1
    fi
    
    # Remove targets from the rule
    local targets
    targets=$(aws events list-targets-by-rule --rule "$rule_name" --region "$AWS_REGION" --query 'Targets[].Id' --output text 2>/dev/null || echo "")
    
    if [ -n "$targets" ]; then
        log_info "Removing targets from EventBridge rule: $targets"
        if aws events remove-targets --rule "$rule_name" --ids $targets --region "$AWS_REGION"; then
            log_success "Removed targets from EventBridge rule $rule_name"
        else
            log_warning "Failed to remove some targets from EventBridge rule $rule_name"
        fi
    fi
    
    return 0
}

# Function to wait for Lambda executions to complete
wait_for_lambda_executions() {
    local function_name="$1"
    local wait_time="${2:-60}"
    
    if [ -z "$function_name" ]; then
        log_warning "Lambda function name not provided, skipping"
        return 0
    fi
    
    log_info "Checking if Lambda function exists: $function_name"
    
    # Check if function exists
    if ! aws lambda get-function --function-name "$function_name" --region "$AWS_REGION" &> /dev/null; then
        log_warning "Lambda function $function_name does not exist"
        return 0
    fi
    
    log_info "Waiting ${wait_time} seconds for Lambda executions to complete..."
    sleep "$wait_time"
    log_success "Wait period completed"
    
    return 0
}

# Function to clean up security group rules
cleanup_security_group_rules() {
    local sg_id="$1"
    
    if [ -z "$sg_id" ]; then
        log_warning "Security group ID not provided, skipping"
        return 0
    fi
    
    log_info "Cleaning up security group rules: $sg_id"
    
    # Check if security group exists
    if ! aws ec2 describe-security-groups --group-ids "$sg_id" --region "$AWS_REGION" &> /dev/null; then
        log_warning "Security group $sg_id does not exist"
        return 0
    fi
    
    # Get security group details
    local sg_details
    sg_details=$(aws ec2 describe-security-groups --group-ids "$sg_id" --region "$AWS_REGION" --output json)
    
    # Remove all ingress rules
    local ingress_rules
    ingress_rules=$(echo "$sg_details" | jq -r '.SecurityGroups[0].IpPermissions')
    
    if [ "$ingress_rules" != "null" ] && [ "$ingress_rules" != "[]" ]; then
        log_info "Removing ingress rules from security group $sg_id"
        echo "$ingress_rules" > /tmp/ingress_rules.json
        
        if aws ec2 revoke-security-group-ingress --group-id "$sg_id" --ip-permissions file:///tmp/ingress_rules.json --region "$AWS_REGION"; then
            log_success "Removed ingress rules from security group $sg_id"
        else
            log_warning "Failed to remove some ingress rules from security group $sg_id"
        fi
        
        rm -f /tmp/ingress_rules.json
    else
        log_info "No ingress rules to remove from security group $sg_id"
    fi
    
    # Remove custom egress rules (keep default allow-all)
    local egress_rules
    egress_rules=$(echo "$sg_details" | jq -r '.SecurityGroups[0].IpPermissionsEgress')
    
    if [ "$egress_rules" != "null" ] && [ "$egress_rules" != "[]" ]; then
        # Filter out default egress rule (allow all outbound)
        local custom_egress_rules
        custom_egress_rules=$(echo "$egress_rules" | jq '[.[] | select(.IpProtocol != "-1" or (.IpRanges | length) != 1 or .IpRanges[0].CidrIp != "0.0.0.0/0")]')
        
        if [ "$custom_egress_rules" != "[]" ]; then
            log_info "Removing custom egress rules from security group $sg_id"
            echo "$custom_egress_rules" > /tmp/egress_rules.json
            
            if aws ec2 revoke-security-group-egress --group-id "$sg_id" --ip-permissions file:///tmp/egress_rules.json --region "$AWS_REGION"; then
                log_success "Removed custom egress rules from security group $sg_id"
            else
                log_warning "Failed to remove some custom egress rules from security group $sg_id"
            fi
            
            rm -f /tmp/egress_rules.json
        else
            log_info "No custom egress rules to remove from security group $sg_id"
        fi
    fi
    
    return 0
}

# Function to clean up SNS subscriptions
cleanup_sns_subscriptions() {
    local topic_arn="$1"
    
    if [ -z "$topic_arn" ]; then
        log_warning "SNS topic ARN not provided, skipping"
        return 0
    fi
    
    log_info "Cleaning up SNS subscriptions for topic: $topic_arn"
    
    # Check if topic exists
    if ! aws sns get-topic-attributes --topic-arn "$topic_arn" --region "$AWS_REGION" &> /dev/null; then
        log_warning "SNS topic $topic_arn does not exist"
        return 0
    fi
    
    # List and unsubscribe all subscriptions
    local subscriptions
    subscriptions=$(aws sns list-subscriptions-by-topic --topic-arn "$topic_arn" --region "$AWS_REGION" --query 'Subscriptions[?SubscriptionArn != `PendingConfirmation`].SubscriptionArn' --output text)
    
    if [ -n "$subscriptions" ]; then
        for subscription in $subscriptions; do
            log_info "Unsubscribing: $subscription"
            if aws sns unsubscribe --subscription-arn "$subscription" --region "$AWS_REGION"; then
                log_success "Unsubscribed: $subscription"
            else
                log_warning "Failed to unsubscribe: $subscription"
            fi
        done
    else
        log_info "No subscriptions to clean up for topic $topic_arn"
    fi
    
    return 0
}

# Function to clean up CloudWatch resources
cleanup_cloudwatch_resources() {
    local environment="$1"
    
    if [ -z "$environment" ]; then
        log_warning "Environment not provided, skipping CloudWatch cleanup"
        return 0
    fi
    
    log_info "Cleaning up CloudWatch resources for environment: $environment"
    
    # Clean up alarms with cloudflare-ip prefix
    local alarm_names
    alarm_names=$(aws cloudwatch describe-alarms --alarm-name-prefix "cloudflare-ip" --region "$AWS_REGION" --query 'MetricAlarms[].AlarmName' --output text 2>/dev/null || echo "")
    
    if [ -n "$alarm_names" ]; then
        log_info "Deleting CloudWatch alarms: $alarm_names"
        if aws cloudwatch delete-alarms --alarm-names $alarm_names --region "$AWS_REGION"; then
            log_success "Deleted CloudWatch alarms"
        else
            log_warning "Failed to delete some CloudWatch alarms"
        fi
    else
        log_info "No CloudWatch alarms to delete"
    fi
    
    # Clean up dashboards with cloudflare-ip prefix
    local dashboard_names
    dashboard_names=$(aws cloudwatch list-dashboards --dashboard-name-prefix "cloudflare-ip" --region "$AWS_REGION" --query 'DashboardEntries[].DashboardName' --output text 2>/dev/null || echo "")
    
    if [ -n "$dashboard_names" ]; then
        for dashboard in $dashboard_names; do
            log_info "Deleting CloudWatch dashboard: $dashboard"
            if aws cloudwatch delete-dashboards --dashboard-names "$dashboard" --region "$AWS_REGION"; then
                log_success "Deleted CloudWatch dashboard: $dashboard"
            else
                log_warning "Failed to delete CloudWatch dashboard: $dashboard"
            fi
        done
    else
        log_info "No CloudWatch dashboards to delete"
    fi
    
    return 0
}

# Function to clean up resources by tags
cleanup_resources_by_tags() {
    local cleanup_tag="$1"
    
    if [ -z "$cleanup_tag" ]; then
        log_warning "Cleanup tag not provided, skipping tag-based cleanup"
        return 0
    fi
    
    log_info "Cleaning up resources with tag: $cleanup_tag"
    
    # This is a placeholder for tag-based resource cleanup
    # In a real implementation, you would query AWS resources by tags
    # and perform cleanup operations on them
    
    log_info "Tag-based cleanup completed (placeholder implementation)"
    
    return 0
}

# Function to validate cleanup results
validate_cleanup() {
    local sg_id="$1"
    local function_name="$2"
    local rule_name="$3"
    local topic_arn="$4"
    
    log_info "Validating cleanup results..."
    
    local validation_errors=0
    
    # Check if security group still exists
    if [ -n "$sg_id" ] && aws ec2 describe-security-groups --group-ids "$sg_id" --region "$AWS_REGION" &> /dev/null; then
        log_warning "Security group $sg_id still exists (this is expected - Terraform will delete it)"
    fi
    
    # Check if Lambda function still exists
    if [ -n "$function_name" ] && aws lambda get-function --function-name "$function_name" --region "$AWS_REGION" &> /dev/null; then
        log_warning "Lambda function $function_name still exists (this is expected - Terraform will delete it)"
    fi
    
    # Check if EventBridge rule still exists and is disabled
    if [ -n "$rule_name" ]; then
        if aws events describe-rule --name "$rule_name" --region "$AWS_REGION" &> /dev/null; then
            local rule_state
            rule_state=$(aws events describe-rule --name "$rule_name" --region "$AWS_REGION" --query 'State' --output text)
            if [ "$rule_state" = "DISABLED" ]; then
                log_success "EventBridge rule $rule_name is properly disabled"
            else
                log_warning "EventBridge rule $rule_name is not disabled (state: $rule_state)"
                validation_errors=$((validation_errors + 1))
            fi
        fi
    fi
    
    # Check if SNS topic still exists
    if [ -n "$topic_arn" ] && aws sns get-topic-attributes --topic-arn "$topic_arn" --region "$AWS_REGION" &> /dev/null; then
        log_warning "SNS topic $topic_arn still exists (this is expected - Terraform will delete it)"
    fi
    
    if [ $validation_errors -eq 0 ]; then
        log_success "Cleanup validation completed successfully"
        return 0
    else
        log_warning "Cleanup validation completed with $validation_errors warnings"
        return 1
    fi
}

# Main cleanup function
main() {
    log_info "=== CLOUDFLARE IP UPDATER CLEANUP START ==="
    log_info "Environment: $ENVIRONMENT"
    log_info "Security Group ID: $SECURITY_GROUP_ID"
    log_info "Lambda Function: $LAMBDA_FUNCTION_NAME"
    log_info "EventBridge Rule: $EVENTBRIDGE_RULE_NAME"
    log_info "SNS Topic ARN: $SNS_TOPIC_ARN"
    log_info "Log Group: $LOG_GROUP_NAME"
    log_info "Cleanup Tag: $CLEANUP_GROUP_TAG"
    log_info "AWS Region: $AWS_REGION"
    log_info "Timestamp: $(date)"
    
    # Check prerequisites
    if ! check_aws_cli; then
        log_error "Prerequisites not met, exiting"
        exit 1
    fi
    
    # Step 1: Disable EventBridge rule to prevent new executions
    log_info "Step 1: Disabling EventBridge rule..."
    disable_eventbridge_rule "$EVENTBRIDGE_RULE_NAME"
    
    # Step 2: Wait for running Lambda executions to complete
    log_info "Step 2: Waiting for Lambda executions to complete..."
    wait_for_lambda_executions "$LAMBDA_FUNCTION_NAME" 60
    
    # Step 3: Clean up security group rules gracefully
    log_info "Step 3: Cleaning up security group rules..."
    cleanup_security_group_rules "$SECURITY_GROUP_ID"
    
    # Step 4: Clean up SNS subscriptions
    log_info "Step 4: Cleaning up SNS subscriptions..."
    cleanup_sns_subscriptions "$SNS_TOPIC_ARN"
    
    # Step 5: Clean up CloudWatch resources
    log_info "Step 5: Cleaning up CloudWatch resources..."
    cleanup_cloudwatch_resources "$ENVIRONMENT"
    
    # Step 6: Clean up resources by tags
    log_info "Step 6: Cleaning up resources by tags..."
    cleanup_resources_by_tags "$CLEANUP_GROUP_TAG"
    
    # Step 7: Validate cleanup results
    log_info "Step 7: Validating cleanup results..."
    validate_cleanup "$SECURITY_GROUP_ID" "$LAMBDA_FUNCTION_NAME" "$EVENTBRIDGE_RULE_NAME" "$SNS_TOPIC_ARN"
    
    log_success "=== CLOUDFLARE IP UPDATER CLEANUP COMPLETED ==="
}

# Execute main function if script is run directly
if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    main "$@"
fi