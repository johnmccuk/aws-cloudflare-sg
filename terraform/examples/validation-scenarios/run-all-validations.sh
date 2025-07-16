#!/bin/bash

# Comprehensive Validation Test Suite
# This script runs all validation scenarios for the Cloudflare AWS Security Group module

set -e

# Configuration
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
TERRAFORM_DIR="$(dirname "$(dirname "$SCRIPT_DIR")")"
VALIDATION_RESULTS_DIR="/tmp/cloudflare-sg-validation-results"
TIMESTAMP=$(date +%Y%m%d_%H%M%S)

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

# Create results directory
mkdir -p "$VALIDATION_RESULTS_DIR"

# Initialize summary
TOTAL_TESTS=0
PASSED_TESTS=0
FAILED_TESTS=0
SUMMARY_FILE="$VALIDATION_RESULTS_DIR/validation_summary_$TIMESTAMP.txt"

echo "Cloudflare AWS Security Group - Validation Test Suite" > "$SUMMARY_FILE"
echo "====================================================" >> "$SUMMARY_FILE"
echo "Started at: $(date)" >> "$SUMMARY_FILE"
echo "" >> "$SUMMARY_FILE"

log_info "Starting comprehensive validation test suite"
log_info "Results will be saved to: $VALIDATION_RESULTS_DIR"

# Test scenarios
SCENARIOS=(
    "terraform-cloud-validation"
    "local-execution-validation"
)

# Function to run individual validation test
run_validation_test() {
    local scenario="$1"
    local tfvars_file="$scenario.tfvars"
    local result_file="$VALIDATION_RESULTS_DIR/${scenario}_result_$TIMESTAMP.txt"
    
    log_info "Running validation test: $scenario"
    TOTAL_TESTS=$((TOTAL_TESTS + 1))
    
    # Check if tfvars file exists
    if [[ ! -f "$tfvars_file" ]]; then
        log_error "Configuration file not found: $tfvars_file"
        echo "FAILED: Configuration file not found" >> "$result_file"
        FAILED_TESTS=$((FAILED_TESTS + 1))
        return 1
    fi
    
    # Change to terraform directory
    cd "$TERRAFORM_DIR"
    
    # Initialize Terraform if needed
    if [[ ! -d ".terraform" ]]; then
        log_info "Initializing Terraform..."
        if ! terraform init -input=false >> "$result_file" 2>&1; then
            log_error "Terraform initialization failed for $scenario"
            echo "FAILED: Terraform initialization failed" >> "$result_file"
            FAILED_TESTS=$((FAILED_TESTS + 1))
            return 1
        fi
    fi
    
    # Validate configuration
    log_info "Validating Terraform configuration for $scenario"
    if ! terraform validate >> "$result_file" 2>&1; then
        log_error "Terraform validation failed for $scenario"
        echo "FAILED: Terraform validation failed" >> "$result_file"
        FAILED_TESTS=$((FAILED_TESTS + 1))
        return 1
    fi
    
    # Run terraform plan (dry run)
    log_info "Running terraform plan for $scenario"
    if terraform plan -var-file="examples/validation-scenarios/$tfvars_file" -input=false >> "$result_file" 2>&1; then
        log_success "Validation test passed: $scenario"
        echo "PASSED: All validation checks successful" >> "$result_file"
        PASSED_TESTS=$((PASSED_TESTS + 1))
        return 0
    else
        log_error "Terraform plan failed for $scenario"
        echo "FAILED: Terraform plan failed" >> "$result_file"
        FAILED_TESTS=$((FAILED_TESTS + 1))
        return 1
    fi
}

# Function to validate prerequisites
validate_prerequisites() {
    log_info "Validating prerequisites..."
    
    local prereq_errors=0
    
    # Check required commands
    if ! command -v terraform &> /dev/null; then
        log_error "Terraform is not installed or not in PATH"
        prereq_errors=$((prereq_errors + 1))
    else
        local terraform_version
        terraform_version=$(terraform version -json | jq -r '.terraform_version' 2>/dev/null || terraform version | head -n1 | cut -d' ' -f2 | sed 's/v//')
        log_info "Terraform version: $terraform_version"
    fi
    
    if ! command -v aws &> /dev/null; then
        log_error "AWS CLI is not installed or not in PATH"
        prereq_errors=$((prereq_errors + 1))
    else
        if aws sts get-caller-identity &> /dev/null; then
            local account_id
            account_id=$(aws sts get-caller-identity --query Account --output text)
            log_info "AWS account: $account_id"
        else
            log_warning "AWS CLI not configured (some tests may fail)"
        fi
    fi
    
    # Check environment variables
    if [[ -z "${VPC_ID:-}" ]]; then
        log_warning "VPC_ID environment variable not set (some validations may be skipped)"
    else
        log_info "VPC_ID: $VPC_ID"
    fi
    
    return $prereq_errors
}

# Function to run network connectivity tests
test_network_connectivity() {
    log_info "Testing network connectivity..."
    
    local connectivity_errors=0
    
    # Test Cloudflare API endpoints
    if command -v curl &> /dev/null; then
        if curl -s --max-time 10 "https://www.cloudflare.com/ips-v4" > /dev/null; then
            log_success "Cloudflare IPv4 API accessible"
        else
            log_error "Cannot access Cloudflare IPv4 API"
            connectivity_errors=$((connectivity_errors + 1))
        fi
        
        if curl -s --max-time 10 "https://www.cloudflare.com/ips-v6" > /dev/null; then
            log_success "Cloudflare IPv6 API accessible"
        else
            log_error "Cannot access Cloudflare IPv6 API"
            connectivity_errors=$((connectivity_errors + 1))
        fi
    else
        log_warning "curl not available - skipping network tests"
    fi
    
    return $connectivity_errors
}

# Function to validate configuration files
validate_configuration_files() {
    log_info "Validating configuration files..."
    
    local config_errors=0
    
    cd "$SCRIPT_DIR"
    
    # Check all scenario files exist
    for scenario in "${SCENARIOS[@]}"; do
        local tfvars_file="$scenario.tfvars"
        if [[ -f "$tfvars_file" ]]; then
            log_success "Configuration file exists: $tfvars_file"
            
            # Basic syntax check
            if grep -q "vpc_id" "$tfvars_file" && grep -q "environment" "$tfvars_file"; then
                log_success "Required variables found in $tfvars_file"
            else
                log_warning "Some required variables may be missing in $tfvars_file"
            fi
        else
            log_error "Configuration file missing: $tfvars_file"
            config_errors=$((config_errors + 1))
        fi
    done
    
    return $config_errors
}

# Function to generate comprehensive report
generate_comprehensive_report() {
    local report_file="$VALIDATION_RESULTS_DIR/comprehensive_report_$TIMESTAMP.html"
    
    cat > "$report_file" << EOF
<!DOCTYPE html>
<html>
<head>
    <title>Cloudflare AWS Security Group - Validation Report</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 20px; }
        .header { background-color: #f0f0f0; padding: 20px; border-radius: 5px; }
        .success { color: green; }
        .error { color: red; }
        .warning { color: orange; }
        .section { margin: 20px 0; padding: 15px; border: 1px solid #ddd; border-radius: 5px; }
        .code { background-color: #f5f5f5; padding: 10px; font-family: monospace; }
        table { border-collapse: collapse; width: 100%; }
        th, td { border: 1px solid #ddd; padding: 8px; text-align: left; }
        th { background-color: #f2f2f2; }
    </style>
</head>
<body>
    <div class="header">
        <h1>Cloudflare AWS Security Group - Validation Report</h1>
        <p>Generated at: $(date)</p>
        <p>Total Tests: $TOTAL_TESTS | Passed: <span class="success">$PASSED_TESTS</span> | Failed: <span class="error">$FAILED_TESTS</span></p>
    </div>

    <div class="section">
        <h2>Test Summary</h2>
        <table>
            <tr><th>Scenario</th><th>Status</th><th>Details</th></tr>
EOF

    # Add test results to HTML report
    for scenario in "${SCENARIOS[@]}"; do
        local result_file="$VALIDATION_RESULTS_DIR/${scenario}_result_$TIMESTAMP.txt"
        if [[ -f "$result_file" ]]; then
            local status
            if grep -q "PASSED" "$result_file"; then
                status="<span class=\"success\">PASSED</span>"
            else
                status="<span class=\"error\">FAILED</span>"
            fi
            echo "            <tr><td>$scenario</td><td>$status</td><td><a href=\"${scenario}_result_$TIMESTAMP.txt\">View Details</a></td></tr>" >> "$report_file"
        fi
    done

    cat >> "$report_file" << EOF
        </table>
    </div>

    <div class="section">
        <h2>Environment Information</h2>
        <div class="code">
Operating System: $(uname -s)<br>
Terraform Version: $(terraform version | head -n1 | cut -d' ' -f2 2>/dev/null || "Not available")<br>
AWS CLI Version: $(aws --version 2>/dev/null | cut -d' ' -f1 || "Not available")<br>
AWS Account: $(aws sts get-caller-identity --query Account --output text 2>/dev/null || "Not available")<br>
AWS Region: $(aws configure get region 2>/dev/null || "Not configured")<br>
VPC ID: ${VPC_ID:-"Not set"}
        </div>
    </div>

    <div class="section">
        <h2>Next Steps</h2>
        <ul>
            <li>Review failed tests and fix configuration issues</li>
            <li>Ensure all prerequisites are met</li>
            <li>Set required environment variables</li>
            <li>Run individual scenario tests for debugging</li>
            <li>Deploy to development environment for further testing</li>
        </ul>
    </div>
</body>
</html>
EOF

    log_success "Comprehensive HTML report generated: $report_file"
}

# Main execution
main() {
    echo -e "${BLUE}Cloudflare AWS Security Group - Comprehensive Validation${NC}"
    echo "========================================================"
    
    # Run prerequisite validation
    if ! validate_prerequisites; then
        log_warning "Some prerequisites are missing but continuing with tests"
    fi
    
    # Test network connectivity
    if ! test_network_connectivity; then
        log_warning "Some network connectivity issues detected"
    fi
    
    # Validate configuration files
    if ! validate_configuration_files; then
        log_error "Configuration file validation failed"
        exit 1
    fi
    
    # Run all validation scenarios
    cd "$SCRIPT_DIR"
    for scenario in "${SCENARIOS[@]}"; do
        run_validation_test "$scenario"
    done
    
    # Generate summary
    echo "" >> "$SUMMARY_FILE"
    echo "Test Results:" >> "$SUMMARY_FILE"
    echo "=============" >> "$SUMMARY_FILE"
    echo "Total Tests: $TOTAL_TESTS" >> "$SUMMARY_FILE"
    echo "Passed: $PASSED_TESTS" >> "$SUMMARY_FILE"
    echo "Failed: $FAILED_TESTS" >> "$SUMMARY_FILE"
    echo "" >> "$SUMMARY_FILE"
    echo "Completed at: $(date)" >> "$SUMMARY_FILE"
    
    # Generate comprehensive report
    generate_comprehensive_report
    
    # Print final summary
    echo ""
    log_info "Validation Test Suite Summary:"
    echo "=============================="
    echo "Total Tests: $TOTAL_TESTS"
    echo "Passed: $PASSED_TESTS"
    echo "Failed: $FAILED_TESTS"
    echo ""
    
    if [[ $FAILED_TESTS -eq 0 ]]; then
        log_success "All validation tests passed!"
        echo "The configuration is ready for deployment."
    else
        log_error "$FAILED_TESTS test(s) failed"
        echo "Please review the results and fix any issues before deployment."
    fi
    
    echo ""
    echo "Results saved to: $VALIDATION_RESULTS_DIR"
    echo "Summary: $SUMMARY_FILE"
    
    # Return appropriate exit code
    return $FAILED_TESTS
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
        echo "  VPC_ID         AWS VPC ID for validation tests"
        echo "  ENVIRONMENT    Environment name for testing"
        echo ""
        echo "This script runs comprehensive validation tests for all scenarios."
        exit 0
        ;;
    --quiet|-q)
        exec > /dev/null
        ;;
esac

# Run main function
main "$@"