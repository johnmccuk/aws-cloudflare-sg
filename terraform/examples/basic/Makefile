# Makefile for Cloudflare AWS Security Group Basic Example
# This Makefile provides convenient commands for managing the deployment

.PHONY: help init plan apply destroy validate clean check-vars

# Default target
help:
	@echo "Cloudflare AWS Security Group - Basic Example"
	@echo ""
	@echo "Available commands:"
	@echo "  help      - Show this help message"
	@echo "  init      - Initialize Terraform"
	@echo "  plan      - Plan Terraform deployment"
	@echo "  apply     - Apply Terraform configuration"
	@echo "  destroy   - Destroy Terraform resources"
	@echo "  validate  - Validate deployment"
	@echo "  clean     - Clean up temporary files"
	@echo "  check     - Check prerequisites"
	@echo ""
	@echo "Configuration:"
	@echo "  Copy terraform.tfvars.example to terraform.tfvars and customize"
	@echo "  Or use environment variables or command line arguments"
	@echo ""
	@echo "Examples:"
	@echo "  make init"
	@echo "  make plan"
	@echo "  make apply"
	@echo "  make validate"
	@echo "  make destroy"

# Check prerequisites
check:
	@echo "Checking prerequisites..."
	@command -v terraform >/dev/null 2>&1 || { echo "Error: Terraform is not installed"; exit 1; }
	@command -v aws >/dev/null 2>&1 || { echo "Error: AWS CLI is not installed"; exit 1; }
	@aws sts get-caller-identity >/dev/null 2>&1 || { echo "Error: AWS credentials not configured"; exit 1; }
	@echo "Prerequisites check passed ✓"

# Initialize Terraform
init: check
	@echo "Initializing Terraform..."
	terraform init

# Plan Terraform deployment
plan: init
	@echo "Planning Terraform deployment..."
	terraform plan

# Apply Terraform configuration
apply: init
	@echo "Applying Terraform configuration..."
	terraform apply

# Validate deployment
validate:
	@echo "Validating deployment..."
	@chmod +x validate-deployment.sh
	./validate-deployment.sh

# Destroy Terraform resources
destroy:
	@echo "Destroying Terraform resources..."
	@echo "This will delete all resources created by this example."
	@read -p "Are you sure? (y/N): " confirm && [ "$$confirm" = "y" ] || exit 1
	terraform destroy

# Clean up temporary files
clean:
	@echo "Cleaning up temporary files..."
	rm -f terraform.tfplan
	rm -f response.json
	rm -f .terraform.lock.hcl
	rm -rf .terraform/
	@echo "Cleanup completed ✓"

# Quick deployment with default settings
quick-deploy: init
	@echo "Quick deployment with default settings..."
	@echo "This will use the default VPC and dev environment"
	terraform apply -auto-approve

# Show current state
status:
	@echo "Current Terraform state:"
	terraform show

# Show outputs
outputs:
	@echo "Terraform outputs:"
	terraform output

# Format Terraform files
format:
	@echo "Formatting Terraform files..."
	terraform fmt -recursive

# Validate Terraform configuration
tf-validate: init
	@echo "Validating Terraform configuration..."
	terraform validate

# Complete workflow: init, plan, apply, validate
deploy: init plan apply validate
	@echo "Deployment completed successfully! ✓"

# Development workflow with validation
dev-deploy: format tf-validate deploy
	@echo "Development deployment completed! ✓"