#!/bin/bash

# Build script for Lambda function with Terraform binary
set -e

echo "Building Lambda deployment package..."

# Create temporary build directory
BUILD_DIR="lambda_build"
rm -rf $BUILD_DIR
mkdir -p $BUILD_DIR

# Copy Lambda function code
cp lambda_function.py $BUILD_DIR/

# Install Python dependencies
if [ -f requirements.txt ]; then
    echo "Installing Python dependencies..."
    pip install -r requirements.txt -t $BUILD_DIR/
fi

# Download Terraform binary for Linux (Lambda runtime)
echo "Downloading Terraform binary..."
TERRAFORM_VERSION="1.6.6"
TERRAFORM_URL="https://releases.hashicorp.com/terraform/${TERRAFORM_VERSION}/terraform_${TERRAFORM_VERSION}_linux_amd64.zip"

cd $BUILD_DIR
curl -o terraform.zip $TERRAFORM_URL
unzip terraform.zip
rm terraform.zip
chmod +x terraform

# Create deployment package
echo "Creating deployment package..."
zip -r ../lambda_function.zip .

# Cleanup
cd ..
rm -rf $BUILD_DIR

echo "Lambda deployment package created: lambda_function.zip"