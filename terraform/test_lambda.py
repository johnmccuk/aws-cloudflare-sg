#!/usr/bin/env python3
"""
Test script for Lambda function Terraform automation functionality.
"""

import unittest
from unittest.mock import patch, MagicMock, mock_open
import os
import sys
import tempfile
import json

# Add the current directory to Python path to import lambda_function
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import lambda_function


class TestTerraformAutomation(unittest.TestCase):
    """Test cases for Terraform automation functionality."""

    def setUp(self):
        """Set up test environment."""
        # Mock environment variables
        self.env_patcher = patch.dict(os.environ, {
            'SECURITY_GROUP_ID': 'sg-12345678',
            'SNS_TOPIC_ARN': 'arn:aws:sns:us-east-1:123456789012:test-topic',
            'TERRAFORM_MODE': 'direct',
            'TERRAFORM_CONFIG_S3_BUCKET': 'test-bucket',
            'TERRAFORM_CONFIG_S3_KEY': 'terraform-config.zip',
            'TERRAFORM_STATE_S3_BUCKET': 'test-state-bucket',
            'TERRAFORM_STATE_S3_KEY': 'terraform.tfstate',
            'AWS_REGION': 'us-east-1'
        })
        self.env_patcher.start()

    def tearDown(self):
        """Clean up test environment."""
        self.env_patcher.stop()

    @patch('lambda_function.shutil.which')
    @patch('lambda_function.update_security_group_if_needed')
    def test_terraform_local_fallback_no_binary(self, mock_update_sg, mock_which):
        """Test fallback to direct updates when Terraform binary is not available."""
        # Mock Terraform binary not found
        mock_which.return_value = None
        mock_update_sg.return_value = True
        
        current_ips = {'1.1.1.1/32', '2.2.2.2/32'}
        existing_ips = {'1.1.1.1/32'}
        
        result = lambda_function.trigger_terraform_local(current_ips, existing_ips)
        
        self.assertTrue(result)
        mock_update_sg.assert_called_once_with(current_ips, existing_ips)

    @patch('lambda_function.shutil.which')
    @patch('lambda_function.update_security_group_if_needed')
    def test_terraform_local_fallback_no_config(self, mock_update_sg, mock_which):
        """Test fallback to direct updates when S3 configuration is missing."""
        # Mock Terraform binary found but no S3 config
        mock_which.return_value = '/usr/bin/terraform'
        mock_update_sg.return_value = True
        
        # Clear S3 configuration
        with patch.dict(os.environ, {'TERRAFORM_CONFIG_S3_BUCKET': '', 'TERRAFORM_CONFIG_S3_KEY': ''}):
            current_ips = {'1.1.1.1/32', '2.2.2.2/32'}
            existing_ips = {'1.1.1.1/32'}
            
            result = lambda_function.trigger_terraform_local(current_ips, existing_ips)
            
            self.assertTrue(result)
            mock_update_sg.assert_called_once_with(current_ips, existing_ips)

    @patch('lambda_function.requests.post')
    @patch('lambda_function.monitor_terraform_cloud_run')
    def test_terraform_cloud_success(self, mock_monitor, mock_post):
        """Test successful Terraform Cloud execution."""
        # Mock successful API response
        mock_response = MagicMock()
        mock_response.raise_for_status.return_value = None
        mock_response.json.return_value = {
            'data': {
                'id': 'run-12345',
                'attributes': {'status': 'planning'}
            }
        }
        mock_post.return_value = mock_response
        mock_monitor.return_value = True
        
        # Set Terraform Cloud environment
        with patch.dict(os.environ, {
            'TERRAFORM_MODE': 'cloud',
            'TERRAFORM_CLOUD_TOKEN': 'test-token',
            'TERRAFORM_WORKSPACE': 'ws-12345',
            'TERRAFORM_ORGANIZATION': 'test-org'
        }):
            current_ips = {'1.1.1.1/32', '2.2.2.2/32'}
            existing_ips = {'1.1.1.1/32'}
            
            result = lambda_function.trigger_terraform_cloud(current_ips, existing_ips)
            
            self.assertTrue(result)
            mock_post.assert_called_once()
            mock_monitor.assert_called_once_with('run-12345', {
                'Authorization': 'Bearer test-token',
                'Content-Type': 'application/vnd.api+json'
            })

    def test_terraform_cloud_missing_config(self):
        """Test Terraform Cloud with missing configuration."""
        with patch.dict(os.environ, {
            'TERRAFORM_MODE': 'cloud',
            'TERRAFORM_CLOUD_TOKEN': '',
            'TERRAFORM_WORKSPACE': '',
            'TERRAFORM_ORGANIZATION': ''
        }):
            current_ips = {'1.1.1.1/32'}
            existing_ips = set()
            
            with self.assertRaises(ValueError) as context:
                lambda_function.trigger_terraform_cloud(current_ips, existing_ips)
            
            self.assertIn("Terraform Cloud configuration incomplete", str(context.exception))

    @patch('lambda_function.requests.get')
    def test_monitor_terraform_cloud_run_success(self, mock_get):
        """Test monitoring Terraform Cloud run to completion."""
        # Mock API responses for run status
        responses = [
            {'data': {'attributes': {'status': 'planning'}}},
            {'data': {'attributes': {'status': 'applying'}}},
            {'data': {'attributes': {'status': 'applied'}}}
        ]
        
        mock_response = MagicMock()
        mock_response.raise_for_status.return_value = None
        mock_response.json.side_effect = responses
        mock_get.return_value = mock_response
        
        headers = {'Authorization': 'Bearer test-token'}
        
        with patch('lambda_function.time.sleep'):  # Speed up test
            result = lambda_function.monitor_terraform_cloud_run('run-12345', headers)
        
        self.assertTrue(result)
        self.assertEqual(mock_get.call_count, 3)

    @patch('lambda_function.requests.get')
    def test_monitor_terraform_cloud_run_failure(self, mock_get):
        """Test monitoring Terraform Cloud run that fails."""
        mock_response = MagicMock()
        mock_response.raise_for_status.return_value = None
        mock_response.json.return_value = {'data': {'attributes': {'status': 'errored'}}}
        mock_get.return_value = mock_response
        
        headers = {'Authorization': 'Bearer test-token'}
        result = lambda_function.monitor_terraform_cloud_run('run-12345', headers)
        
        self.assertFalse(result)

    @patch('lambda_function.boto3.client')
    def test_download_terraform_config(self, mock_boto3):
        """Test downloading Terraform configuration from S3."""
        mock_s3_client = MagicMock()
        mock_boto3.return_value = mock_s3_client
        
        with tempfile.TemporaryDirectory() as temp_dir:
            lambda_function.download_terraform_config(temp_dir)
            
            mock_s3_client.download_file.assert_called_once_with(
                'test-bucket',
                'terraform-config.zip',
                os.path.join(temp_dir, 'terraform-config.zip')
            )

    def test_setup_terraform_backend(self):
        """Test setting up Terraform backend configuration."""
        with tempfile.TemporaryDirectory() as temp_dir:
            lambda_function.setup_terraform_backend(temp_dir)
            
            backend_file = os.path.join(temp_dir, 'backend.tf')
            self.assertTrue(os.path.exists(backend_file))
            
            with open(backend_file, 'r') as f:
                content = f.read()
                self.assertIn('backend "s3"', content)
                self.assertIn('test-state-bucket', content)
                self.assertIn('terraform.tfstate', content)

    @patch('lambda_function.subprocess.run')
    def test_run_terraform_command_success(self, mock_run):
        """Test successful Terraform command execution."""
        mock_result = MagicMock()
        mock_result.returncode = 0
        mock_result.stdout = 'Terraform initialized successfully'
        mock_result.stderr = ''
        mock_run.return_value = mock_result
        
        with tempfile.TemporaryDirectory() as temp_dir:
            result = lambda_function.run_terraform_command(['terraform', 'init'], temp_dir)
            
            self.assertTrue(result)
            mock_run.assert_called_once()

    @patch('lambda_function.subprocess.run')
    def test_run_terraform_command_failure(self, mock_run):
        """Test failed Terraform command execution."""
        mock_result = MagicMock()
        mock_result.returncode = 1
        mock_result.stdout = ''
        mock_result.stderr = 'Error: configuration invalid'
        mock_run.return_value = mock_result
        
        with tempfile.TemporaryDirectory() as temp_dir:
            result = lambda_function.run_terraform_command(['terraform', 'plan'], temp_dir)
            
            self.assertFalse(result)

    @patch('lambda_function.trigger_terraform_automation')
    @patch('lambda_function.get_existing_security_group_ips')
    @patch('lambda_function.fetch_cloudflare_ips')
    def test_lambda_handler_with_terraform_automation(self, mock_fetch, mock_existing, mock_terraform):
        """Test Lambda handler with Terraform automation."""
        # Mock IP sets with changes
        mock_fetch.return_value = {'1.1.1.1/32', '2.2.2.2/32'}
        mock_existing.return_value = {'1.1.1.1/32'}
        mock_terraform.return_value = True
        
        event = {}
        context = MagicMock()
        
        with patch('lambda_function.send_notification') as mock_notify:
            result = lambda_function.lambda_handler(event, context)
            
            self.assertEqual(result['statusCode'], 200)
            response_body = json.loads(result['body'])
            self.assertTrue(response_body['changes_made'])
            self.assertEqual(response_body['ip_count'], 2)
            
            mock_terraform.assert_called_once()
            mock_notify.assert_called_once()


if __name__ == '__main__':
    # Run the tests
    unittest.main(verbosity=2)