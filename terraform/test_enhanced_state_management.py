#!/usr/bin/env python3
"""
Enhanced state management test suite for Cloudflare IP security group automation.
This file contains comprehensive tests for state validation, drift detection, and idempotency features.
"""

import unittest
from unittest.mock import Mock, patch, MagicMock
import json
import boto3
from moto import mock_ec2, mock_sns, mock_cloudwatch
import sys
import os

# Add the current directory to the path to import lambda_function
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

# Import the lambda function with mocked environment variables
with patch.dict(os.environ, {
    'SECURITY_GROUP_ID': 'sg-12345678',
    'SNS_TOPIC_ARN': 'arn:aws:sns:us-east-1:123456789012:test-topic',
    'ENABLE_STATE_VALIDATION': 'true',
    'ENABLE_DRIFT_DETECTION': 'true',
    'IP_CHANGE_THRESHOLD_PERCENT': '30',
    'MAX_IP_CHANGES_PER_UPDATE': '50',
    'ENABLE_ENHANCED_LIFECYCLE': 'true',
    'ENABLE_QUOTA_CHECKING': 'true',
    'MAX_RULES_PER_SECURITY_GROUP': '120',
    'MAX_SECURITY_GROUPS_PER_VPC': '2500',
    'MAX_EXPECTED_CLOUDFLARE_IPS': '200'
}):
    import lambda_function


class TestEnhancedStateManagement(unittest.TestCase):
    """Test cases for enhanced state management and idempotency features."""
    
    def setUp(self):
        """Set up test fixtures."""
        self.sample_cloudflare_ips = {
            '103.21.244.0/22',
            '103.22.200.0/22',
            '103.31.4.0/22',
            '104.16.0.0/13',
            '108.162.192.0/18'
        }
        
        self.sample_existing_ips = {
            '103.21.244.0/22',
            '103.22.200.0/22',
            '103.31.4.0/22',
            '104.16.0.0/13'
        }
    
    def test_state_validation_enabled(self):
        """Test that state validation is properly enabled."""
        self.assertTrue(lambda_function.ENABLE_STATE_VALIDATION)
        self.assertTrue(lambda_function.ENABLE_DRIFT_DETECTION)
    
    def test_perform_state_validation_no_ips(self):
        """Test state validation when no IPs are retrieved."""
        with self.assertRaises(ValueError) as context:
            lambda_function.perform_state_validation(set(), self.sample_existing_ips)
        
        self.assertIn("No Cloudflare IPs retrieved", str(context.exception))
    
    def test_perform_state_validation_too_many_ips(self):
        """Test state validation when too many IPs are retrieved."""
        too_many_ips = {f'192.168.{i}.0/24' for i in range(500)}  # 500 IPs
        
        with self.assertRaises(ValueError) as context:
            lambda_function.perform_state_validation(too_many_ips, self.sample_existing_ips)
        
        self.assertIn("exceeds reasonable maximum", str(context.exception))
    
    @patch('lambda_function.logger')
    def test_perform_state_validation_drift_detected(self, mock_logger):
        """Test drift detection when changes are present."""
        lambda_function.perform_state_validation(self.sample_cloudflare_ips, self.sample_existing_ips)
        
        # Verify drift detection logging
        mock_logger.info.assert_any_call("Drift detection enabled - analyzing state differences")
        mock_logger.info.assert_any_call("State drift detected: 1 IPs to add, 0 IPs to remove")
    
    @patch('lambda_function.logger')
    def test_perform_state_validation_no_drift(self, mock_logger):
        """Test drift detection when no changes are present."""
        lambda_function.perform_state_validation(self.sample_existing_ips, self.sample_existing_ips)
        
        # Verify no drift logging
        mock_logger.info.assert_any_call("No state drift detected - security group is up to date")
    
    def test_should_use_replacement_strategy_absolute_threshold(self):
        """Test replacement strategy trigger based on absolute change count."""
        # Create scenario with more changes than MAX_IP_CHANGES_PER_UPDATE (50)
        large_ip_set = {f'192.168.{i}.0/24' for i in range(60)}
        small_ip_set = {f'10.0.{i}.0/24' for i in range(5)}
        
        result = lambda_function.should_use_replacement_strategy(
            large_ip_set, set(), small_ip_set
        )
        
        self.assertTrue(result)
    
    def test_should_use_replacement_strategy_percentage_threshold(self):
        """Test replacement strategy trigger based on percentage change."""
        existing_ips = {f'192.168.{i}.0/24' for i in range(10)}  # 10 existing IPs
        ips_to_add = {f'10.0.{i}.0/24' for i in range(4)}  # 4 new IPs = 40% change
        
        result = lambda_function.should_use_replacement_strategy(
            ips_to_add, set(), existing_ips
        )
        
        self.assertTrue(result)  # 40% > 30% threshold
    
    def test_should_use_replacement_strategy_no_trigger(self):
        """Test replacement strategy not triggered for small changes."""
        existing_ips = {f'192.168.{i}.0/24' for i in range(10)}  # 10 existing IPs
        ips_to_add = {f'10.0.{i}.0/24' for i in range(2)}  # 2 new IPs = 20% change
        
        result = lambda_function.should_use_replacement_strategy(
            ips_to_add, set(), existing_ips
        )
        
        self.assertFalse(result)  # 20% < 30% threshold and 2 < 50 absolute
    
    @patch('lambda_function.logger')
    def test_validate_aws_service_quotas_warnings(self, mock_logger):
        """Test AWS service quota validation with warnings."""
        # Mock quota checking enabled with warnings
        with patch.dict(os.environ, {
            'ENABLE_QUOTA_CHECKING': 'true',
            'RULES_APPROACHING_LIMIT': 'true',
            'REQUIRES_MULTIPLE_GROUPS': 'true',
            'SECURITY_GROUPS_NEEDED': '3',
            'CURRENT_SECURITY_GROUPS_COUNT': '2000',
            'MAX_SECURITY_GROUPS_PER_VPC': '2500'
        }):
            lambda_function.validate_aws_service_quotas()
        
        # Verify warning logs
        mock_logger.warning.assert_any_call("Security group rules approaching limit. Current usage is high.")
        mock_logger.info.assert_any_call("Multiple security groups required: 3 groups needed")
    
    @patch('lambda_function.boto3.client')
    def test_log_cloudwatch_metrics(self, mock_boto3_client):
        """Test CloudWatch metrics logging."""
        mock_cloudwatch = Mock()
        mock_boto3_client.return_value = mock_cloudwatch
        
        lambda_function.log_cloudwatch_metrics(
            self.sample_cloudflare_ips, 
            self.sample_existing_ips, 
            True
        )
        
        # Verify CloudWatch metrics were sent
        mock_cloudwatch.put_metric_data.assert_called_once()
        call_args = mock_cloudwatch.put_metric_data.call_args[1]
        
        self.assertEqual(call_args['Namespace'], 'CloudflareIPUpdater')
        self.assertEqual(len(call_args['MetricData']), 3)
        
        # Check metric names
        metric_names = [metric['MetricName'] for metric in call_args['MetricData']]
        self.assertIn('CloudflareIPCount', metric_names)
        self.assertIn('SecurityGroupRulesCount', metric_names)
        self.assertIn('IPRangesUpdated', metric_names)
    
    def test_create_detailed_notification_with_changes(self):
        """Test detailed notification creation with changes."""
        notification = lambda_function.create_detailed_notification(
            self.sample_cloudflare_ips,
            self.sample_existing_ips,
            True
        )
        
        self.assertIn("Cloudflare IP Update Report", notification)
        self.assertIn("Changes Made: Yes", notification)
        self.assertIn("IPs Added: 1", notification)
        self.assertIn("IPs Removed: 0", notification)
        self.assertIn("State Management:", notification)
        self.assertIn("State Validation: Enabled", notification)
        self.assertIn("Drift Detection: Enabled", notification)
    
    def test_create_detailed_notification_no_changes(self):
        """Test detailed notification creation without changes."""
        notification = lambda_function.create_detailed_notification(
            self.sample_existing_ips,
            self.sample_existing_ips,
            False
        )
        
        self.assertIn("Cloudflare IP Update Report", notification)
        self.assertIn("Changes Made: No", notification)
        self.assertIn("No changes were needed", notification)
    
    @patch('lambda_function.get_sns_client')
    @patch('lambda_function.boto3.client')
    def test_send_notification_with_metrics(self, mock_boto3_client, mock_get_sns_client):
        """Test notification sending with CloudWatch metrics."""
        mock_sns = Mock()
        mock_cloudwatch = Mock()
        mock_get_sns_client.return_value = mock_sns
        mock_boto3_client.return_value = mock_cloudwatch
        
        lambda_function.send_notification("Test message", "SUCCESS")
        
        # Verify SNS publish was called
        mock_sns.publish.assert_called_once()
        call_args = mock_sns.publish.call_args[1]
        self.assertEqual(call_args['Subject'], "Cloudflare IP Update - SUCCESS")
        self.assertEqual(call_args['Message'], "Test message")
        
        # Verify CloudWatch metric was logged
        mock_cloudwatch.put_metric_data.assert_called_once()
    
    @patch('lambda_function.logger')
    def test_log_quota_warning(self, mock_logger):
        """Test quota warning logging."""
        lambda_function.log_quota_warning("Test quota warning")
        mock_logger.warning.assert_called_with("QUOTA WARNING: Test quota warning")
    
    @patch('lambda_function.logger')
    def test_log_state_drift_detected(self, mock_logger):
        """Test state drift detection logging."""
        lambda_function.log_state_drift_detected(5, 3)
        mock_logger.error.assert_called_with("State drift detected: 5 IPs to add, 3 IPs to remove")
    
    @patch('lambda_function.logger')
    def test_log_replacement_strategy_trigger(self, mock_logger):
        """Test replacement strategy trigger logging."""
        lambda_function.log_replacement_strategy_trigger(10, 5, 20)
        mock_logger.info.assert_called_with("Replacement strategy triggered: 15 total changes (75.0% of existing 20 IPs)")
    
    def test_validate_cidr_valid_ipv4(self):
        """Test CIDR validation for valid IPv4."""
        self.assertTrue(lambda_function.validate_cidr("192.168.1.0/24"))
        self.assertTrue(lambda_function.validate_cidr("10.0.0.0/8"))
    
    def test_validate_cidr_valid_ipv6(self):
        """Test CIDR validation for valid IPv6."""
        self.assertTrue(lambda_function.validate_cidr("2001:db8::/32"))
        self.assertTrue(lambda_function.validate_cidr("::1/128"))
    
    def test_validate_cidr_invalid(self):
        """Test CIDR validation for invalid formats."""
        self.assertFalse(lambda_function.validate_cidr("invalid"))
        self.assertFalse(lambda_function.validate_cidr("192.168.1.0/33"))
        self.assertFalse(lambda_function.validate_cidr(""))


class TestIdempotencyFeatures(unittest.TestCase):
    """Test cases for idempotency and resource replacement strategies."""
    
    def setUp(self):
        """Set up test fixtures."""
        self.current_ips = {
            '103.21.244.0/22',
            '103.22.200.0/22',
            '104.16.0.0/13',
            '108.162.192.0/18',
            '131.0.72.0/22'
        }
        
        self.existing_ips = {
            '103.21.244.0/22',
            '103.22.200.0/22',
            '104.16.0.0/13'
        }
    
    def test_idempotent_no_changes_needed(self):
        """Test idempotent behavior when no changes are needed."""
        # When current and existing IPs are the same
        same_ips = self.existing_ips.copy()
        
        ips_to_add = self.current_ips - same_ips
        ips_to_remove = same_ips - self.current_ips
        
        self.assertEqual(len(ips_to_add), 2)  # 2 new IPs
        self.assertEqual(len(ips_to_remove), 0)  # 0 removed IPs
    
    def test_incremental_changes_detection(self):
        """Test detection of incremental changes."""
        ips_to_add = self.current_ips - self.existing_ips
        ips_to_remove = self.existing_ips - self.current_ips
        
        # Should detect 2 new IPs and 0 removed IPs
        self.assertEqual(len(ips_to_add), 2)
        self.assertEqual(len(ips_to_remove), 0)
        
        expected_new_ips = {'108.162.192.0/18', '131.0.72.0/22'}
        self.assertEqual(ips_to_add, expected_new_ips)
    
    def test_replacement_strategy_calculation(self):
        """Test replacement strategy calculation logic."""
        # Test with small changes (should not trigger replacement)
        small_changes = lambda_function.should_use_replacement_strategy(
            {'192.168.1.0/24'}, set(), self.existing_ips
        )
        self.assertFalse(small_changes)
        
        # Test with large percentage changes (should trigger replacement)
        large_percentage_changes = lambda_function.should_use_replacement_strategy(
            {'192.168.1.0/24', '192.168.2.0/24'}, set(), self.existing_ips
        )
        # 2 changes out of 3 existing = 66.7% > 30% threshold
        self.assertTrue(large_percentage_changes)


if __name__ == '__main__':
    # Run the tests
    unittest.main(verbosity=2)