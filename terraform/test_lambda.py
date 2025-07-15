#!/usr/bin/env python3
"""
Test script for the Lambda function to validate syntax and basic functionality.
"""

import sys
import os
import json
from unittest.mock import Mock, patch, MagicMock

# Add the current directory to Python path
sys.path.insert(0, os.path.dirname(__file__))

def test_lambda_imports():
    """Test that all imports work correctly."""
    try:
        import lambda_function
        print("✓ All imports successful")
        return True
    except ImportError as e:
        print(f"✗ Import error: {e}")
        return False

def test_validate_cidr():
    """Test CIDR validation function."""
    try:
        from lambda_function import validate_cidr
        
        # Test valid CIDRs
        assert validate_cidr("192.168.1.0/24") == True
        assert validate_cidr("10.0.0.0/8") == True
        assert validate_cidr("2001:db8::/32") == True
        
        # Test invalid CIDRs
        assert validate_cidr("invalid") == False
        assert validate_cidr("192.168.1.0/33") == False
        assert validate_cidr("") == False
        
        print("✓ CIDR validation tests passed")
        return True
    except Exception as e:
        print(f"✗ CIDR validation test failed: {e}")
        return False

def test_fetch_ip_ranges_with_retry():
    """Test IP range fetching with mocked requests."""
    try:
        from lambda_function import fetch_ip_ranges_with_retry
        
        # Mock successful response
        mock_response = Mock()
        mock_response.text = "192.168.1.0/24\n10.0.0.0/8\n# Comment line\n\n"
        mock_response.raise_for_status = Mock()
        
        with patch('lambda_function.requests.get', return_value=mock_response):
            result = fetch_ip_ranges_with_retry("http://test.com", "IPv4")
            expected = {"192.168.1.0/24", "10.0.0.0/8"}
            assert result == expected
        
        print("✓ IP range fetching test passed")
        return True
    except Exception as e:
        print(f"✗ IP range fetching test failed: {e}")
        return False

def test_build_ip_permission():
    """Test IP permission building."""
    try:
        from lambda_function import build_ip_permission
        
        # Test IPv4
        ipv4_perm = build_ip_permission("192.168.1.0/24", 443, "tcp")
        assert ipv4_perm['IpProtocol'] == 'tcp'
        assert ipv4_perm['FromPort'] == 443
        assert ipv4_perm['ToPort'] == 443
        assert 'IpRanges' in ipv4_perm
        assert ipv4_perm['IpRanges'][0]['CidrIp'] == '192.168.1.0/24'
        
        # Test IPv6
        ipv6_perm = build_ip_permission("2001:db8::/32", 443, "tcp")
        assert 'Ipv6Ranges' in ipv6_perm
        assert ipv6_perm['Ipv6Ranges'][0]['CidrIpv6'] == '2001:db8::/32'
        
        print("✓ IP permission building test passed")
        return True
    except Exception as e:
        print(f"✗ IP permission building test failed: {e}")
        return False

def test_lambda_handler_structure():
    """Test that lambda handler has correct structure."""
    try:
        # Mock environment variables at module level
        with patch.dict('lambda_function.os.environ', {
            'SECURITY_GROUP_ID': 'sg-12345678',
            'SNS_TOPIC_ARN': 'arn:aws:sns:us-east-1:123456789012:test',
            'MAX_RETRIES': '3',
            'RETRY_DELAY': '5'
        }):
            # Re-import to pick up environment variables
            import importlib
            import lambda_function
            importlib.reload(lambda_function)
            
            # Mock AWS client functions
            with patch('lambda_function.get_ec2_client') as mock_ec2, \
                 patch('lambda_function.get_sns_client') as mock_sns, \
                 patch('lambda_function.fetch_cloudflare_ips') as mock_fetch, \
                 patch('lambda_function.get_existing_security_group_ips') as mock_existing, \
                 patch('lambda_function.update_security_group_if_needed') as mock_update, \
                 patch('lambda_function.send_notification') as mock_notify:
                
                mock_fetch.return_value = {"192.168.1.0/24", "10.0.0.0/8"}
                mock_existing.return_value = {"192.168.1.0/24"}
                mock_update.return_value = True
                
                result = lambda_function.lambda_handler({}, {})
                
                assert result['statusCode'] == 200
                assert 'body' in result
                body = json.loads(result['body'])
                assert 'message' in body
                assert 'changes_made' in body
                assert 'ip_count' in body
        
        print("✓ Lambda handler structure test passed")
        return True
    except Exception as e:
        print(f"✗ Lambda handler structure test failed: {e}")
        return False

def main():
    """Run all tests."""
    print("Testing Lambda function...")
    print("=" * 50)
    
    tests = [
        test_lambda_imports,
        test_validate_cidr,
        test_fetch_ip_ranges_with_retry,
        test_build_ip_permission,
        test_lambda_handler_structure
    ]
    
    passed = 0
    total = len(tests)
    
    for test in tests:
        if test():
            passed += 1
        print()
    
    print("=" * 50)
    print(f"Tests passed: {passed}/{total}")
    
    if passed == total:
        print("✓ All tests passed! Lambda function is ready.")
        return True
    else:
        print("✗ Some tests failed. Please review the code.")
        return False

if __name__ == "__main__":
    success = main()
    sys.exit(0 if success else 1)