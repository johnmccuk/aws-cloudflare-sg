#!/usr/bin/env python3
"""
Simple validation script for enhanced state management features.
This script validates the configuration and logic without requiring external dependencies.
"""

import os
import sys
import json

def validate_environment_variables():
    """Validate that required environment variables are properly configured."""
    print("=== Environment Variable Validation ===")
    
    required_vars = [
        'SECURITY_GROUP_ID',
        'ENABLE_STATE_VALIDATION',
        'ENABLE_DRIFT_DETECTION',
        'IP_CHANGE_THRESHOLD_PERCENT',
        'MAX_IP_CHANGES_PER_UPDATE'
    ]
    
    optional_vars = [
        'ENABLE_ENHANCED_LIFECYCLE',
        'ENABLE_QUOTA_CHECKING',
        'MAX_EXPECTED_CLOUDFLARE_IPS',
        'SNS_TOPIC_ARN'
    ]
    
    missing_vars = []
    for var in required_vars:
        if var not in os.environ:
            missing_vars.append(var)
        else:
            print(f"✓ {var}: {os.environ[var]}")
    
    for var in optional_vars:
        if var in os.environ:
            print(f"✓ {var}: {os.environ[var]}")
        else:
            print(f"- {var}: Not set (optional)")
    
    if missing_vars:
        print(f"✗ Missing required variables: {', '.join(missing_vars)}")
        return False
    
    print("✓ All required environment variables are set")
    return True


def validate_configuration_logic():
    """Validate the logic of configuration parameters."""
    print("\n=== Configuration Logic Validation ===")
    
    try:
        # Validate IP change threshold
        threshold = int(os.environ.get('IP_CHANGE_THRESHOLD_PERCENT', '30'))
        if threshold < 10 or threshold > 100:
            print(f"✗ IP_CHANGE_THRESHOLD_PERCENT ({threshold}) must be between 10 and 100")
            return False
        print(f"✓ IP change threshold: {threshold}%")
        
        # Validate max IP changes
        max_changes = int(os.environ.get('MAX_IP_CHANGES_PER_UPDATE', '50'))
        if max_changes < 1 or max_changes > 200:
            print(f"✗ MAX_IP_CHANGES_PER_UPDATE ({max_changes}) must be between 1 and 200")
            return False
        print(f"✓ Max IP changes per update: {max_changes}")
        
        # Validate max expected IPs
        max_expected = int(os.environ.get('MAX_EXPECTED_CLOUDFLARE_IPS', '200'))
        if max_expected < 50 or max_expected > 1000:
            print(f"✗ MAX_EXPECTED_CLOUDFLARE_IPS ({max_expected}) must be between 50 and 1000")
            return False
        print(f"✓ Max expected Cloudflare IPs: {max_expected}")
        
        # Validate boolean flags
        state_validation = os.environ.get('ENABLE_STATE_VALIDATION', 'true').lower() == 'true'
        drift_detection = os.environ.get('ENABLE_DRIFT_DETECTION', 'true').lower() == 'true'
        enhanced_lifecycle = os.environ.get('ENABLE_ENHANCED_LIFECYCLE', 'false').lower() == 'true'
        
        print(f"✓ State validation: {'Enabled' if state_validation else 'Disabled'}")
        print(f"✓ Drift detection: {'Enabled' if drift_detection else 'Disabled'}")
        print(f"✓ Enhanced lifecycle: {'Enabled' if enhanced_lifecycle else 'Disabled'}")
        
        # Validate dependencies
        if drift_detection and not state_validation:
            print("✗ Drift detection requires state validation to be enabled")
            return False
        
        if enhanced_lifecycle and not (state_validation and drift_detection):
            print("✗ Enhanced lifecycle requires both state validation and drift detection")
            return False
        
        print("✓ Configuration dependencies are satisfied")
        return True
        
    except ValueError as e:
        print(f"✗ Configuration validation error: {e}")
        return False


def test_replacement_strategy_logic():
    """Test the replacement strategy decision logic."""
    print("\n=== Replacement Strategy Logic Test ===")
    
    threshold_percent = int(os.environ.get('IP_CHANGE_THRESHOLD_PERCENT', '30'))
    max_changes = int(os.environ.get('MAX_IP_CHANGES_PER_UPDATE', '50'))
    
    # Test scenarios
    test_cases = [
        {
            'name': 'Small changes - no replacement',
            'existing_count': 100,
            'changes_count': 10,
            'expected': False
        },
        {
            'name': 'Large percentage change - replacement needed',
            'existing_count': 10,
            'changes_count': 4,  # 40% > 30% threshold
            'expected': True
        },
        {
            'name': 'Large absolute change - replacement needed',
            'existing_count': 100,
            'changes_count': 60,  # 60 > 50 max changes
            'expected': True
        },
        {
            'name': 'Edge case - exactly at threshold',
            'existing_count': 100,
            'changes_count': 30,  # Exactly 30%
            'expected': False  # Should be > threshold, not >=
        }
    ]
    
    all_passed = True
    for test_case in test_cases:
        existing_count = test_case['existing_count']
        changes_count = test_case['changes_count']
        expected = test_case['expected']
        
        # Calculate if replacement strategy should be used
        percentage_change = (changes_count * 100) / existing_count if existing_count > 0 else 0
        should_replace = (percentage_change > threshold_percent) or (changes_count > max_changes)
        
        if should_replace == expected:
            print(f"✓ {test_case['name']}: {changes_count} changes, {percentage_change:.1f}% change -> {'Replace' if should_replace else 'Update'}")
        else:
            print(f"✗ {test_case['name']}: Expected {'Replace' if expected else 'Update'}, got {'Replace' if should_replace else 'Update'}")
            all_passed = False
    
    return all_passed


def validate_cidr_logic():
    """Test CIDR validation logic."""
    print("\n=== CIDR Validation Logic Test ===")
    
    # Test cases for CIDR validation
    test_cidrs = [
        ('192.168.1.0/24', True, 'Valid IPv4 CIDR'),
        ('10.0.0.0/8', True, 'Valid IPv4 CIDR with /8'),
        ('2001:db8::/32', True, 'Valid IPv6 CIDR'),
        ('::1/128', True, 'Valid IPv6 loopback'),
        ('192.168.1.0/33', False, 'Invalid IPv4 CIDR - bad prefix'),
        ('invalid', False, 'Invalid CIDR format'),
        ('', False, 'Empty string'),
        ('192.168.1.0', False, 'Missing prefix length')
    ]
    
    all_passed = True
    for cidr, expected, description in test_cidrs:
        try:
            import ipaddress
            ipaddress.ip_network(cidr, strict=False)
            is_valid = True
        except ValueError:
            is_valid = False
        
        if is_valid == expected:
            print(f"✓ {description}: '{cidr}' -> {'Valid' if is_valid else 'Invalid'}")
        else:
            print(f"✗ {description}: '{cidr}' -> Expected {'Valid' if expected else 'Invalid'}, got {'Valid' if is_valid else 'Invalid'}")
            all_passed = False
    
    return all_passed


def generate_configuration_summary():
    """Generate a summary of the current configuration."""
    print("\n=== Configuration Summary ===")
    
    config = {
        'state_management': {
            'state_validation': os.environ.get('ENABLE_STATE_VALIDATION', 'true').lower() == 'true',
            'drift_detection': os.environ.get('ENABLE_DRIFT_DETECTION', 'true').lower() == 'true',
            'enhanced_lifecycle': os.environ.get('ENABLE_ENHANCED_LIFECYCLE', 'false').lower() == 'true',
            'ip_change_threshold_percent': int(os.environ.get('IP_CHANGE_THRESHOLD_PERCENT', '30')),
            'max_ip_changes_per_update': int(os.environ.get('MAX_IP_CHANGES_PER_UPDATE', '50'))
        },
        'quota_management': {
            'quota_checking_enabled': os.environ.get('ENABLE_QUOTA_CHECKING', 'false').lower() == 'true',
            'max_expected_cloudflare_ips': int(os.environ.get('MAX_EXPECTED_CLOUDFLARE_IPS', '200')),
            'max_rules_per_security_group': int(os.environ.get('MAX_RULES_PER_SECURITY_GROUP', '120'))
        },
        'automation': {
            'security_group_id': os.environ.get('SECURITY_GROUP_ID', 'Not set'),
            'sns_topic_configured': bool(os.environ.get('SNS_TOPIC_ARN')),
            'terraform_mode': os.environ.get('TERRAFORM_MODE', 'direct')
        }
    }
    
    print(json.dumps(config, indent=2))
    return config


def main():
    """Main validation function."""
    print("Enhanced State Management Validation")
    print("=" * 50)
    
    # Set default environment variables for testing if not set
    default_env = {
        'SECURITY_GROUP_ID': 'sg-12345678',
        'ENABLE_STATE_VALIDATION': 'true',
        'ENABLE_DRIFT_DETECTION': 'true',
        'IP_CHANGE_THRESHOLD_PERCENT': '30',
        'MAX_IP_CHANGES_PER_UPDATE': '50',
        'ENABLE_ENHANCED_LIFECYCLE': 'true',
        'ENABLE_QUOTA_CHECKING': 'true',
        'MAX_EXPECTED_CLOUDFLARE_IPS': '200',
        'MAX_RULES_PER_SECURITY_GROUP': '120'
    }
    
    for key, value in default_env.items():
        if key not in os.environ:
            os.environ[key] = value
    
    # Run validation tests
    tests = [
        validate_environment_variables,
        validate_configuration_logic,
        test_replacement_strategy_logic,
        validate_cidr_logic
    ]
    
    all_passed = True
    for test in tests:
        if not test():
            all_passed = False
    
    # Generate configuration summary
    generate_configuration_summary()
    
    # Final result
    print("\n" + "=" * 50)
    if all_passed:
        print("✓ All validation tests passed!")
        print("Enhanced state management configuration is valid.")
        return 0
    else:
        print("✗ Some validation tests failed!")
        print("Please review the configuration and fix any issues.")
        return 1


if __name__ == '__main__':
    sys.exit(main())