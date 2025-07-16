import json
import boto3
import requests
import logging
import time
import subprocess
import tempfile
import shutil
from typing import List, Set, Dict, Any
from botocore.exceptions import ClientError, BotoCoreError
import os

# Configure logging
logger = logging.getLogger()
logger.setLevel(logging.INFO)

# AWS clients will be initialized when needed
ec2_client = None
sns_client = None

def get_ec2_client():
    """Get EC2 client, initializing if needed."""
    global ec2_client
    if ec2_client is None:
        ec2_client = boto3.client('ec2')
    return ec2_client

def get_sns_client():
    """Get SNS client, initializing if needed."""
    global sns_client
    if sns_client is None:
        sns_client = boto3.client('sns')
    return sns_client

# Configuration from environment variables
SECURITY_GROUP_ID = os.environ.get('SECURITY_GROUP_ID')
SNS_TOPIC_ARN = os.environ.get('SNS_TOPIC_ARN', '')
MAX_RETRIES = int(os.environ.get('MAX_RETRIES', '3'))
RETRY_DELAY = int(os.environ.get('RETRY_DELAY', '5'))

# State management configuration
ENABLE_STATE_VALIDATION = os.environ.get('ENABLE_STATE_VALIDATION', 'true').lower() == 'true'
ENABLE_DRIFT_DETECTION = os.environ.get('ENABLE_DRIFT_DETECTION', 'true').lower() == 'true'
IP_CHANGE_THRESHOLD_PERCENT = int(os.environ.get('IP_CHANGE_THRESHOLD_PERCENT', '30'))
MAX_IP_CHANGES_PER_UPDATE = int(os.environ.get('MAX_IP_CHANGES_PER_UPDATE', '50'))
ENABLE_ENHANCED_LIFECYCLE = os.environ.get('ENABLE_ENHANCED_LIFECYCLE', 'false').lower() == 'true'

# Quota management configuration
ENABLE_QUOTA_CHECKING = os.environ.get('ENABLE_QUOTA_CHECKING', 'false').lower() == 'true'
MAX_RULES_PER_SECURITY_GROUP = int(os.environ.get('MAX_RULES_PER_SECURITY_GROUP', '120'))
MAX_SECURITY_GROUPS_PER_VPC = int(os.environ.get('MAX_SECURITY_GROUPS_PER_VPC', '2500'))
CURRENT_SECURITY_GROUPS_COUNT = int(os.environ.get('CURRENT_SECURITY_GROUPS_COUNT', '0'))
REQUIRES_MULTIPLE_GROUPS = os.environ.get('REQUIRES_MULTIPLE_GROUPS', 'false').lower() == 'true'
SECURITY_GROUPS_NEEDED = int(os.environ.get('SECURITY_GROUPS_NEEDED', '1'))
RULES_APPROACHING_LIMIT = os.environ.get('RULES_APPROACHING_LIMIT', 'false').lower() == 'true'
MAX_EXPECTED_CLOUDFLARE_IPS = int(os.environ.get('MAX_EXPECTED_CLOUDFLARE_IPS', '200'))

# Terraform automation configuration
TERRAFORM_MODE = os.environ.get('TERRAFORM_MODE', 'direct')  # 'direct' or 'cloud'
TERRAFORM_CLOUD_TOKEN = os.environ.get('TERRAFORM_CLOUD_TOKEN', '')
TERRAFORM_WORKSPACE = os.environ.get('TERRAFORM_WORKSPACE', '')
TERRAFORM_ORGANIZATION = os.environ.get('TERRAFORM_ORGANIZATION', '')
TERRAFORM_CONFIG_S3_BUCKET = os.environ.get('TERRAFORM_CONFIG_S3_BUCKET', '')
TERRAFORM_CONFIG_S3_KEY = os.environ.get('TERRAFORM_CONFIG_S3_KEY', '')
TERRAFORM_STATE_S3_BUCKET = os.environ.get('TERRAFORM_STATE_S3_BUCKET', '')
TERRAFORM_STATE_S3_KEY = os.environ.get('TERRAFORM_STATE_S3_KEY', '')

# Cloudflare IP endpoints
CLOUDFLARE_IPV4_URL = "https://www.cloudflare.com/ips-v4"
CLOUDFLARE_IPV6_URL = "https://www.cloudflare.com/ips-v6"


def lambda_handler(event, context):
    """
    Main Lambda handler function for updating Cloudflare IP ranges in security group.
    """
    try:
        logger.info("Starting Cloudflare IP update process")
        
        # Validate required environment variables
        if not SECURITY_GROUP_ID:
            raise ValueError("SECURITY_GROUP_ID environment variable is required")
        
        # Perform quota validation if enabled
        if ENABLE_QUOTA_CHECKING:
            validate_aws_service_quotas()
        
        # Fetch current Cloudflare IP ranges
        current_ips = fetch_cloudflare_ips()
        logger.info(f"Retrieved {len(current_ips)} Cloudflare IP ranges")
        
        # Validate IP count against expected maximum
        if ENABLE_QUOTA_CHECKING and len(current_ips) > MAX_EXPECTED_CLOUDFLARE_IPS:
            logger.warning(f"Cloudflare IP count ({len(current_ips)}) exceeds expected maximum ({MAX_EXPECTED_CLOUDFLARE_IPS})")
            log_quota_warning(f"Cloudflare IP count exceeds expected maximum: {len(current_ips)} > {MAX_EXPECTED_CLOUDFLARE_IPS}")
        
        # Get existing security group rules
        existing_ips = get_existing_security_group_ips()
        logger.info(f"Found {len(existing_ips)} existing IP ranges in security group")
        
        # Perform state validation and drift detection if enabled
        if ENABLE_STATE_VALIDATION or ENABLE_DRIFT_DETECTION:
            perform_state_validation(current_ips, existing_ips)
        
        # Compare IP sets to determine if changes are needed
        ips_to_add = current_ips - existing_ips
        ips_to_remove = existing_ips - current_ips
        
        if not ips_to_add and not ips_to_remove:
            logger.info("No changes needed - IP ranges are up to date")
            changes_made = False
        else:
            logger.info(f"Changes detected: {len(ips_to_add)} IPs to add, {len(ips_to_remove)} IPs to remove")
            
            # Check if changes require replacement strategy
            if should_use_replacement_strategy(ips_to_add, ips_to_remove, existing_ips):
                logger.info("Replacement strategy triggered due to significant IP changes")
                log_replacement_strategy_trigger(len(ips_to_add), len(ips_to_remove), len(existing_ips))
            
            # Trigger Terraform automation to apply changes
            changes_made = trigger_terraform_automation(current_ips, existing_ips)
        
        # Log CloudWatch custom metrics for monitoring
        log_cloudwatch_metrics(current_ips, existing_ips, changes_made)
        
        # Send notification for both successful changes and no-change scenarios
        if SNS_TOPIC_ARN:
            notification_details = create_detailed_notification(current_ips, existing_ips, changes_made)
            send_notification(notification_details, "SUCCESS")
        
        return {
            'statusCode': 200,
            'body': json.dumps({
                'message': 'Cloudflare IP update completed successfully',
                'changes_made': changes_made,
                'ip_count': len(current_ips),
                'state_validation_enabled': ENABLE_STATE_VALIDATION,
                'drift_detection_enabled': ENABLE_DRIFT_DETECTION
            })
        }
        
    except Exception as e:
        error_msg = f"Error updating Cloudflare IPs: {str(e)}"
        logger.error(error_msg, exc_info=True)
        
        # Send error notification
        if SNS_TOPIC_ARN:
            send_notification(f"ERROR: {error_msg}", "ERROR")
        
        return {
            'statusCode': 500,
            'body': json.dumps({
                'error': error_msg
            })
        }


def fetch_cloudflare_ips() -> Set[str]:
    """
    Fetch current Cloudflare IP ranges from official APIs with retry logic.
    """
    all_ips = set()
    
    # Fetch IPv4 ranges
    ipv4_ranges = fetch_ip_ranges_with_retry(CLOUDFLARE_IPV4_URL, "IPv4")
    all_ips.update(ipv4_ranges)
    
    # Fetch IPv6 ranges
    ipv6_ranges = fetch_ip_ranges_with_retry(CLOUDFLARE_IPV6_URL, "IPv6")
    all_ips.update(ipv6_ranges)
    
    return all_ips


def fetch_ip_ranges_with_retry(url: str, ip_type: str) -> Set[str]:
    """
    Fetch IP ranges from a URL with retry logic and error handling.
    """
    for attempt in range(MAX_RETRIES):
        try:
            logger.info(f"Fetching {ip_type} ranges from {url} (attempt {attempt + 1})")
            
            response = requests.get(url, timeout=30)
            response.raise_for_status()
            
            # Parse and validate IP ranges
            ip_ranges = set()
            for line in response.text.strip().split('\n'):
                line = line.strip()
                if line and not line.startswith('#'):
                    # Basic CIDR validation
                    if validate_cidr(line):
                        ip_ranges.add(line)
                    else:
                        logger.warning(f"Invalid CIDR format: {line}")
            
            logger.info(f"Successfully fetched {len(ip_ranges)} {ip_type} ranges")
            return ip_ranges
            
        except requests.exceptions.RequestException as e:
            logger.warning(f"Attempt {attempt + 1} failed for {ip_type}: {str(e)}")
            if attempt < MAX_RETRIES - 1:
                time.sleep(RETRY_DELAY * (2 ** attempt))  # Exponential backoff
            else:
                raise Exception(f"Failed to fetch {ip_type} ranges after {MAX_RETRIES} attempts: {str(e)}")
        
        except Exception as e:
            logger.error(f"Unexpected error fetching {ip_type} ranges: {str(e)}")
            raise


def validate_cidr(cidr: str) -> bool:
    """
    Basic CIDR format validation.
    """
    try:
        import ipaddress
        ipaddress.ip_network(cidr, strict=False)
        return True
    except ValueError:
        return False


def get_existing_security_group_ips() -> Set[str]:
    """
    Get existing IP ranges from the security group rules.
    """
    try:
        response = get_ec2_client().describe_security_groups(GroupIds=[SECURITY_GROUP_ID])
        
        if not response['SecurityGroups']:
            raise Exception(f"Security group {SECURITY_GROUP_ID} not found")
        
        security_group = response['SecurityGroups'][0]
        existing_ips = set()
        
        # Extract CIDR blocks from ingress rules
        for rule in security_group.get('IpRanges', []):
            if rule.get('CidrIp'):
                existing_ips.add(rule['CidrIp'])
        
        # Extract IPv6 CIDR blocks from ingress rules
        for rule in security_group.get('Ipv6Ranges', []):
            if rule.get('CidrIpv6'):
                existing_ips.add(rule['CidrIpv6'])
        
        return existing_ips
        
    except ClientError as e:
        logger.error(f"AWS API error getting security group: {str(e)}")
        raise
    except Exception as e:
        logger.error(f"Error getting existing security group IPs: {str(e)}")
        raise


def update_security_group_if_needed(current_ips: Set[str], existing_ips: Set[str]) -> bool:
    """
    Update security group rules if IP ranges have changed.
    Returns True if changes were made, False otherwise.
    """
    # Compare IP sets
    ips_to_add = current_ips - existing_ips
    ips_to_remove = existing_ips - current_ips
    
    if not ips_to_add and not ips_to_remove:
        logger.info("No changes needed - IP ranges are up to date")
        return False
    
    logger.info(f"Changes detected: {len(ips_to_add)} IPs to add, {len(ips_to_remove)} IPs to remove")
    
    try:
        # Get current security group configuration for ports and protocol
        sg_info = get_security_group_config()
        
        # Remove outdated rules
        if ips_to_remove:
            remove_security_group_rules(ips_to_remove, sg_info)
        
        # Add new rules
        if ips_to_add:
            add_security_group_rules(ips_to_add, sg_info)
        
        logger.info("Security group updated successfully")
        return True
        
    except Exception as e:
        logger.error(f"Error updating security group: {str(e)}")
        raise


def get_security_group_config() -> Dict[str, Any]:
    """
    Get security group configuration including ports and protocols.
    """
    try:
        response = get_ec2_client().describe_security_groups(GroupIds=[SECURITY_GROUP_ID])
        security_group = response['SecurityGroups'][0]
        
        # Extract port and protocol information from existing rules
        ports = set()
        protocols = set()
        
        for rule in security_group.get('IpPermissions', []):
            if rule.get('FromPort') is not None:
                ports.add(rule['FromPort'])
            if rule.get('IpProtocol'):
                protocols.add(rule['IpProtocol'])
        
        # Default to HTTPS if no existing rules
        if not ports:
            ports.add(443)
        if not protocols:
            protocols.add('tcp')
        
        return {
            'ports': list(ports),
            'protocols': list(protocols)
        }
        
    except Exception as e:
        logger.error(f"Error getting security group config: {str(e)}")
        # Return defaults
        return {'ports': [443], 'protocols': ['tcp']}


def remove_security_group_rules(ips_to_remove: Set[str], sg_config: Dict[str, Any]):
    """
    Remove outdated security group rules.
    """
    for ip in ips_to_remove:
        for port in sg_config['ports']:
            for protocol in sg_config['protocols']:
                try:
                    ip_permissions = build_ip_permission(ip, port, protocol)
                    
                    get_ec2_client().revoke_security_group_ingress(
                        GroupId=SECURITY_GROUP_ID,
                        IpPermissions=[ip_permissions]
                    )
                    logger.info(f"Removed rule for {ip}:{port}/{protocol}")
                    
                except ClientError as e:
                    if e.response['Error']['Code'] != 'InvalidPermission.NotFound':
                        logger.error(f"Error removing rule for {ip}:{port}/{protocol}: {str(e)}")
                        raise


def add_security_group_rules(ips_to_add: Set[str], sg_config: Dict[str, Any]):
    """
    Add new security group rules.
    """
    for ip in ips_to_add:
        for port in sg_config['ports']:
            for protocol in sg_config['protocols']:
                try:
                    ip_permissions = build_ip_permission(ip, port, protocol)
                    
                    get_ec2_client().authorize_security_group_ingress(
                        GroupId=SECURITY_GROUP_ID,
                        IpPermissions=[ip_permissions]
                    )
                    logger.info(f"Added rule for {ip}:{port}/{protocol}")
                    
                except ClientError as e:
                    if e.response['Error']['Code'] != 'InvalidPermission.Duplicate':
                        logger.error(f"Error adding rule for {ip}:{port}/{protocol}: {str(e)}")
                        raise


def build_ip_permission(ip: str, port: int, protocol: str) -> Dict[str, Any]:
    """
    Build IP permission object for security group rule.
    """
    permission = {
        'IpProtocol': protocol,
        'FromPort': port,
        'ToPort': port
    }
    
    # Determine if IPv4 or IPv6
    if ':' in ip:
        permission['Ipv6Ranges'] = [{'CidrIpv6': ip, 'Description': f'Cloudflare IP range {ip}'}]
    else:
        permission['IpRanges'] = [{'CidrIp': ip, 'Description': f'Cloudflare IP range {ip}'}]
    
    return permission


def trigger_terraform_automation(current_ips: Set[str], existing_ips: Set[str]) -> bool:
    """
    Trigger Terraform automation to apply IP changes.
    Returns True if changes were successfully applied, False otherwise.
    """
    try:
        logger.info("Starting Terraform automation process")
        
        # Log detailed change information
        ips_to_add = current_ips - existing_ips
        ips_to_remove = existing_ips - current_ips
        
        logger.info(f"Terraform automation triggered with changes:")
        logger.info(f"  - Current Cloudflare IPs: {len(current_ips)}")
        logger.info(f"  - Existing security group IPs: {len(existing_ips)}")
        logger.info(f"  - IPs to add: {len(ips_to_add)}")
        logger.info(f"  - IPs to remove: {len(ips_to_remove)}")
        
        if ips_to_add:
            logger.info(f"New IP ranges to add: {sorted(list(ips_to_add))}")
        if ips_to_remove:
            logger.info(f"Outdated IP ranges to remove: {sorted(list(ips_to_remove))}")
        
        # Validate secure credential handling
        validate_terraform_credentials()
        
        # Execute Terraform automation based on mode
        if TERRAFORM_MODE == 'cloud':
            success = trigger_terraform_cloud(current_ips, existing_ips)
        else:
            success = trigger_terraform_local(current_ips, existing_ips)
        
        # Log automation results
        if success:
            logger.info("Terraform automation completed successfully")
            logger.info(f"Security group now configured with {len(current_ips)} Cloudflare IP ranges")
        else:
            logger.error("Terraform automation failed")
            
        return success
            
    except Exception as e:
        logger.error(f"Error in Terraform automation: {str(e)}")
        raise


def validate_terraform_credentials():
    """
    Validate that Terraform credentials are properly configured and secure.
    """
    try:
        logger.info("Validating Terraform credentials and configuration")
        
        if TERRAFORM_MODE == 'cloud':
            # Validate Terraform Cloud credentials
            if not TERRAFORM_CLOUD_TOKEN:
                raise ValueError("TERRAFORM_CLOUD_TOKEN is required for cloud mode but not configured")
            
            if len(TERRAFORM_CLOUD_TOKEN) < 20:
                raise ValueError("TERRAFORM_CLOUD_TOKEN appears to be invalid (too short)")
            
            if not TERRAFORM_WORKSPACE:
                raise ValueError("TERRAFORM_WORKSPACE is required for cloud mode but not configured")
            
            if not TERRAFORM_ORGANIZATION:
                raise ValueError("TERRAFORM_ORGANIZATION is required for cloud mode but not configured")
            
            logger.info("Terraform Cloud credentials validated successfully")
            
        else:
            # Validate local Terraform configuration
            if TERRAFORM_CONFIG_S3_BUCKET and not TERRAFORM_CONFIG_S3_KEY:
                raise ValueError("TERRAFORM_CONFIG_S3_KEY is required when TERRAFORM_CONFIG_S3_BUCKET is specified")
            
            if TERRAFORM_STATE_S3_BUCKET and not TERRAFORM_STATE_S3_KEY:
                raise ValueError("TERRAFORM_STATE_S3_KEY is required when TERRAFORM_STATE_S3_BUCKET is specified")
            
            # Validate S3 access if configuration is provided
            if TERRAFORM_CONFIG_S3_BUCKET:
                validate_s3_access(TERRAFORM_CONFIG_S3_BUCKET, TERRAFORM_CONFIG_S3_KEY)
            
            if TERRAFORM_STATE_S3_BUCKET and TERRAFORM_STATE_S3_BUCKET != TERRAFORM_CONFIG_S3_BUCKET:
                validate_s3_access(TERRAFORM_STATE_S3_BUCKET, TERRAFORM_STATE_S3_KEY)
            
            logger.info("Local Terraform configuration validated successfully")
        
        # Validate AWS credentials are available
        try:
            # Test AWS credentials by making a simple API call
            get_ec2_client().describe_regions(MaxResults=1)
            logger.info("AWS credentials validated successfully")
        except Exception as e:
            raise ValueError(f"AWS credentials validation failed: {str(e)}")
            
    except Exception as e:
        logger.error(f"Terraform credentials validation failed: {str(e)}")
        raise


def validate_s3_access(bucket: str, key: str):
    """
    Validate S3 access for Terraform configuration or state.
    """
    try:
        s3_client = boto3.client('s3')
        
        # Check if bucket exists and is accessible
        s3_client.head_bucket(Bucket=bucket)
        
        # Check if the specific object exists (for config) or if we can write to the location (for state)
        try:
            s3_client.head_object(Bucket=bucket, Key=key)
            logger.info(f"S3 object s3://{bucket}/{key} exists and is accessible")
        except ClientError as e:
            if e.response['Error']['Code'] == '404':
                # Object doesn't exist, check if we can write to the bucket
                logger.info(f"S3 object s3://{bucket}/{key} does not exist, validating write access")
                # We'll assume write access is available if bucket access works
            else:
                raise
                
    except Exception as e:
        raise ValueError(f"S3 access validation failed for s3://{bucket}/{key}: {str(e)}")


def trigger_terraform_cloud(current_ips: Set[str], existing_ips: Set[str]) -> bool:
    """
    Trigger Terraform Cloud workspace run to apply changes.
    """
    try:
        logger.info("=== TERRAFORM CLOUD AUTOMATION START ===")
        logger.info(f"Organization: {TERRAFORM_ORGANIZATION}")
        logger.info(f"Workspace: {TERRAFORM_WORKSPACE}")
        logger.info(f"IP changes: {len(current_ips - existing_ips)} to add, {len(existing_ips - current_ips)} to remove")
        
        # Validate required configuration
        if not all([TERRAFORM_CLOUD_TOKEN, TERRAFORM_WORKSPACE, TERRAFORM_ORGANIZATION]):
            raise ValueError("Terraform Cloud configuration incomplete. Required: TERRAFORM_CLOUD_TOKEN, TERRAFORM_WORKSPACE, TERRAFORM_ORGANIZATION")
        
        # Prepare API headers
        headers = {
            'Authorization': f'Bearer {TERRAFORM_CLOUD_TOKEN}',
            'Content-Type': 'application/vnd.api+json'
        }
        
        # Log the automation trigger details
        automation_message = f'Automated Cloudflare IP update - {len(current_ips)} IP ranges'
        logger.info(f"Automation message: {automation_message}")
        
        # Create workspace run
        run_data = {
            'data': {
                'type': 'runs',
                'attributes': {
                    'message': automation_message,
                    'auto-apply': True
                },
                'relationships': {
                    'workspace': {
                        'data': {
                            'type': 'workspaces',
                            'id': TERRAFORM_WORKSPACE
                        }
                    }
                }
            }
        }
        
        # Trigger the run
        api_url = f'https://app.terraform.io/api/v2/runs'
        logger.info(f"Sending Terraform Cloud API request to: {api_url}")
        
        response = requests.post(api_url, headers=headers, json=run_data, timeout=30)
        response.raise_for_status()
        
        run_info = response.json()
        run_id = run_info['data']['id']
        run_url = f"https://app.terraform.io/app/{TERRAFORM_ORGANIZATION}/workspaces/{TERRAFORM_WORKSPACE}/runs/{run_id}"
        
        logger.info(f"Terraform Cloud run triggered successfully")
        logger.info(f"Run ID: {run_id}")
        logger.info(f"Run URL: {run_url}")
        
        # Monitor run status
        success = monitor_terraform_cloud_run(run_id, headers)
        
        logger.info(f"=== TERRAFORM CLOUD AUTOMATION END - {'SUCCESS' if success else 'FAILED'} ===")
        return success
        
    except Exception as e:
        logger.error(f"Error triggering Terraform Cloud: {str(e)}")
        logger.error("=== TERRAFORM CLOUD AUTOMATION END - ERROR ===")
        raise


def monitor_terraform_cloud_run(run_id: str, headers: Dict[str, str]) -> bool:
    """
    Monitor Terraform Cloud run status until completion.
    """
    try:
        logger.info(f"Monitoring Terraform Cloud run: {run_id}")
        
        max_wait_time = 600  # 10 minutes
        check_interval = 30  # 30 seconds
        elapsed_time = 0
        
        while elapsed_time < max_wait_time:
            # Check run status
            api_url = f'https://app.terraform.io/api/v2/runs/{run_id}'
            response = requests.get(api_url, headers=headers, timeout=30)
            response.raise_for_status()
            
            run_data = response.json()
            status = run_data['data']['attributes']['status']
            
            logger.info(f"Terraform Cloud run status: {status}")
            
            if status in ['applied', 'planned_and_finished']:
                logger.info("Terraform Cloud run completed successfully")
                return True
            elif status in ['errored', 'canceled', 'force_canceled']:
                logger.error(f"Terraform Cloud run failed with status: {status}")
                return False
            elif status in ['planning', 'applying', 'pending', 'queued']:
                # Still running, wait and check again
                time.sleep(check_interval)
                elapsed_time += check_interval
            else:
                logger.warning(f"Unknown Terraform Cloud run status: {status}")
                time.sleep(check_interval)
                elapsed_time += check_interval
        
        logger.error(f"Terraform Cloud run timed out after {max_wait_time} seconds")
        return False
        
    except Exception as e:
        logger.error(f"Error monitoring Terraform Cloud run: {str(e)}")
        raise


def trigger_terraform_local(current_ips: Set[str], existing_ips: Set[str]) -> bool:
    """
    Execute Terraform locally using downloaded configuration from S3.
    """
    try:
        logger.info("=== LOCAL TERRAFORM AUTOMATION START ===")
        logger.info(f"Config S3 Bucket: {TERRAFORM_CONFIG_S3_BUCKET}")
        logger.info(f"Config S3 Key: {TERRAFORM_CONFIG_S3_KEY}")
        logger.info(f"State S3 Bucket: {TERRAFORM_STATE_S3_BUCKET}")
        logger.info(f"State S3 Key: {TERRAFORM_STATE_S3_KEY}")
        logger.info(f"IP changes: {len(current_ips - existing_ips)} to add, {len(existing_ips - current_ips)} to remove")
        
        # Check if Terraform binary is available
        terraform_path = shutil.which('terraform')
        if not terraform_path:
            logger.warning("Terraform binary not found in Lambda environment. Falling back to direct security group updates.")
            logger.info("=== LOCAL TERRAFORM AUTOMATION END - FALLBACK TO DIRECT UPDATES ===")
            return update_security_group_if_needed(current_ips, existing_ips)
        
        logger.info(f"Terraform binary found at: {terraform_path}")
        
        # Validate required configuration
        if not all([TERRAFORM_CONFIG_S3_BUCKET, TERRAFORM_CONFIG_S3_KEY]):
            logger.warning("Local Terraform configuration incomplete. Required: TERRAFORM_CONFIG_S3_BUCKET, TERRAFORM_CONFIG_S3_KEY. Falling back to direct updates.")
            logger.info("=== LOCAL TERRAFORM AUTOMATION END - FALLBACK TO DIRECT UPDATES ===")
            return update_security_group_if_needed(current_ips, existing_ips)
        
        # Create temporary directory for Terraform execution
        with tempfile.TemporaryDirectory() as temp_dir:
            logger.info(f"Created temporary directory: {temp_dir}")
            
            try:
                # Download Terraform configuration from S3
                logger.info("Step 1: Downloading Terraform configuration")
                download_terraform_config(temp_dir)
                
                # Set up Terraform backend configuration if specified
                if TERRAFORM_STATE_S3_BUCKET and TERRAFORM_STATE_S3_KEY:
                    logger.info("Step 2: Setting up Terraform backend configuration")
                    setup_terraform_backend(temp_dir)
                else:
                    logger.info("Step 2: Skipping backend configuration (not specified)")
                
                # Initialize Terraform
                logger.info("Step 3: Initializing Terraform")
                if not run_terraform_command(['terraform', 'init'], temp_dir):
                    logger.error("Terraform init failed, falling back to direct security group updates")
                    logger.info("=== LOCAL TERRAFORM AUTOMATION END - FALLBACK TO DIRECT UPDATES ===")
                    return update_security_group_if_needed(current_ips, existing_ips)
                
                # Plan Terraform changes
                logger.info("Step 4: Planning Terraform changes")
                if not run_terraform_command(['terraform', 'plan', '-out=tfplan'], temp_dir):
                    logger.error("Terraform plan failed, falling back to direct security group updates")
                    logger.info("=== LOCAL TERRAFORM AUTOMATION END - FALLBACK TO DIRECT UPDATES ===")
                    return update_security_group_if_needed(current_ips, existing_ips)
                
                # Apply Terraform changes
                logger.info("Step 5: Applying Terraform changes")
                if not run_terraform_command(['terraform', 'apply', '-auto-approve', 'tfplan'], temp_dir):
                    logger.error("Terraform apply failed, falling back to direct security group updates")
                    logger.info("=== LOCAL TERRAFORM AUTOMATION END - FALLBACK TO DIRECT UPDATES ===")
                    return update_security_group_if_needed(current_ips, existing_ips)
                
                logger.info("Local Terraform execution completed successfully")
                logger.info("=== LOCAL TERRAFORM AUTOMATION END - SUCCESS ===")
                return True
                
            except Exception as e:
                logger.error(f"Error during Terraform execution steps: {str(e)}")
                logger.info("=== LOCAL TERRAFORM AUTOMATION END - FALLBACK TO DIRECT UPDATES ===")
                return update_security_group_if_needed(current_ips, existing_ips)
            
    except Exception as e:
        logger.error(f"Error in local Terraform execution: {str(e)}. Falling back to direct security group updates.")
        logger.error("=== LOCAL TERRAFORM AUTOMATION END - ERROR ===")
        return update_security_group_if_needed(current_ips, existing_ips)


def download_terraform_config(temp_dir: str):
    """
    Download Terraform configuration files from S3.
    """
    try:
        bucket = os.environ.get('TERRAFORM_CONFIG_S3_BUCKET', TERRAFORM_CONFIG_S3_BUCKET)
        key = os.environ.get('TERRAFORM_CONFIG_S3_KEY', TERRAFORM_CONFIG_S3_KEY)
        
        logger.info(f"Downloading Terraform config from s3://{bucket}/{key}")
        
        s3_client = boto3.client('s3')
        
        # Download and extract configuration
        config_path = os.path.join(temp_dir, 'terraform-config.zip')
        s3_client.download_file(bucket, key, config_path)
        
        # Extract if it's a zip file
        if key.endswith('.zip'):
            import zipfile
            with zipfile.ZipFile(config_path, 'r') as zip_ref:
                zip_ref.extractall(temp_dir)
            os.remove(config_path)
        
        logger.info("Terraform configuration downloaded successfully")
        
    except Exception as e:
        logger.error(f"Error downloading Terraform config: {str(e)}")
        raise


def setup_terraform_backend(temp_dir: str):
    """
    Set up Terraform backend configuration for S3 state storage.
    """
    try:
        logger.info("Setting up Terraform S3 backend configuration")
        
        bucket = os.environ.get('TERRAFORM_STATE_S3_BUCKET', TERRAFORM_STATE_S3_BUCKET)
        key = os.environ.get('TERRAFORM_STATE_S3_KEY', TERRAFORM_STATE_S3_KEY)
        region = os.environ.get('AWS_REGION', 'us-east-1')
        
        backend_config = f"""
terraform {{
  backend "s3" {{
    bucket = "{bucket}"
    key    = "{key}"
    region = "{region}"
  }}
}}
"""
        
        backend_file = os.path.join(temp_dir, 'backend.tf')
        with open(backend_file, 'w') as f:
            f.write(backend_config)
        
        logger.info(f"Terraform backend configuration created for s3://{bucket}/{key}")
        
    except Exception as e:
        logger.error(f"Error setting up Terraform backend: {str(e)}")
        raise


def run_terraform_command(command: List[str], working_dir: str) -> bool:
    """
    Execute a Terraform command with proper logging and error handling.
    """
    try:
        logger.info(f"Executing command: {' '.join(command)}")
        
        # Set environment variables for Terraform
        env = os.environ.copy()
        env['TF_IN_AUTOMATION'] = 'true'
        env['TF_INPUT'] = 'false'
        
        # Execute command
        result = subprocess.run(
            command,
            cwd=working_dir,
            capture_output=True,
            text=True,
            env=env,
            timeout=300  # 5 minute timeout
        )
        
        # Log output
        if result.stdout:
            logger.info(f"Terraform stdout: {result.stdout}")
        if result.stderr:
            logger.warning(f"Terraform stderr: {result.stderr}")
        
        if result.returncode == 0:
            logger.info(f"Command completed successfully: {' '.join(command)}")
            return True
        else:
            logger.error(f"Command failed with return code {result.returncode}: {' '.join(command)}")
            return False
            
    except subprocess.TimeoutExpired:
        logger.error(f"Command timed out: {' '.join(command)}")
        return False
    except Exception as e:
        logger.error(f"Error executing command {' '.join(command)}: {str(e)}")
        return False


def create_detailed_notification(current_ips: Set[str], existing_ips: Set[str], changes_made: bool) -> str:
    """
    Create a detailed notification message with comprehensive logging information.
    """
    try:
        ips_to_add = current_ips - existing_ips
        ips_to_remove = existing_ips - current_ips
        
        # Create detailed notification message
        notification_lines = [
            "=== CLOUDFLARE IP UPDATE AUTOMATION REPORT ===",
            f"Timestamp: {time.strftime('%Y-%m-%d %H:%M:%S UTC', time.gmtime())}",
            f"Security Group ID: {SECURITY_GROUP_ID}",
            f"Terraform Mode: {TERRAFORM_MODE}",
            "",
            "SUMMARY:",
            f"  - Total Cloudflare IP ranges: {len(current_ips)}",
            f"  - Previous IP ranges: {len(existing_ips)}",
            f"  - Changes made: {'Yes' if changes_made else 'No'}",
            f"  - IP ranges added: {len(ips_to_add)}",
            f"  - IP ranges removed: {len(ips_to_remove)}",
            ""
        ]
        
        if ips_to_add:
            notification_lines.extend([
                "NEW IP RANGES ADDED:",
                *[f"  + {ip}" for ip in sorted(list(ips_to_add))],
                ""
            ])
        
        if ips_to_remove:
            notification_lines.extend([
                "OUTDATED IP RANGES REMOVED:",
                *[f"  - {ip}" for ip in sorted(list(ips_to_remove))],
                ""
            ])
        
        if TERRAFORM_MODE == 'cloud' and TERRAFORM_ORGANIZATION and TERRAFORM_WORKSPACE:
            notification_lines.extend([
                "TERRAFORM CLOUD DETAILS:",
                f"  - Organization: {TERRAFORM_ORGANIZATION}",
                f"  - Workspace: {TERRAFORM_WORKSPACE}",
                f"  - Run URL: https://app.terraform.io/app/{TERRAFORM_ORGANIZATION}/workspaces/{TERRAFORM_WORKSPACE}",
                ""
            ])
        elif TERRAFORM_MODE == 'direct':
            notification_lines.extend([
                "TERRAFORM LOCAL EXECUTION:",
                f"  - Config S3 Bucket: {TERRAFORM_CONFIG_S3_BUCKET or 'Not configured'}",
                f"  - State S3 Bucket: {TERRAFORM_STATE_S3_BUCKET or 'Not configured'}",
                ""
            ])
        
        notification_lines.extend([
            "AUTOMATION STATUS: SUCCESS" if changes_made else "AUTOMATION STATUS: NO CHANGES NEEDED",
            "=== END REPORT ==="
        ])
        
        return "\n".join(notification_lines)
        
    except Exception as e:
        logger.error(f"Error creating detailed notification: {str(e)}")
        # Return a basic notification if detailed creation fails
        return f"Cloudflare IP ranges updated via Terraform automation. {len(current_ips)} IP ranges now configured."


def send_notification(message: str, notification_type: str = "INFO"):
    """
    Send SNS notification about the update with appropriate subject and formatting.
    
    Args:
        message: The notification message content
        notification_type: Type of notification (SUCCESS, ERROR, INFO)
    """
    try:
        # Determine subject based on notification type
        subject_map = {
            "SUCCESS": "✅ Cloudflare IP Update - Success",
            "ERROR": "❌ Cloudflare IP Update - Error",
            "INFO": "ℹ️ Cloudflare IP Update - Information"
        }
        
        subject = subject_map.get(notification_type, "Cloudflare IP Update Notification")
        
        # Add timestamp and environment info to message
        timestamp = time.strftime('%Y-%m-%d %H:%M:%S UTC', time.gmtime())
        environment = os.environ.get('AWS_LAMBDA_FUNCTION_NAME', 'unknown').split('-')[-1] if 'AWS_LAMBDA_FUNCTION_NAME' in os.environ else 'unknown'
        
        formatted_message = f"""
Environment: {environment}
Timestamp: {timestamp}
Security Group: {SECURITY_GROUP_ID}

{message}

---
This is an automated notification from the Cloudflare IP updater Lambda function.
"""
        
        # Publish to SNS
        response = get_sns_client().publish(
            TopicArn=SNS_TOPIC_ARN,
            Message=formatted_message.strip(),
            Subject=subject
        )
        
        logger.info(f"Notification sent successfully - Type: {notification_type}")
        logger.info(f"SNS Message ID: {response.get('MessageId', 'unknown')}")
        logger.info(f"Notification content preview: {message[:200]}...")
        
        # Log CloudWatch custom metric for monitoring
        try:
            cloudwatch = boto3.client('cloudwatch')
            cloudwatch.put_metric_data(
                Namespace='CloudflareIPUpdater',
                MetricData=[
                    {
                        'MetricName': 'NotificationsSent',
                        'Value': 1,
                        'Unit': 'Count',
                        'Dimensions': [
                            {
                                'Name': 'NotificationType',
                                'Value': notification_type
                            },
                            {
                                'Name': 'Environment',
                                'Value': environment
                            }
                        ]
                    }
                ]
            )
            logger.info(f"CloudWatch metric logged for notification type: {notification_type}")
        except Exception as metric_error:
            logger.warning(f"Failed to log CloudWatch metric: {str(metric_error)}")
        
    except Exception as e:
        logger.error(f"Error sending notification: {str(e)}")
        # Try to send a basic error notification if the main one fails
        try:
            get_sns_client().publish(
                TopicArn=SNS_TOPIC_ARN,
                Message=f"Failed to send detailed notification. Error: {str(e)}\nOriginal message type: {notification_type}",
                Subject="❌ Cloudflare IP Update - Notification Error"
            )
        except Exception as fallback_error:
            logger.error(f"Failed to send fallback notification: {str(fallback_error)}")


def log_cloudwatch_metrics(current_ips: Set[str], existing_ips: Set[str], changes_made: bool):
    """
    Log custom CloudWatch metrics for monitoring and dashboard display.
    """
    try:
        cloudwatch = boto3.client('cloudwatch')
        environment = os.environ.get('AWS_LAMBDA_FUNCTION_NAME', 'unknown').split('-')[-1] if 'AWS_LAMBDA_FUNCTION_NAME' in os.environ else 'unknown'
        
        # Calculate metrics
        ips_to_add = current_ips - existing_ips
        ips_to_remove = existing_ips - current_ips
        total_rule_count = len(current_ips)
        
        # Prepare metric data
        metric_data = [
            {
                'MetricName': 'IPRangesUpdated',
                'Value': 1 if changes_made else 0,
                'Unit': 'Count',
                'Dimensions': [
                    {
                        'Name': 'Environment',
                        'Value': environment
                    }
                ]
            },
            {
                'MetricName': 'SecurityGroupRulesCount',
                'Value': total_rule_count,
                'Unit': 'Count',
                'Dimensions': [
                    {
                        'Name': 'Environment',
                        'Value': environment
                    }
                ]
            },
            {
                'MetricName': 'IPRangesAdded',
                'Value': len(ips_to_add),
                'Unit': 'Count',
                'Dimensions': [
                    {
                        'Name': 'Environment',
                        'Value': environment
                    }
                ]
            },
            {
                'MetricName': 'IPRangesRemoved',
                'Value': len(ips_to_remove),
                'Unit': 'Count',
                'Dimensions': [
                    {
                        'Name': 'Environment',
                        'Value': environment
                    }
                ]
            },
            {
                'MetricName': 'AutomationExecutions',
                'Value': 1,
                'Unit': 'Count',
                'Dimensions': [
                    {
                        'Name': 'Environment',
                        'Value': environment
                    },
                    {
                        'Name': 'ChangesDetected',
                        'Value': 'Yes' if changes_made else 'No'
                    }
                ]
            }
        ]
        
        # Send metrics to CloudWatch
        cloudwatch.put_metric_data(
            Namespace='CloudflareIPUpdater',
            MetricData=metric_data
        )
        
        logger.info(f"CloudWatch metrics logged successfully:")
        logger.info(f"  - IP ranges updated: {1 if changes_made else 0}")
        logger.info(f"  - Total security group rules: {total_rule_count}")
        logger.info(f"  - IP ranges added: {len(ips_to_add)}")
        logger.info(f"  - IP ranges removed: {len(ips_to_remove)}")
        
    except Exception as e:
        logger.warning(f"Failed to log CloudWatch metrics: {str(e)}")
        # Don't raise exception as this is not critical to the main functionality
d
ef validate_aws_service_quotas():
    """
    Validate AWS service quotas to ensure we don't exceed limits.
    """
    try:
        logger.info("Validating AWS service quotas")
        
        # Check security group count in VPC
        if CURRENT_SECURITY_GROUPS_COUNT > (MAX_SECURITY_GROUPS_PER_VPC * 0.9):
            warning_msg = f"Security groups approaching limit: {CURRENT_SECURITY_GROUPS_COUNT}/{MAX_SECURITY_GROUPS_PER_VPC} (90% threshold)"
            logger.warning(warning_msg)
            log_quota_warning(warning_msg)
        
        # Check if rules will exceed limits
        if RULES_APPROACHING_LIMIT:
            warning_msg = f"Security group rules approaching limit for current configuration"
            logger.warning(warning_msg)
            log_quota_warning(warning_msg)
        
        # Check if multiple security groups are needed
        if REQUIRES_MULTIPLE_GROUPS:
            info_msg = f"Multiple security groups required: {SECURITY_GROUPS_NEEDED} groups needed"
            logger.info(info_msg)
        
        logger.info("AWS service quota validation completed")
        
    except Exception as e:
        logger.error(f"Error validating AWS service quotas: {str(e)}")
        raise


def perform_state_validation(current_ips: Set[str], existing_ips: Set[str]):
    """
    Perform state validation and drift detection.
    """
    try:
        logger.info("Performing state validation and drift detection")
        
        if ENABLE_DRIFT_DETECTION:
            # Check for drift between expected and actual state
            if current_ips != existing_ips:
                drift_msg = f"State drift detected: Expected {len(current_ips)} IPs, found {len(existing_ips)} IPs"
                logger.error(drift_msg)
                
                # Log detailed drift information
                ips_missing = current_ips - existing_ips
                ips_extra = existing_ips - current_ips
                
                if ips_missing:
                    logger.error(f"Missing IP ranges: {sorted(list(ips_missing))}")
                if ips_extra:
                    logger.error(f"Extra IP ranges: {sorted(list(ips_extra))}")
            else:
                logger.info("No state drift detected - security group matches expected state")
        
        if ENABLE_STATE_VALIDATION:
            # Validate IP count is within expected range
            if len(current_ips) > MAX_EXPECTED_CLOUDFLARE_IPS:
                validation_msg = f"IP count validation failed: {len(current_ips)} > {MAX_EXPECTED_CLOUDFLARE_IPS}"
                logger.warning(validation_msg)
                log_quota_warning(validation_msg)
            
            # Validate CIDR format for all IPs
            invalid_cidrs = []
            for ip in current_ips:
                if not validate_cidr(ip):
                    invalid_cidrs.append(ip)
            
            if invalid_cidrs:
                validation_msg = f"Invalid CIDR formats detected: {invalid_cidrs}"
                logger.error(validation_msg)
                raise ValueError(validation_msg)
        
        logger.info("State validation completed successfully")
        
    except Exception as e:
        logger.error(f"Error during state validation: {str(e)}")
        raise


def should_use_replacement_strategy(ips_to_add: Set[str], ips_to_remove: Set[str], existing_ips: Set[str]) -> bool:
    """
    Determine if changes require replacement strategy based on thresholds.
    """
    try:
        total_changes = len(ips_to_add) + len(ips_to_remove)
        
        # Check absolute change threshold
        if total_changes > MAX_IP_CHANGES_PER_UPDATE:
            logger.info(f"Replacement strategy triggered: {total_changes} changes exceed maximum {MAX_IP_CHANGES_PER_UPDATE}")
            return True
        
        # Check percentage change threshold
        if len(existing_ips) > 0:
            change_percentage = (total_changes * 100) / len(existing_ips)
            if change_percentage > IP_CHANGE_THRESHOLD_PERCENT:
                logger.info(f"Replacement strategy triggered: {change_percentage:.1f}% change exceeds threshold {IP_CHANGE_THRESHOLD_PERCENT}%")
                return True
        
        return False
        
    except Exception as e:
        logger.error(f"Error determining replacement strategy: {str(e)}")
        return False


def log_quota_warning(message: str):
    """
    Log quota warning for CloudWatch metric filtering.
    """
    logger.warning(f"QUOTA WARNING: {message}")


def log_replacement_strategy_trigger(ips_to_add: int, ips_to_remove: int, existing_count: int):
    """
    Log replacement strategy trigger for CloudWatch metric filtering.
    """
    logger.info(f"Replacement strategy triggered: adding {ips_to_add}, removing {ips_to_remove}, existing {existing_count}")


def create_detailed_notification(current_ips: Set[str], existing_ips: Set[str], changes_made: bool) -> str:
    """
    Create detailed notification message with state and quota information.
    """
    try:
        ips_to_add = current_ips - existing_ips
        ips_to_remove = existing_ips - current_ips
        
        notification = f"""
Cloudflare IP Update Report
==========================

Status: {'SUCCESS - Changes Applied' if changes_made else 'SUCCESS - No Changes Needed'}
Timestamp: {time.strftime('%Y-%m-%d %H:%M:%S UTC', time.gmtime())}

IP Range Summary:
- Current Cloudflare IPs: {len(current_ips)}
- Previous Security Group IPs: {len(existing_ips)}
- IPs Added: {len(ips_to_add)}
- IPs Removed: {len(ips_to_remove)}

Configuration:
- State Validation: {'Enabled' if ENABLE_STATE_VALIDATION else 'Disabled'}
- Drift Detection: {'Enabled' if ENABLE_DRIFT_DETECTION else 'Disabled'}
- Quota Checking: {'Enabled' if ENABLE_QUOTA_CHECKING else 'Disabled'}
- Enhanced Lifecycle: {'Enabled' if ENABLE_ENHANCED_LIFECYCLE else 'Disabled'}
"""

        if ENABLE_QUOTA_CHECKING:
            notification += f"""
Quota Information:
- Security Groups in VPC: {CURRENT_SECURITY_GROUPS_COUNT}/{MAX_SECURITY_GROUPS_PER_VPC}
- Rules per Security Group Limit: {MAX_RULES_PER_SECURITY_GROUP}
- Multiple Groups Required: {'Yes' if REQUIRES_MULTIPLE_GROUPS else 'No'}
- Groups Needed: {SECURITY_GROUPS_NEEDED}
"""

        if changes_made and (ips_to_add or ips_to_remove):
            if should_use_replacement_strategy(ips_to_add, ips_to_remove, existing_ips):
                notification += "\nReplacement Strategy: TRIGGERED (significant changes detected)"
            else:
                notification += "\nReplacement Strategy: Not required"

        if ips_to_add and len(ips_to_add) <= 10:
            notification += f"\nNew IP Ranges Added:\n" + "\n".join(f"  - {ip}" for ip in sorted(ips_to_add))
        elif ips_to_add:
            notification += f"\nNew IP Ranges Added: {len(ips_to_add)} ranges (too many to list)"

        if ips_to_remove and len(ips_to_remove) <= 10:
            notification += f"\nIP Ranges Removed:\n" + "\n".join(f"  - {ip}" for ip in sorted(ips_to_remove))
        elif ips_to_remove:
            notification += f"\nIP Ranges Removed: {len(ips_to_remove)} ranges (too many to list)"

        return notification.strip()
        
    except Exception as e:
        logger.error(f"Error creating detailed notification: {str(e)}")
        return f"Cloudflare IP update completed. Status: {'Changes Applied' if changes_made else 'No Changes Needed'}"


def log_cloudwatch_metrics(current_ips: Set[str], existing_ips: Set[str], changes_made: bool):
    """
    Log custom CloudWatch metrics for monitoring with enhanced state information.
    """
    try:
        cloudwatch = boto3.client('cloudwatch')
        
        # Basic metrics
        metrics = [
            {
                'MetricName': 'IPRangesUpdated',
                'Value': 1 if changes_made else 0,
                'Unit': 'Count',
                'Dimensions': [
                    {'Name': 'Environment', 'Value': os.environ.get('AWS_LAMBDA_FUNCTION_NAME', 'unknown')},
                    {'Name': 'UpdateType', 'Value': 'Automated'}
                ]
            },
            {
                'MetricName': 'SecurityGroupRulesCount',
                'Value': len(current_ips),
                'Unit': 'Count',
                'Dimensions': [
                    {'Name': 'Environment', 'Value': os.environ.get('AWS_LAMBDA_FUNCTION_NAME', 'unknown')},
                    {'Name': 'SecurityGroupId', 'Value': SECURITY_GROUP_ID}
                ]
            }
        ]
        
        # State management metrics
        if ENABLE_STATE_VALIDATION or ENABLE_DRIFT_DETECTION:
            ips_to_add = current_ips - existing_ips
            ips_to_remove = existing_ips - current_ips
            
            metrics.extend([
                {
                    'MetricName': 'IPsAdded',
                    'Value': len(ips_to_add),
                    'Unit': 'Count',
                    'Dimensions': [{'Name': 'Environment', 'Value': os.environ.get('AWS_LAMBDA_FUNCTION_NAME', 'unknown')}]
                },
                {
                    'MetricName': 'IPsRemoved',
                    'Value': len(ips_to_remove),
                    'Unit': 'Count',
                    'Dimensions': [{'Name': 'Environment', 'Value': os.environ.get('AWS_LAMBDA_FUNCTION_NAME', 'unknown')}]
                },
                {
                    'MetricName': 'StateDriftDetected',
                    'Value': 1 if (ips_to_add or ips_to_remove) else 0,
                    'Unit': 'Count',
                    'Dimensions': [{'Name': 'Environment', 'Value': os.environ.get('AWS_LAMBDA_FUNCTION_NAME', 'unknown')}]
                }
            ])
        
        # Quota management metrics
        if ENABLE_QUOTA_CHECKING:
            metrics.extend([
                {
                    'MetricName': 'SecurityGroupsInVPC',
                    'Value': CURRENT_SECURITY_GROUPS_COUNT,
                    'Unit': 'Count',
                    'Dimensions': [{'Name': 'VPC', 'Value': 'current'}]
                },
                {
                    'MetricName': 'MultipleGroupsRequired',
                    'Value': 1 if REQUIRES_MULTIPLE_GROUPS else 0,
                    'Unit': 'Count',
                    'Dimensions': [{'Name': 'Environment', 'Value': os.environ.get('AWS_LAMBDA_FUNCTION_NAME', 'unknown')}]
                }
            ])
        
        # Send metrics to CloudWatch
        for i in range(0, len(metrics), 20):  # CloudWatch allows max 20 metrics per call
            batch = metrics[i:i+20]
            cloudwatch.put_metric_data(
                Namespace='CloudflareIPUpdater',
                MetricData=batch
            )
        
        logger.info(f"Logged {len(metrics)} CloudWatch metrics")
        
    except Exception as e:
        logger.error(f"Error logging CloudWatch metrics: {str(e)}")
        # Don't raise exception as this is not critical for the main functionality


def send_notification(message: str, notification_type: str):
    """
    Send SNS notification with enhanced formatting.
    """
    try:
        if not SNS_TOPIC_ARN:
            logger.info("SNS topic not configured, skipping notification")
            return
        
        subject = f"Cloudflare IP Update - {notification_type}"
        
        # Add environment context to subject if available
        env_name = os.environ.get('AWS_LAMBDA_FUNCTION_NAME', '').split('-')[-1] if os.environ.get('AWS_LAMBDA_FUNCTION_NAME') else 'unknown'
        if env_name and env_name != 'unknown':
            subject += f" ({env_name})"
        
        get_sns_client().publish(
            TopicArn=SNS_TOPIC_ARN,
            Subject=subject,
            Message=message
        )
        
        logger.info(f"Notification sent: {notification_type}")
        
        # Log custom metric for notification
        try:
            cloudwatch = boto3.client('cloudwatch')
            cloudwatch.put_metric_data(
                Namespace='CloudflareIPUpdater',
                MetricData=[
                    {
                        'MetricName': 'NotificationsSent',
                        'Value': 1,
                        'Unit': 'Count',
                        'Dimensions': [
                            {'Name': 'NotificationType', 'Value': notification_type},
                            {'Name': 'Environment', 'Value': env_name}
                        ]
                    }
                ]
            )
        except Exception as metric_error:
            logger.warning(f"Failed to log notification metric: {str(metric_error)}")
        
    except Exception as e:
        logger.error(f"Error sending notification: {str(e)}")
        # Don't raise exception as notification failure shouldn't stop the main process
d
ef validate_aws_service_quotas():
    """
    Validate AWS service quotas to ensure we don't exceed limits.
    """
    try:
        logger.info("Validating AWS service quotas")
        
        if ENABLE_QUOTA_CHECKING:
            # Check security group rules quota
            if RULES_APPROACHING_LIMIT:
                logger.warning(f"Security group rules approaching limit. Current usage is high.")
                log_quota_warning("Security group rules approaching AWS service limit")
            
            # Check if multiple security groups are needed
            if REQUIRES_MULTIPLE_GROUPS:
                logger.info(f"Multiple security groups required: {SECURITY_GROUPS_NEEDED} groups needed")
                log_quota_warning(f"Multiple security groups required due to rule limits: {SECURITY_GROUPS_NEEDED} groups")
            
            # Validate current security group count
            if CURRENT_SECURITY_GROUPS_COUNT > (MAX_SECURITY_GROUPS_PER_VPC * 0.8):
                logger.warning(f"Security groups per VPC approaching limit: {CURRENT_SECURITY_GROUPS_COUNT}/{MAX_SECURITY_GROUPS_PER_VPC}")
                log_quota_warning(f"Security groups per VPC approaching limit: {CURRENT_SECURITY_GROUPS_COUNT}/{MAX_SECURITY_GROUPS_PER_VPC}")
        
        logger.info("AWS service quota validation completed")
        
    except Exception as e:
        logger.error(f"Error validating AWS service quotas: {str(e)}")
        raise


def perform_state_validation(current_ips: Set[str], existing_ips: Set[str]):
    """
    Perform state validation and drift detection.
    """
    try:
        logger.info("Performing state validation and drift detection")
        
        if ENABLE_STATE_VALIDATION:
            logger.info("State validation enabled - checking for consistency")
            
            # Validate IP count is reasonable
            if len(current_ips) == 0:
                logger.error("No Cloudflare IPs retrieved - this indicates a problem")
                raise ValueError("No Cloudflare IPs retrieved from API")
            
            if len(current_ips) > MAX_EXPECTED_CLOUDFLARE_IPS * 2:
                logger.error(f"Cloudflare IP count ({len(current_ips)}) is unexpectedly high")
                raise ValueError(f"Cloudflare IP count exceeds reasonable maximum: {len(current_ips)}")
        
        if ENABLE_DRIFT_DETECTION:
            logger.info("Drift detection enabled - analyzing state differences")
            
            ips_to_add = current_ips - existing_ips
            ips_to_remove = existing_ips - current_ips
            
            if ips_to_add or ips_to_remove:
                logger.info(f"State drift detected: {len(ips_to_add)} IPs to add, {len(ips_to_remove)} IPs to remove")
                
                # Log detailed drift information
                if ips_to_add:
                    logger.info(f"New Cloudflare IPs detected: {sorted(list(ips_to_add))}")
                if ips_to_remove:
                    logger.info(f"Outdated IPs to remove: {sorted(list(ips_to_remove))}")
                
                # Log drift detection metric
                log_state_drift_detected(len(ips_to_add), len(ips_to_remove))
            else:
                logger.info("No state drift detected - security group is up to date")
        
        logger.info("State validation and drift detection completed")
        
    except Exception as e:
        logger.error(f"Error in state validation: {str(e)}")
        raise


def should_use_replacement_strategy(ips_to_add: Set[str], ips_to_remove: Set[str], existing_ips: Set[str]) -> bool:
    """
    Determine if changes require replacement strategy due to significant changes.
    """
    try:
        total_changes = len(ips_to_add) + len(ips_to_remove)
        
        # Check absolute change threshold
        if total_changes > MAX_IP_CHANGES_PER_UPDATE:
            logger.info(f"Replacement strategy triggered: {total_changes} changes exceed maximum of {MAX_IP_CHANGES_PER_UPDATE}")
            return True
        
        # Check percentage change threshold
        if len(existing_ips) > 0:
            change_percentage = (total_changes * 100) / len(existing_ips)
            if change_percentage > IP_CHANGE_THRESHOLD_PERCENT:
                logger.info(f"Replacement strategy triggered: {change_percentage:.1f}% change exceeds threshold of {IP_CHANGE_THRESHOLD_PERCENT}%")
                return True
        
        return False
        
    except Exception as e:
        logger.error(f"Error determining replacement strategy: {str(e)}")
        return False


def log_quota_warning(message: str):
    """
    Log quota warning for CloudWatch metric filtering.
    """
    logger.warning(f"QUOTA WARNING: {message}")


def log_state_drift_detected(ips_to_add_count: int, ips_to_remove_count: int):
    """
    Log state drift detection for CloudWatch metric filtering.
    """
    logger.error(f"State drift detected: {ips_to_add_count} IPs to add, {ips_to_remove_count} IPs to remove")


def log_replacement_strategy_trigger(ips_to_add_count: int, ips_to_remove_count: int, existing_count: int):
    """
    Log replacement strategy trigger for CloudWatch metric filtering.
    """
    total_changes = ips_to_add_count + ips_to_remove_count
    change_percentage = (total_changes * 100) / existing_count if existing_count > 0 else 0
    
    logger.info(f"Replacement strategy triggered: {total_changes} total changes ({change_percentage:.1f}% of existing {existing_count} IPs)")


def log_cloudwatch_metrics(current_ips: Set[str], existing_ips: Set[str], changes_made: bool):
    """
    Log custom CloudWatch metrics for monitoring.
    """
    try:
        cloudwatch = boto3.client('cloudwatch')
        
        # Log IP count metrics
        cloudwatch.put_metric_data(
            Namespace='CloudflareIPUpdater',
            MetricData=[
                {
                    'MetricName': 'CloudflareIPCount',
                    'Value': len(current_ips),
                    'Unit': 'Count',
                    'Dimensions': [
                        {
                            'Name': 'SecurityGroupId',
                            'Value': SECURITY_GROUP_ID
                        }
                    ]
                },
                {
                    'MetricName': 'SecurityGroupRulesCount',
                    'Value': len(existing_ips),
                    'Unit': 'Count',
                    'Dimensions': [
                        {
                            'Name': 'SecurityGroupId',
                            'Value': SECURITY_GROUP_ID
                        }
                    ]
                },
                {
                    'MetricName': 'IPRangesUpdated',
                    'Value': 1 if changes_made else 0,
                    'Unit': 'Count',
                    'Dimensions': [
                        {
                            'Name': 'SecurityGroupId',
                            'Value': SECURITY_GROUP_ID
                        }
                    ]
                }
            ]
        )
        
        logger.info("CloudWatch metrics logged successfully")
        
    except Exception as e:
        logger.warning(f"Failed to log CloudWatch metrics: {str(e)}")


def create_detailed_notification(current_ips: Set[str], existing_ips: Set[str], changes_made: bool) -> str:
    """
    Create detailed notification message for SNS.
    """
    try:
        ips_to_add = current_ips - existing_ips
        ips_to_remove = existing_ips - current_ips
        
        message_parts = [
            "Cloudflare IP Update Report",
            "=" * 30,
            f"Security Group ID: {SECURITY_GROUP_ID}",
            f"Timestamp: {time.strftime('%Y-%m-%d %H:%M:%S UTC', time.gmtime())}",
            "",
            f"Current Cloudflare IPs: {len(current_ips)}",
            f"Previous Security Group IPs: {len(existing_ips)}",
            f"Changes Made: {'Yes' if changes_made else 'No'}",
            ""
        ]
        
        if changes_made:
            message_parts.extend([
                f"IPs Added: {len(ips_to_add)}",
                f"IPs Removed: {len(ips_to_remove)}",
                ""
            ])
            
            if ips_to_add:
                message_parts.extend([
                    "New IP Ranges:",
                    *[f"  + {ip}" for ip in sorted(ips_to_add)],
                    ""
                ])
            
            if ips_to_remove:
                message_parts.extend([
                    "Removed IP Ranges:",
                    *[f"  - {ip}" for ip in sorted(ips_to_remove)],
                    ""
                ])
        else:
            message_parts.append("No changes were needed - security group is up to date.")
        
        # Add state management information
        if ENABLE_STATE_VALIDATION or ENABLE_DRIFT_DETECTION:
            message_parts.extend([
                "",
                "State Management:",
                f"  State Validation: {'Enabled' if ENABLE_STATE_VALIDATION else 'Disabled'}",
                f"  Drift Detection: {'Enabled' if ENABLE_DRIFT_DETECTION else 'Disabled'}",
                f"  Enhanced Lifecycle: {'Enabled' if ENABLE_ENHANCED_LIFECYCLE else 'Disabled'}"
            ])
        
        # Add quota information if enabled
        if ENABLE_QUOTA_CHECKING:
            message_parts.extend([
                "",
                "Quota Information:",
                f"  Quota Checking: Enabled",
                f"  Rules Approaching Limit: {'Yes' if RULES_APPROACHING_LIMIT else 'No'}",
                f"  Multiple Groups Required: {'Yes' if REQUIRES_MULTIPLE_GROUPS else 'No'}"
            ])
            
            if REQUIRES_MULTIPLE_GROUPS:
                message_parts.append(f"  Security Groups Needed: {SECURITY_GROUPS_NEEDED}")
        
        return "\n".join(message_parts)
        
    except Exception as e:
        logger.error(f"Error creating detailed notification: {str(e)}")
        return f"Cloudflare IP update completed. Changes made: {changes_made}. IP count: {len(current_ips)}"


def send_notification(message: str, notification_type: str = "INFO"):
    """
    Send notification via SNS.
    """
    try:
        if not SNS_TOPIC_ARN:
            logger.info("SNS topic not configured, skipping notification")
            return
        
        subject = f"Cloudflare IP Update - {notification_type}"
        
        get_sns_client().publish(
            TopicArn=SNS_TOPIC_ARN,
            Subject=subject,
            Message=message
        )
        
        logger.info(f"Notification sent successfully: {notification_type}")
        
        # Log notification metric
        try:
            cloudwatch = boto3.client('cloudwatch')
            cloudwatch.put_metric_data(
                Namespace='CloudflareIPUpdater',
                MetricData=[
                    {
                        'MetricName': 'NotificationsSent',
                        'Value': 1,
                        'Unit': 'Count',
                        'Dimensions': [
                            {
                                'Name': 'NotificationType',
                                'Value': notification_type
                            }
                        ]
                    }
                ]
            )
        except Exception as metric_error:
            logger.warning(f"Failed to log notification metric: {str(metric_error)}")
        
    except Exception as e:
        logger.error(f"Error sending notification: {str(e)}")


def download_terraform_config(temp_dir: str):
    """
    Download Terraform configuration files from S3.
    """
    try:
        bucket = TERRAFORM_CONFIG_S3_BUCKET
        key = TERRAFORM_CONFIG_S3_KEY
        
        logger.info(f"Downloading Terraform config from s3://{bucket}/{key}")
        
        s3_client = boto3.client('s3')
        
        # Download and extract configuration
        config_path = os.path.join(temp_dir, 'terraform-config.zip')
        s3_client.download_file(bucket, key, config_path)
        
        # Extract if it's a zip file
        if key.endswith('.zip'):
            import zipfile
            with zipfile.ZipFile(config_path, 'r') as zip_ref:
                zip_ref.extractall(temp_dir)
            os.remove(config_path)
        else:
            # If it's a single file, rename it appropriately
            target_path = os.path.join(temp_dir, 'main.tf')
            os.rename(config_path, target_path)
        
        logger.info("Terraform configuration downloaded successfully")
        
    except Exception as e:
        logger.error(f"Error downloading Terraform config: {str(e)}")
        raise


def setup_terraform_backend(temp_dir: str):
    """
    Set up Terraform backend configuration for state management.
    """
    try:
        backend_config = f"""
terraform {{
  backend "s3" {{
    bucket = "{TERRAFORM_STATE_S3_BUCKET}"
    key    = "{TERRAFORM_STATE_S3_KEY}"
    region = "{boto3.Session().region_name or 'us-east-1'}"
  }}
}}
"""
        
        backend_file = os.path.join(temp_dir, 'backend.tf')
        with open(backend_file, 'w') as f:
            f.write(backend_config)
        
        logger.info("Terraform backend configuration created")
        
    except Exception as e:
        logger.error(f"Error setting up Terraform backend: {str(e)}")
        raise


def run_terraform_command(command: List[str], working_dir: str) -> bool:
    """
    Run a Terraform command and return success status.
    """
    try:
        logger.info(f"Running command: {' '.join(command)}")
        
        result = subprocess.run(
            command,
            cwd=working_dir,
            capture_output=True,
            text=True,
            timeout=300  # 5 minute timeout
        )
        
        if result.stdout:
            logger.info(f"Command output: {result.stdout}")
        
        if result.stderr:
            logger.warning(f"Command stderr: {result.stderr}")
        
        if result.returncode == 0:
            logger.info(f"Command completed successfully: {' '.join(command)}")
            return True
        else:
            logger.error(f"Command failed with return code {result.returncode}: {' '.join(command)}")
            return False
        
    except subprocess.TimeoutExpired:
        logger.error(f"Command timed out: {' '.join(command)}")
        return False
    except Exception as e:
        logger.error(f"Error running command {' '.join(command)}: {str(e)}")
        return False