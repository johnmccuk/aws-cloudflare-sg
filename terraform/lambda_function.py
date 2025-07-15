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
        
        # Fetch current Cloudflare IP ranges
        current_ips = fetch_cloudflare_ips()
        logger.info(f"Retrieved {len(current_ips)} Cloudflare IP ranges")
        
        # Get existing security group rules
        existing_ips = get_existing_security_group_ips()
        logger.info(f"Found {len(existing_ips)} existing IP ranges in security group")
        
        # Compare IP sets to determine if changes are needed
        ips_to_add = current_ips - existing_ips
        ips_to_remove = existing_ips - current_ips
        
        if not ips_to_add and not ips_to_remove:
            logger.info("No changes needed - IP ranges are up to date")
            changes_made = False
        else:
            logger.info(f"Changes detected: {len(ips_to_add)} IPs to add, {len(ips_to_remove)} IPs to remove")
            
            # Trigger Terraform automation to apply changes
            changes_made = trigger_terraform_automation(current_ips, existing_ips)
        
        # Send notification if changes were made
        if changes_made and SNS_TOPIC_ARN:
            notification_details = create_detailed_notification(current_ips, existing_ips, changes_made)
            send_notification(notification_details)
        
        return {
            'statusCode': 200,
            'body': json.dumps({
                'message': 'Cloudflare IP update completed successfully',
                'changes_made': changes_made,
                'ip_count': len(current_ips)
            })
        }
        
    except Exception as e:
        error_msg = f"Error updating Cloudflare IPs: {str(e)}"
        logger.error(error_msg, exc_info=True)
        
        # Send error notification
        if SNS_TOPIC_ARN:
            send_notification(f"ERROR: {error_msg}")
        
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


def send_notification(message: str):
    """
    Send SNS notification about the update.
    """
    try:
        get_sns_client().publish(
            TopicArn=SNS_TOPIC_ARN,
            Message=message,
            Subject="Cloudflare IP Update Notification"
        )
        logger.info("Notification sent successfully")
        logger.info(f"Notification content preview: {message[:200]}...")
    except Exception as e:
        logger.error(f"Error sending notification: {str(e)}")