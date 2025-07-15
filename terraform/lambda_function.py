import json
import boto3
import requests
import logging
import time
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
        
        # Compare and update if necessary
        changes_made = update_security_group_if_needed(current_ips, existing_ips)
        
        # Send notification if changes were made
        if changes_made and SNS_TOPIC_ARN:
            send_notification(f"Cloudflare IP ranges updated successfully. {len(current_ips)} IP ranges now configured.")
        
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
    except Exception as e:
        logger.error(f"Error sending notification: {str(e)}")