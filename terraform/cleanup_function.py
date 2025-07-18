#!/usr/bin/env python3
"""
Cleanup Lambda function for Cloudflare IP updater infrastructure.
This function handles graceful cleanup of resources during terraform destroy operations.
"""

import json
import boto3
import logging
import time
import os
from typing import Dict, List, Any
from botocore.exceptions import ClientError, BotoCoreError

# Configure logging
logger = logging.getLogger()
logger.setLevel(logging.INFO)

# AWS clients
ec2_client = None
lambda_client = None
events_client = None
sns_client = None
cloudwatch_client = None
logs_client = None

def get_aws_client(service_name: str):
    """Get AWS client for specified service, initializing if needed."""
    global ec2_client, lambda_client, events_client, sns_client, cloudwatch_client, logs_client
    
    clients = {
        'ec2': ec2_client,
        'lambda': lambda_client,
        'events': events_client,
        'sns': sns_client,
        'cloudwatch': cloudwatch_client,
        'logs': logs_client
    }
    
    if clients[service_name] is None:
        clients[service_name] = boto3.client(service_name)
        
        # Update global variables
        if service_name == 'ec2':
            ec2_client = clients[service_name]
        elif service_name == 'lambda':
            lambda_client = clients[service_name]
        elif service_name == 'events':
            events_client = clients[service_name]
        elif service_name == 'sns':
            sns_client = clients[service_name]
        elif service_name == 'cloudwatch':
            cloudwatch_client = clients[service_name]
        elif service_name == 'logs':
            logs_client = clients[service_name]
    
    return clients[service_name]

# Configuration from environment variables
ENVIRONMENT = os.environ.get('ENVIRONMENT', 'unknown')
SECURITY_GROUP_ID = os.environ.get('SECURITY_GROUP_ID', '')
MAIN_LAMBDA_FUNCTION = os.environ.get('MAIN_LAMBDA_FUNCTION', '')
LOG_GROUP_NAME = os.environ.get('LOG_GROUP_NAME', '')
SNS_TOPIC_ARN = os.environ.get('SNS_TOPIC_ARN', '')
EVENTBRIDGE_RULE_NAME = os.environ.get('EVENTBRIDGE_RULE_NAME', '')
CLEANUP_MODE = os.environ.get('CLEANUP_MODE', 'graceful')
# Additional resources for cleanup
ADDITIONAL_SECURITY_GROUP_IDS = os.environ.get('ADDITIONAL_SECURITY_GROUP_IDS', '').split(',') if os.environ.get('ADDITIONAL_SECURITY_GROUP_IDS') else []
CLOUDWATCH_DASHBOARD_NAME = os.environ.get('CLOUDWATCH_DASHBOARD_NAME', '')
CLOUDWATCH_ALARM_NAMES = os.environ.get('CLOUDWATCH_ALARM_NAMES', '').split(',') if os.environ.get('CLOUDWATCH_ALARM_NAMES') else []
MAIN_IAM_ROLE_NAME = os.environ.get('MAIN_IAM_ROLE_NAME', '')
CLEANUP_GROUP_TAG = os.environ.get('CLEANUP_GROUP_TAG', '')


def lambda_handler(event, context):
    """
    Main Lambda handler for cleanup operations.
    """
    try:
        logger.info("=== CLOUDFLARE IP UPDATER CLEANUP START ===")
        logger.info(f"Environment: {ENVIRONMENT}")
        logger.info(f"Cleanup Mode: {CLEANUP_MODE}")
        logger.info(f"Event: {json.dumps(event, default=str)}")
        
        cleanup_results = {
            'environment': ENVIRONMENT,
            'cleanup_mode': CLEANUP_MODE,
            'timestamp': time.strftime('%Y-%m-%d %H:%M:%S UTC', time.gmtime()),
            'operations': []
        }
        
        # Determine cleanup operations based on event type
        if event.get('source') == 'terraform.destroy':
            logger.info("Terraform destroy cleanup requested")
            cleanup_results = perform_terraform_destroy_cleanup(cleanup_results)
        elif event.get('cleanup_type') == 'manual':
            logger.info("Manual cleanup requested")
            cleanup_results = perform_manual_cleanup(cleanup_results, event.get('operations', []))
        else:
            logger.info("General cleanup requested")
            cleanup_results = perform_general_cleanup(cleanup_results)
        
        # Send cleanup notification if SNS topic is configured
        if SNS_TOPIC_ARN:
            send_cleanup_notification(cleanup_results)
        
        logger.info("=== CLOUDFLARE IP UPDATER CLEANUP COMPLETED ===")
        
        return {
            'statusCode': 200,
            'body': json.dumps({
                'message': 'Cleanup completed successfully',
                'results': cleanup_results
            })
        }
        
    except Exception as e:
        error_msg = f"Error during cleanup: {str(e)}"
        logger.error(error_msg, exc_info=True)
        
        # Send error notification
        if SNS_TOPIC_ARN:
            try:
                get_aws_client('sns').publish(
                    TopicArn=SNS_TOPIC_ARN,
                    Subject=f"❌ Cloudflare IP Cleanup Error - {ENVIRONMENT}",
                    Message=f"Cleanup operation failed:\n\n{error_msg}"
                )
            except Exception as sns_error:
                logger.error(f"Failed to send error notification: {str(sns_error)}")
        
        return {
            'statusCode': 500,
            'body': json.dumps({
                'error': error_msg
            })
        }


def perform_terraform_destroy_cleanup(cleanup_results: Dict[str, Any]) -> Dict[str, Any]:
    """
    Perform cleanup operations specifically for terraform destroy.
    """
    logger.info("Starting Terraform destroy cleanup operations")
    
    # Step 1: Disable EventBridge rule to prevent new executions
    if EVENTBRIDGE_RULE_NAME:
        cleanup_results['operations'].append(
            disable_eventbridge_rule(EVENTBRIDGE_RULE_NAME)
        )
    
    # Step 2: Wait for running Lambda executions to complete
    if MAIN_LAMBDA_FUNCTION:
        cleanup_results['operations'].append(
            wait_for_lambda_executions(MAIN_LAMBDA_FUNCTION)
        )
    
    # Step 3: Clean up security group rules gracefully
    if SECURITY_GROUP_ID:
        cleanup_results['operations'].append(
            cleanup_security_group_rules(SECURITY_GROUP_ID)
        )
    
    # Step 3a: Clean up additional security groups
    if ADDITIONAL_SECURITY_GROUP_IDS:
        cleanup_results['operations'].append(
            cleanup_additional_security_groups(ADDITIONAL_SECURITY_GROUP_IDS)
        )
    
    # Step 4: Clean up CloudWatch resources
    cleanup_results['operations'].append(
        cleanup_cloudwatch_resources()
    )
    
    # Step 4a: Clean up specific CloudWatch alarms and dashboards
    if CLOUDWATCH_ALARM_NAMES or CLOUDWATCH_DASHBOARD_NAME:
        cleanup_results['operations'].append(
            cleanup_specific_cloudwatch_resources()
        )
    
    # Step 5: Clean up SNS subscriptions
    if SNS_TOPIC_ARN:
        cleanup_results['operations'].append(
            cleanup_sns_subscriptions(SNS_TOPIC_ARN)
        )
    
    # Step 6: Clean up resources by tags
    if CLEANUP_GROUP_TAG:
        cleanup_results['operations'].append(
            cleanup_resources_by_tags(CLEANUP_GROUP_TAG)
        )
    
    logger.info("Terraform destroy cleanup operations completed")
    return cleanup_results


def perform_manual_cleanup(cleanup_results: Dict[str, Any], operations: List[str]) -> Dict[str, Any]:
    """
    Perform manual cleanup operations based on specified operations list.
    """
    logger.info(f"Starting manual cleanup operations: {operations}")
    
    operation_map = {
        'disable_eventbridge': lambda: disable_eventbridge_rule(EVENTBRIDGE_RULE_NAME),
        'cleanup_security_group': lambda: cleanup_security_group_rules(SECURITY_GROUP_ID),
        'cleanup_cloudwatch': lambda: cleanup_cloudwatch_resources(),
        'cleanup_sns': lambda: cleanup_sns_subscriptions(SNS_TOPIC_ARN),
        'wait_lambda': lambda: wait_for_lambda_executions(MAIN_LAMBDA_FUNCTION)
    }
    
    for operation in operations:
        if operation in operation_map:
            try:
                result = operation_map[operation]()
                cleanup_results['operations'].append(result)
            except Exception as e:
                logger.error(f"Manual cleanup operation '{operation}' failed: {str(e)}")
                cleanup_results['operations'].append({
                    'operation': operation,
                    'status': 'failed',
                    'error': str(e)
                })
        else:
            logger.warning(f"Unknown manual cleanup operation: {operation}")
    
    return cleanup_results


def perform_general_cleanup(cleanup_results: Dict[str, Any]) -> Dict[str, Any]:
    """
    Perform general cleanup operations for maintenance.
    """
    logger.info("Starting general cleanup operations")
    
    # Clean up old log streams
    if LOG_GROUP_NAME:
        cleanup_results['operations'].append(
            cleanup_old_log_streams(LOG_GROUP_NAME)
        )
    
    # Validate resource state
    cleanup_results['operations'].append(
        validate_resource_state()
    )
    
    return cleanup_results


def disable_eventbridge_rule(rule_name: str) -> Dict[str, Any]:
    """
    Disable EventBridge rule to prevent new Lambda executions.
    """
    try:
        logger.info(f"Disabling EventBridge rule: {rule_name}")
        
        events_client = get_aws_client('events')
        
        # Check if rule exists
        try:
            events_client.describe_rule(Name=rule_name)
        except ClientError as e:
            if e.response['Error']['Code'] == 'ResourceNotFoundException':
                logger.info(f"EventBridge rule {rule_name} does not exist")
                return {
                    'operation': 'disable_eventbridge_rule',
                    'status': 'skipped',
                    'message': 'Rule does not exist'
                }
            raise
        
        # Disable the rule
        events_client.disable_rule(Name=rule_name)
        logger.info(f"EventBridge rule {rule_name} disabled successfully")
        
        # Remove targets from the rule
        try:
            targets_response = events_client.list_targets_by_rule(Rule=rule_name)
            if targets_response['Targets']:
                target_ids = [target['Id'] for target in targets_response['Targets']]
                events_client.remove_targets(
                    Rule=rule_name,
                    Ids=target_ids
                )
                logger.info(f"Removed {len(target_ids)} targets from rule {rule_name}")
        except Exception as e:
            logger.warning(f"Failed to remove targets from rule {rule_name}: {str(e)}")
        
        return {
            'operation': 'disable_eventbridge_rule',
            'status': 'success',
            'rule_name': rule_name
        }
        
    except Exception as e:
        logger.error(f"Failed to disable EventBridge rule {rule_name}: {str(e)}")
        return {
            'operation': 'disable_eventbridge_rule',
            'status': 'failed',
            'error': str(e)
        }


def wait_for_lambda_executions(function_name: str) -> Dict[str, Any]:
    """
    Wait for running Lambda executions to complete.
    """
    try:
        logger.info(f"Waiting for Lambda executions to complete: {function_name}")
        
        lambda_client = get_aws_client('lambda')
        
        # Check if function exists
        try:
            lambda_client.get_function(FunctionName=function_name)
        except ClientError as e:
            if e.response['Error']['Code'] == 'ResourceNotFoundException':
                logger.info(f"Lambda function {function_name} does not exist")
                return {
                    'operation': 'wait_for_lambda_executions',
                    'status': 'skipped',
                    'message': 'Function does not exist'
                }
            raise
        
        # Wait for executions to complete (simple approach - wait fixed time)
        wait_time = 60  # Wait 60 seconds for executions to complete
        logger.info(f"Waiting {wait_time} seconds for Lambda executions to complete...")
        time.sleep(wait_time)
        
        return {
            'operation': 'wait_for_lambda_executions',
            'status': 'success',
            'function_name': function_name,
            'wait_time_seconds': wait_time
        }
        
    except Exception as e:
        logger.error(f"Error waiting for Lambda executions: {str(e)}")
        return {
            'operation': 'wait_for_lambda_executions',
            'status': 'failed',
            'error': str(e)
        }


def cleanup_security_group_rules(security_group_id: str) -> Dict[str, Any]:
    """
    Clean up security group rules gracefully.
    """
    try:
        logger.info(f"Cleaning up security group rules: {security_group_id}")
        
        ec2_client = get_aws_client('ec2')
        
        # Check if security group exists
        try:
            response = ec2_client.describe_security_groups(GroupIds=[security_group_id])
            security_group = response['SecurityGroups'][0]
        except ClientError as e:
            if e.response['Error']['Code'] == 'InvalidGroupId.NotFound':
                logger.info(f"Security group {security_group_id} does not exist")
                return {
                    'operation': 'cleanup_security_group_rules',
                    'status': 'skipped',
                    'message': 'Security group does not exist'
                }
            raise
        
        rules_removed = 0
        
        # Remove all ingress rules
        if security_group.get('IpPermissions'):
            try:
                ec2_client.revoke_security_group_ingress(
                    GroupId=security_group_id,
                    IpPermissions=security_group['IpPermissions']
                )
                rules_removed += len(security_group['IpPermissions'])
                logger.info(f"Removed {len(security_group['IpPermissions'])} ingress rules")
            except ClientError as e:
                if e.response['Error']['Code'] != 'InvalidPermission.NotFound':
                    logger.warning(f"Failed to remove some ingress rules: {str(e)}")
        
        # Remove all egress rules (except default)
        if security_group.get('IpPermissionsEgress'):
            # Keep default egress rule (allow all outbound)
            custom_egress_rules = [
                rule for rule in security_group['IpPermissionsEgress']
                if not (rule.get('IpProtocol') == '-1' and 
                       rule.get('IpRanges') == [{'CidrIp': '0.0.0.0/0'}] and
                       rule.get('Ipv6Ranges') == [{'CidrIpv6': '::/0'}])
            ]
            
            if custom_egress_rules:
                try:
                    ec2_client.revoke_security_group_egress(
                        GroupId=security_group_id,
                        IpPermissions=custom_egress_rules
                    )
                    rules_removed += len(custom_egress_rules)
                    logger.info(f"Removed {len(custom_egress_rules)} custom egress rules")
                except ClientError as e:
                    if e.response['Error']['Code'] != 'InvalidPermission.NotFound':
                        logger.warning(f"Failed to remove some egress rules: {str(e)}")
        
        return {
            'operation': 'cleanup_security_group_rules',
            'status': 'success',
            'security_group_id': security_group_id,
            'rules_removed': rules_removed
        }
        
    except Exception as e:
        logger.error(f"Failed to cleanup security group rules: {str(e)}")
        return {
            'operation': 'cleanup_security_group_rules',
            'status': 'failed',
            'error': str(e)
        }


def cleanup_cloudwatch_resources() -> Dict[str, Any]:
    """
    Clean up CloudWatch alarms and dashboards related to the Cloudflare IP updater.
    """
    try:
        logger.info("Cleaning up CloudWatch resources")
        
        cloudwatch_client = get_aws_client('cloudwatch')
        resources_cleaned = 0
        
        # Find and delete related alarms
        try:
            alarms_response = cloudwatch_client.describe_alarms(
                AlarmNamePrefix=f"cloudflare-ip"
            )
            
            alarm_names = [alarm['AlarmName'] for alarm in alarms_response['MetricAlarms']]
            
            if alarm_names:
                cloudwatch_client.delete_alarms(AlarmNames=alarm_names)
                resources_cleaned += len(alarm_names)
                logger.info(f"Deleted {len(alarm_names)} CloudWatch alarms")
        except Exception as e:
            logger.warning(f"Failed to cleanup CloudWatch alarms: {str(e)}")
        
        # Find and delete related dashboards
        try:
            dashboards_response = cloudwatch_client.list_dashboards(
                DashboardNamePrefix=f"cloudflare-ip"
            )
            
            dashboard_names = [dashboard['DashboardName'] for dashboard in dashboards_response['DashboardEntries']]
            
            for dashboard_name in dashboard_names:
                try:
                    cloudwatch_client.delete_dashboards(DashboardNames=[dashboard_name])
                    resources_cleaned += 1
                    logger.info(f"Deleted CloudWatch dashboard: {dashboard_name}")
                except Exception as e:
                    logger.warning(f"Failed to delete dashboard {dashboard_name}: {str(e)}")
        except Exception as e:
            logger.warning(f"Failed to cleanup CloudWatch dashboards: {str(e)}")
        
        return {
            'operation': 'cleanup_cloudwatch_resources',
            'status': 'success',
            'resources_cleaned': resources_cleaned
        }
        
    except Exception as e:
        logger.error(f"Failed to cleanup CloudWatch resources: {str(e)}")
        return {
            'operation': 'cleanup_cloudwatch_resources',
            'status': 'failed',
            'error': str(e)
        }


def cleanup_sns_subscriptions(topic_arn: str) -> Dict[str, Any]:
    """
    Clean up SNS subscriptions for the topic.
    """
    try:
        logger.info(f"Cleaning up SNS subscriptions for topic: {topic_arn}")
        
        sns_client = get_aws_client('sns')
        
        # Check if topic exists
        try:
            sns_client.get_topic_attributes(TopicArn=topic_arn)
        except ClientError as e:
            if e.response['Error']['Code'] == 'NotFound':
                logger.info(f"SNS topic {topic_arn} does not exist")
                return {
                    'operation': 'cleanup_sns_subscriptions',
                    'status': 'skipped',
                    'message': 'Topic does not exist'
                }
            raise
        
        # List and unsubscribe all subscriptions
        subscriptions_response = sns_client.list_subscriptions_by_topic(TopicArn=topic_arn)
        subscriptions_cleaned = 0
        
        for subscription in subscriptions_response['Subscriptions']:
            try:
                if subscription['SubscriptionArn'] != 'PendingConfirmation':
                    sns_client.unsubscribe(SubscriptionArn=subscription['SubscriptionArn'])
                    subscriptions_cleaned += 1
                    logger.info(f"Unsubscribed: {subscription['SubscriptionArn']}")
            except Exception as e:
                logger.warning(f"Failed to unsubscribe {subscription['SubscriptionArn']}: {str(e)}")
        
        return {
            'operation': 'cleanup_sns_subscriptions',
            'status': 'success',
            'topic_arn': topic_arn,
            'subscriptions_cleaned': subscriptions_cleaned
        }
        
    except Exception as e:
        logger.error(f"Failed to cleanup SNS subscriptions: {str(e)}")
        return {
            'operation': 'cleanup_sns_subscriptions',
            'status': 'failed',
            'error': str(e)
        }


def cleanup_old_log_streams(log_group_name: str) -> Dict[str, Any]:
    """
    Clean up old log streams to reduce storage costs.
    """
    try:
        logger.info(f"Cleaning up old log streams in: {log_group_name}")
        
        logs_client = get_aws_client('logs')
        
        # Check if log group exists
        try:
            logs_client.describe_log_groups(logGroupNamePrefix=log_group_name)
        except ClientError as e:
            if e.response['Error']['Code'] == 'ResourceNotFoundException':
                logger.info(f"Log group {log_group_name} does not exist")
                return {
                    'operation': 'cleanup_old_log_streams',
                    'status': 'skipped',
                    'message': 'Log group does not exist'
                }
            raise
        
        # Get log streams older than 7 days
        cutoff_time = int((time.time() - (7 * 24 * 60 * 60)) * 1000)  # 7 days ago in milliseconds
        
        streams_response = logs_client.describe_log_streams(
            logGroupName=log_group_name,
            orderBy='LastEventTime',
            descending=False
        )
        
        streams_deleted = 0
        for stream in streams_response['logStreams']:
            if stream.get('lastEventTime', 0) < cutoff_time:
                try:
                    logs_client.delete_log_stream(
                        logGroupName=log_group_name,
                        logStreamName=stream['logStreamName']
                    )
                    streams_deleted += 1
                    logger.info(f"Deleted old log stream: {stream['logStreamName']}")
                except Exception as e:
                    logger.warning(f"Failed to delete log stream {stream['logStreamName']}: {str(e)}")
        
        return {
            'operation': 'cleanup_old_log_streams',
            'status': 'success',
            'log_group_name': log_group_name,
            'streams_deleted': streams_deleted
        }
        
    except Exception as e:
        logger.error(f"Failed to cleanup old log streams: {str(e)}")
        return {
            'operation': 'cleanup_old_log_streams',
            'status': 'failed',
            'error': str(e)
        }


def validate_resource_state() -> Dict[str, Any]:
    """
    Validate the current state of resources for consistency.
    """
    try:
        logger.info("Validating resource state")
        
        validation_results = {
            'security_group_exists': False,
            'lambda_function_exists': False,
            'eventbridge_rule_exists': False,
            'sns_topic_exists': False,
            'log_group_exists': False
        }
        
        # Check security group
        if SECURITY_GROUP_ID:
            try:
                get_aws_client('ec2').describe_security_groups(GroupIds=[SECURITY_GROUP_ID])
                validation_results['security_group_exists'] = True
            except ClientError:
                pass
        
        # Check Lambda function
        if MAIN_LAMBDA_FUNCTION:
            try:
                get_aws_client('lambda').get_function(FunctionName=MAIN_LAMBDA_FUNCTION)
                validation_results['lambda_function_exists'] = True
            except ClientError:
                pass
        
        # Check EventBridge rule
        if EVENTBRIDGE_RULE_NAME:
            try:
                get_aws_client('events').describe_rule(Name=EVENTBRIDGE_RULE_NAME)
                validation_results['eventbridge_rule_exists'] = True
            except ClientError:
                pass
        
        # Check SNS topic
        if SNS_TOPIC_ARN:
            try:
                get_aws_client('sns').get_topic_attributes(TopicArn=SNS_TOPIC_ARN)
                validation_results['sns_topic_exists'] = True
            except ClientError:
                pass
        
        # Check log group
        if LOG_GROUP_NAME:
            try:
                get_aws_client('logs').describe_log_groups(logGroupNamePrefix=LOG_GROUP_NAME)
                validation_results['log_group_exists'] = True
            except ClientError:
                pass
        
        return {
            'operation': 'validate_resource_state',
            'status': 'success',
            'validation_results': validation_results
        }
        
    except Exception as e:
        logger.error(f"Failed to validate resource state: {str(e)}")
        return {
            'operation': 'validate_resource_state',
            'status': 'failed',
            'error': str(e)
        }


def cleanup_additional_security_groups(security_group_ids: List[str]) -> Dict[str, Any]:
    """
    Clean up additional security groups created for handling large IP lists.
    """
    try:
        logger.info(f"Cleaning up additional security groups: {security_group_ids}")
        
        ec2_client = get_aws_client('ec2')
        groups_cleaned = 0
        
        for sg_id in security_group_ids:
            if not sg_id.strip():  # Skip empty strings
                continue
                
            try:
                # Check if security group exists
                response = ec2_client.describe_security_groups(GroupIds=[sg_id])
                security_group = response['SecurityGroups'][0]
                
                # Remove all ingress rules
                if security_group.get('IpPermissions'):
                    try:
                        ec2_client.revoke_security_group_ingress(
                            GroupId=sg_id,
                            IpPermissions=security_group['IpPermissions']
                        )
                        logger.info(f"Removed ingress rules from security group {sg_id}")
                    except ClientError as e:
                        if e.response['Error']['Code'] != 'InvalidPermission.NotFound':
                            logger.warning(f"Failed to remove ingress rules from {sg_id}: {str(e)}")
                
                # Remove custom egress rules (keep default)
                if security_group.get('IpPermissionsEgress'):
                    custom_egress_rules = [
                        rule for rule in security_group['IpPermissionsEgress']
                        if not (rule.get('IpProtocol') == '-1' and 
                               rule.get('IpRanges') == [{'CidrIp': '0.0.0.0/0'}] and
                               rule.get('Ipv6Ranges') == [{'CidrIpv6': '::/0'}])
                    ]
                    
                    if custom_egress_rules:
                        try:
                            ec2_client.revoke_security_group_egress(
                                GroupId=sg_id,
                                IpPermissions=custom_egress_rules
                            )
                            logger.info(f"Removed custom egress rules from security group {sg_id}")
                        except ClientError as e:
                            if e.response['Error']['Code'] != 'InvalidPermission.NotFound':
                                logger.warning(f"Failed to remove egress rules from {sg_id}: {str(e)}")
                
                groups_cleaned += 1
                
            except ClientError as e:
                if e.response['Error']['Code'] == 'InvalidGroupId.NotFound':
                    logger.info(f"Security group {sg_id} does not exist")
                else:
                    logger.warning(f"Failed to cleanup security group {sg_id}: {str(e)}")
        
        return {
            'operation': 'cleanup_additional_security_groups',
            'status': 'success',
            'groups_cleaned': groups_cleaned,
            'total_groups': len([sg for sg in security_group_ids if sg.strip()])
        }
        
    except Exception as e:
        logger.error(f"Failed to cleanup additional security groups: {str(e)}")
        return {
            'operation': 'cleanup_additional_security_groups',
            'status': 'failed',
            'error': str(e)
        }


def cleanup_terraform_resources() -> Dict[str, Any]:
    """
    Clean up Terraform-managed resources during destroy operations.
    """
    try:
        logger.info("Cleaning up Terraform-managed resources")
        
        resources_cleaned = 0
        cleanup_details = []
        
        # Clean up Lambda function environment variables that might reference destroyed resources
        try:
            lambda_client = get_aws_client('lambda')
            
            # Update function configuration to remove references to resources being destroyed
            if MAIN_LAMBDA_FUNCTION:
                current_config = lambda_client.get_function_configuration(FunctionName=MAIN_LAMBDA_FUNCTION)
                env_vars = current_config.get('Environment', {}).get('Variables', {})
                
                # Remove environment variables that reference resources being destroyed
                cleanup_env_vars = {
                    key: value for key, value in env_vars.items()
                    if not any(cleanup_key in key.upper() for cleanup_key in ['SECURITY_GROUP_ID', 'SNS_TOPIC_ARN'])
                }
                
                if len(cleanup_env_vars) != len(env_vars):
                    lambda_client.update_function_configuration(
                        FunctionName=MAIN_LAMBDA_FUNCTION,
                        Environment={'Variables': cleanup_env_vars}
                    )
                    logger.info(f"Updated Lambda function environment variables for cleanup")
                    resources_cleaned += 1
                    cleanup_details.append("Updated Lambda environment variables")
        
        except Exception as e:
            logger.warning(f"Failed to cleanup Lambda environment variables: {str(e)}")
        
        return {
            'operation': 'cleanup_terraform_resources',
            'status': 'success',
            'resources_cleaned': resources_cleaned,
            'cleanup_details': cleanup_details
        }
        
    except Exception as e:
        logger.error(f"Failed to cleanup Terraform resources: {str(e)}")
        return {
            'operation': 'cleanup_terraform_resources',
            'status': 'failed',
            'error': str(e)
        }


def validate_cleanup_completion() -> Dict[str, Any]:
    """
    Validate that cleanup operations have been completed successfully.
    """
    try:
        logger.info("Validating cleanup completion")
        
        validation_results = {
            'security_group_rules_cleaned': False,
            'eventbridge_rule_disabled': False,
            'sns_subscriptions_cleaned': False,
            'lambda_function_accessible': False,
            'cleanup_timestamp': time.strftime('%Y-%m-%d %H:%M:%S UTC', time.gmtime())
        }
        
        # Check if security group rules have been cleaned
        if SECURITY_GROUP_ID:
            try:
                ec2_client = get_aws_client('ec2')
                response = ec2_client.describe_security_groups(GroupIds=[SECURITY_GROUP_ID])
                security_group = response['SecurityGroups'][0]
                
                # Check if ingress rules are minimal (only default rules remain)
                ingress_rules = security_group.get('IpPermissions', [])
                if len(ingress_rules) <= 1:  # Allow for one default rule
                    validation_results['security_group_rules_cleaned'] = True
                    logger.info("Security group rules have been cleaned")
                else:
                    logger.warning(f"Security group still has {len(ingress_rules)} ingress rules")
                    
            except ClientError as e:
                if e.response['Error']['Code'] == 'InvalidGroupId.NotFound':
                    validation_results['security_group_rules_cleaned'] = True
                    logger.info("Security group has been deleted")
                else:
                    logger.warning(f"Failed to check security group status: {str(e)}")
        
        # Check if EventBridge rule is disabled
        if EVENTBRIDGE_RULE_NAME:
            try:
                events_client = get_aws_client('events')
                response = events_client.describe_rule(Name=EVENTBRIDGE_RULE_NAME)
                
                if response['State'] == 'DISABLED':
                    validation_results['eventbridge_rule_disabled'] = True
                    logger.info("EventBridge rule is disabled")
                else:
                    logger.warning(f"EventBridge rule state: {response['State']}")
                    
            except ClientError as e:
                if e.response['Error']['Code'] == 'ResourceNotFoundException':
                    validation_results['eventbridge_rule_disabled'] = True
                    logger.info("EventBridge rule has been deleted")
                else:
                    logger.warning(f"Failed to check EventBridge rule status: {str(e)}")
        
        # Check if SNS subscriptions have been cleaned
        if SNS_TOPIC_ARN:
            try:
                sns_client = get_aws_client('sns')
                response = sns_client.list_subscriptions_by_topic(TopicArn=SNS_TOPIC_ARN)
                
                active_subscriptions = [
                    sub for sub in response['Subscriptions']
                    if sub['SubscriptionArn'] != 'PendingConfirmation'
                ]
                
                if len(active_subscriptions) == 0:
                    validation_results['sns_subscriptions_cleaned'] = True
                    logger.info("SNS subscriptions have been cleaned")
                else:
                    logger.warning(f"SNS topic still has {len(active_subscriptions)} active subscriptions")
                    
            except ClientError as e:
                if e.response['Error']['Code'] == 'NotFound':
                    validation_results['sns_subscriptions_cleaned'] = True
                    logger.info("SNS topic has been deleted")
                else:
                    logger.warning(f"Failed to check SNS topic status: {str(e)}")
        
        # Check if Lambda function is still accessible
        if MAIN_LAMBDA_FUNCTION:
            try:
                lambda_client = get_aws_client('lambda')
                lambda_client.get_function(FunctionName=MAIN_LAMBDA_FUNCTION)
                validation_results['lambda_function_accessible'] = True
                logger.info("Lambda function is still accessible")
                
            except ClientError as e:
                if e.response['Error']['Code'] == 'ResourceNotFoundException':
                    logger.info("Lambda function has been deleted")
                else:
                    logger.warning(f"Failed to check Lambda function status: {str(e)}")
        
        # Calculate overall cleanup success
        cleanup_success_count = sum(1 for result in validation_results.values() if isinstance(result, bool) and result)
        total_checks = len([k for k, v in validation_results.items() if isinstance(v, bool)])
        
        validation_results['cleanup_success_rate'] = f"{cleanup_success_count}/{total_checks}"
        validation_results['overall_status'] = 'success' if cleanup_success_count == total_checks else 'partial'
        
        return {
            'operation': 'validate_cleanup_completion',
            'status': 'success',
            'validation_results': validation_results
        }
        
    except Exception as e:
        logger.error(f"Failed to validate cleanup completion: {str(e)}")
        return {
            'operation': 'validate_cleanup_completion',
            'status': 'failed',
            'error': str(e)
        }


def cleanup_specific_cloudwatch_resources() -> Dict[str, Any]:
    """
    Clean up specific CloudWatch alarms and dashboards.
    """
    try:
        logger.info("Cleaning up specific CloudWatch resources")
        
        cloudwatch_client = get_aws_client('cloudwatch')
        resources_cleaned = 0
        
        # Clean up specific alarms
        if CLOUDWATCH_ALARM_NAMES:
            valid_alarm_names = [name for name in CLOUDWATCH_ALARM_NAMES if name.strip()]
            if valid_alarm_names:
                try:
                    cloudwatch_client.delete_alarms(AlarmNames=valid_alarm_names)
                    resources_cleaned += len(valid_alarm_names)
                    logger.info(f"Deleted {len(valid_alarm_names)} specific CloudWatch alarms")
                except Exception as e:
                    logger.warning(f"Failed to delete specific alarms: {str(e)}")
        
        # Clean up specific dashboard
        if CLOUDWATCH_DASHBOARD_NAME:
            try:
                cloudwatch_client.delete_dashboards(DashboardNames=[CLOUDWATCH_DASHBOARD_NAME])
                resources_cleaned += 1
                logger.info(f"Deleted CloudWatch dashboard: {CLOUDWATCH_DASHBOARD_NAME}")
            except Exception as e:
                logger.warning(f"Failed to delete dashboard {CLOUDWATCH_DASHBOARD_NAME}: {str(e)}")
        
        return {
            'operation': 'cleanup_specific_cloudwatch_resources',
            'status': 'success',
            'resources_cleaned': resources_cleaned
        }
        
    except Exception as e:
        logger.error(f"Failed to cleanup specific CloudWatch resources: {str(e)}")
        return {
            'operation': 'cleanup_specific_cloudwatch_resources',
            'status': 'failed',
            'error': str(e)
        }


def cleanup_resources_by_tags(cleanup_group_tag: str) -> Dict[str, Any]:
    """
    Clean up resources identified by cleanup tags.
    """
    try:
        logger.info(f"Cleaning up resources by tag: {cleanup_group_tag}")
        
        resources_cleaned = 0
        cleanup_details = []
        
        # Clean up tagged EC2 security groups
        try:
            ec2_client = get_aws_client('ec2')
            
            # Find security groups with the cleanup tag
            response = ec2_client.describe_security_groups(
                Filters=[
                    {
                        'Name': 'tag:CleanupGroup',
                        'Values': [cleanup_group_tag]
                    }
                ]
            )
            
            for sg in response['SecurityGroups']:
                try:
                    # Remove all rules first
                    if sg.get('IpPermissions'):
                        ec2_client.revoke_security_group_ingress(
                            GroupId=sg['GroupId'],
                            IpPermissions=sg['IpPermissions']
                        )
                        logger.info(f"Removed ingress rules from tagged security group {sg['GroupId']}")
                    
                    # Remove custom egress rules
                    if sg.get('IpPermissionsEgress'):
                        custom_egress_rules = [
                            rule for rule in sg['IpPermissionsEgress']
                            if not (rule.get('IpProtocol') == '-1' and 
                                   rule.get('IpRanges') == [{'CidrIp': '0.0.0.0/0'}] and
                                   rule.get('Ipv6Ranges') == [{'CidrIpv6': '::/0'}])
                        ]
                        
                        if custom_egress_rules:
                            ec2_client.revoke_security_group_egress(
                                GroupId=sg['GroupId'],
                                IpPermissions=custom_egress_rules
                            )
                            logger.info(f"Removed custom egress rules from tagged security group {sg['GroupId']}")
                    
                    resources_cleaned += 1
                    cleanup_details.append(f"Cleaned security group {sg['GroupId']}")
                    
                except Exception as e:
                    logger.warning(f"Failed to clean security group {sg['GroupId']}: {str(e)}")
                    
        except Exception as e:
            logger.warning(f"Failed to cleanup tagged security groups: {str(e)}")
        
        # Clean up tagged Lambda functions
        try:
            lambda_client = get_aws_client('lambda')
            
            # List all Lambda functions and check tags
            paginator = lambda_client.get_paginator('list_functions')
            
            for page in paginator.paginate():
                for function in page['Functions']:
                    try:
                        # Get function tags
                        tags_response = lambda_client.list_tags(Resource=function['FunctionArn'])
                        tags = tags_response.get('Tags', {})
                        
                        if tags.get('CleanupGroup') == cleanup_group_tag:
                            # Remove event source mappings
                            mappings_response = lambda_client.list_event_source_mappings(
                                FunctionName=function['FunctionName']
                            )
                            
                            for mapping in mappings_response['EventSourceMappings']:
                                try:
                                    lambda_client.delete_event_source_mapping(
                                        UUID=mapping['UUID']
                                    )
                                    logger.info(f"Removed event source mapping for {function['FunctionName']}")
                                except Exception as e:
                                    logger.warning(f"Failed to remove event source mapping: {str(e)}")
                            
                            resources_cleaned += 1
                            cleanup_details.append(f"Cleaned Lambda function {function['FunctionName']}")
                            
                    except Exception as e:
                        logger.warning(f"Failed to process Lambda function {function['FunctionName']}: {str(e)}")
                        
        except Exception as e:
            logger.warning(f"Failed to cleanup tagged Lambda functions: {str(e)}")
        
        # Clean up tagged CloudWatch resources
        try:
            cloudwatch_client = get_aws_client('cloudwatch')
            
            # Find and clean up alarms with the tag
            paginator = cloudwatch_client.get_paginator('describe_alarms')
            
            for page in paginator.paginate():
                for alarm in page['MetricAlarms']:
                    try:
                        # Get alarm tags
                        tags_response = cloudwatch_client.list_tags_for_resource(
                            ResourceARN=alarm['AlarmArn']
                        )
                        
                        tags = {tag['Key']: tag['Value'] for tag in tags_response.get('Tags', [])}
                        
                        if tags.get('CleanupGroup') == cleanup_group_tag:
                            cloudwatch_client.delete_alarms(AlarmNames=[alarm['AlarmName']])
                            resources_cleaned += 1
                            cleanup_details.append(f"Cleaned CloudWatch alarm {alarm['AlarmName']}")
                            logger.info(f"Deleted tagged CloudWatch alarm: {alarm['AlarmName']}")
                            
                    except Exception as e:
                        logger.warning(f"Failed to process alarm {alarm['AlarmName']}: {str(e)}")
                        
        except Exception as e:
            logger.warning(f"Failed to cleanup tagged CloudWatch alarms: {str(e)}")
        
        # Clean up tagged SNS topics
        try:
            sns_client = get_aws_client('sns')
            
            # List all SNS topics and check tags
            paginator = sns_client.get_paginator('list_topics')
            
            for page in paginator.paginate():
                for topic in page['Topics']:
                    try:
                        # Get topic tags
                        tags_response = sns_client.list_tags_for_resource(
                            ResourceArn=topic['TopicArn']
                        )
                        
                        tags = {tag['Key']: tag['Value'] for tag in tags_response.get('Tags', [])}
                        
                        if tags.get('CleanupGroup') == cleanup_group_tag:
                            # Clean up subscriptions first
                            subscriptions_response = sns_client.list_subscriptions_by_topic(
                                TopicArn=topic['TopicArn']
                            )
                            
                            for subscription in subscriptions_response['Subscriptions']:
                                if subscription['SubscriptionArn'] != 'PendingConfirmation':
                                    try:
                                        sns_client.unsubscribe(
                                            SubscriptionArn=subscription['SubscriptionArn']
                                        )
                                        logger.info(f"Unsubscribed from tagged SNS topic: {subscription['SubscriptionArn']}")
                                    except Exception as e:
                                        logger.warning(f"Failed to unsubscribe: {str(e)}")
                            
                            resources_cleaned += 1
                            cleanup_details.append(f"Cleaned SNS topic {topic['TopicArn']}")
                            
                    except Exception as e:
                        logger.warning(f"Failed to process SNS topic {topic['TopicArn']}: {str(e)}")
                        
        except Exception as e:
            logger.warning(f"Failed to cleanup tagged SNS topics: {str(e)}")
        
        # Clean up tagged CloudWatch log groups
        try:
            logs_client = get_aws_client('logs')
            
            # List log groups and check tags
            paginator = logs_client.get_paginator('describe_log_groups')
            
            for page in paginator.paginate():
                for log_group in page['logGroups']:
                    try:
                        # Get log group tags
                        tags_response = logs_client.list_tags_log_group(
                            logGroupName=log_group['logGroupName']
                        )
                        
                        tags = tags_response.get('tags', {})
                        
                        if tags.get('CleanupGroup') == cleanup_group_tag:
                            # Delete old log streams (keep recent ones)
                            cutoff_time = int((time.time() - (7 * 24 * 60 * 60)) * 1000)
                            
                            streams_response = logs_client.describe_log_streams(
                                logGroupName=log_group['logGroupName'],
                                orderBy='LastEventTime',
                                descending=False
                            )
                            
                            streams_deleted = 0
                            for stream in streams_response['logStreams']:
                                if stream.get('lastEventTime', 0) < cutoff_time:
                                    try:
                                        logs_client.delete_log_stream(
                                            logGroupName=log_group['logGroupName'],
                                            logStreamName=stream['logStreamName']
                                        )
                                        streams_deleted += 1
                                    except Exception as e:
                                        logger.warning(f"Failed to delete log stream: {str(e)}")
                            
                            if streams_deleted > 0:
                                resources_cleaned += 1
                                cleanup_details.append(f"Cleaned {streams_deleted} old log streams from {log_group['logGroupName']}")
                                logger.info(f"Deleted {streams_deleted} old log streams from tagged log group")
                            
                    except Exception as e:
                        logger.warning(f"Failed to process log group {log_group['logGroupName']}: {str(e)}")
                        
        except Exception as e:
            logger.warning(f"Failed to cleanup tagged log groups: {str(e)}")
        
        return {
            'operation': 'cleanup_resources_by_tags',
            'status': 'success',
            'cleanup_group_tag': cleanup_group_tag,
            'resources_cleaned': resources_cleaned,
            'cleanup_details': cleanup_details
        }
        
    except Exception as e:
        logger.error(f"Failed to cleanup resources by tags: {str(e)}")
        return {
            'operation': 'cleanup_resources_by_tags',
            'status': 'failed',
            'error': str(e)
        }Lambda functions with the cleanup tag
        try:
            lambda_client = get_aws_client('lambda')
            
            # List all Lambda functions and check for cleanup tags
            paginator = lambda_client.get_paginator('list_functions')
            for page in paginator.paginate():
                for function in page['Functions']:
                    function_name = function['FunctionName']
                    
                    # Check if function has cleanup tags
                    try:
                        tags_response = lambda_client.list_tags(Resource=function['FunctionArn'])
                        tags = tags_response.get('Tags', {})
                        
                        if tags.get('CleanupGroup') == cleanup_group_tag or cleanup_group_tag in function_name:
                            logger.info(f"Found Lambda function for cleanup: {function_name}")
                            
                            # Disable function by updating configuration
                            try:
                                lambda_client.update_function_configuration(
                                    FunctionName=function_name,
                                    Environment={'Variables': {'CLEANUP_DISABLED': 'true'}}
                                )
                                resources_cleaned += 1
                                cleanup_details.append(f"Disabled Lambda function: {function_name}")
                                logger.info(f"Disabled Lambda function: {function_name}")
                            except Exception as e:
                                logger.warning(f"Failed to disable Lambda function {function_name}: {str(e)}")
                                cleanup_details.append(f"Failed to disable Lambda function {function_name}: {str(e)}")
                    
                    except Exception as e:
                        logger.debug(f"Could not check tags for function {function_name}: {str(e)}")
                        
        except Exception as e:
            logger.warning(f"Failed to cleanup Lambda functions by tags: {str(e)}")
            cleanup_details.append(f"Lambda cleanup error: {str(e)}")
        
        # Clean up EventBridge rules with cleanup tags
        try:
            events_client = get_aws_client('events')
            
            # List EventBridge rules
            paginator = events_client.get_paginator('list_rules')
            for page in paginator.paginate():
                for rule in page['Rules']:
                    rule_name = rule['Name']
                    
                    if cleanup_group_tag in rule_name or 'cloudflare-ip' in rule_name:
                        logger.info(f"Found EventBridge rule for cleanup: {rule_name}")
                        
                        try:
                            # Disable the rule
                            events_client.disable_rule(Name=rule_name)
                            
                            # Remove targets
                            targets_response = events_client.list_targets_by_rule(Rule=rule_name)
                            if targets_response['Targets']:
                                target_ids = [target['Id'] for target in targets_response['Targets']]
                                events_client.remove_targets(Rule=rule_name, Ids=target_ids)
                                logger.info(f"Removed {len(target_ids)} targets from rule {rule_name}")
                            
                            resources_cleaned += 1
                            cleanup_details.append(f"Disabled EventBridge rule: {rule_name}")
                            logger.info(f"Disabled EventBridge rule: {rule_name}")
                            
                        except Exception as e:
                            logger.warning(f"Failed to cleanup EventBridge rule {rule_name}: {str(e)}")
                            cleanup_details.append(f"Failed to cleanup EventBridge rule {rule_name}: {str(e)}")
                            
        except Exception as e:
            logger.warning(f"Failed to cleanup EventBridge rules by tags: {str(e)}")
            cleanup_details.append(f"EventBridge cleanup error: {str(e)}")
        
        # Clean up CloudWatch log groups with cleanup tags
        try:
            logs_client = get_aws_client('logs')
            
            # List log groups with cloudflare-ip prefix
            paginator = logs_client.get_paginator('describe_log_groups')
            for page in paginator.paginate(logGroupNamePrefix='/aws/lambda/cloudflare-ip'):
                for log_group in page['logGroups']:
                    log_group_name = log_group['logGroupName']
                    
                    logger.info(f"Found log group for cleanup: {log_group_name}")
                    
                    try:
                        # Clean up old log streams (keep recent ones)
                        cutoff_time = int((time.time() - (24 * 60 * 60)) * 1000)  # 24 hours ago
                        
                        streams_response = logs_client.describe_log_streams(
                            logGroupName=log_group_name,
                            orderBy='LastEventTime',
                            descending=False
                        )
                        
                        streams_deleted = 0
                        for stream in streams_response['logStreams']:
                            if stream.get('lastEventTime', 0) < cutoff_time:
                                try:
                                    logs_client.delete_log_stream(
                                        logGroupName=log_group_name,
                                        logStreamName=stream['logStreamName']
                                    )
                                    streams_deleted += 1
                                except Exception as e:
                                    logger.debug(f"Failed to delete log stream {stream['logStreamName']}: {str(e)}")
                        
                        if streams_deleted > 0:
                            resources_cleaned += streams_deleted
                            cleanup_details.append(f"Deleted {streams_deleted} old log streams from {log_group_name}")
                            logger.info(f"Deleted {streams_deleted} old log streams from {log_group_name}")
                            
                    except Exception as e:
                        logger.warning(f"Failed to cleanup log streams in {log_group_name}: {str(e)}")
                        cleanup_details.append(f"Log streams cleanup error for {log_group_name}: {str(e)}")
                        
        except Exception as e:
            logger.warning(f"Failed to cleanup log groups by tags: {str(e)}")
            cleanup_details.append(f"Log groups cleanup error: {str(e)}")
        
        return {
            'operation': 'cleanup_resources_by_tags',
            'status': 'success',
            'cleanup_group_tag': cleanup_group_tag,
            'resources_cleaned': resources_cleaned,
            'cleanup_details': cleanup_details
        }
        
    except Exception as e:
        logger.error(f"Failed to cleanup resources by tags: {str(e)}")
        return {
            'operation': 'cleanup_resources_by_tags',
            'status': 'failed',
            'error': str(e)
        }


def perform_lambda_automation_cleanup(cleanup_results: Dict[str, Any]) -> Dict[str, Any]:
    """
    Perform comprehensive cleanup of Lambda automation components.
    """
    logger.info("Starting Lambda automation components cleanup")
    
    # Step 1: Disable all automation Lambda functions
    if MAIN_LAMBDA_FUNCTION:
        cleanup_results['operations'].append(
            disable_lambda_automation(MAIN_LAMBDA_FUNCTION)
        )
    
    # Step 2: Clean up Lambda event source mappings
    cleanup_results['operations'].append(
        cleanup_lambda_event_mappings()
    )
    
    # Step 3: Clean up Lambda function versions and aliases
    cleanup_results['operations'].append(
        cleanup_lambda_versions_and_aliases()
    )
    
    # Step 4: Clean up Lambda function environment variables containing sensitive data
    cleanup_results['operations'].append(
        cleanup_lambda_environment_variables()
    )
    
    # Step 5: Clean up Lambda function concurrency settings
    cleanup_results['operations'].append(
        cleanup_lambda_concurrency_settings()
    )
    
    logger.info("Lambda automation components cleanup completed")
    return cleanup_results


def disable_lambda_automation(function_name: str) -> Dict[str, Any]:
    """
    Disable Lambda automation by updating function configuration.
    """
    try:
        logger.info(f"Disabling Lambda automation: {function_name}")
        
        lambda_client = get_aws_client('lambda')
        
        # Check if function exists
        try:
            function_config = lambda_client.get_function(FunctionName=function_name)
        except ClientError as e:
            if e.response['Error']['Code'] == 'ResourceNotFoundException':
                logger.info(f"Lambda function {function_name} does not exist")
                return {
                    'operation': 'disable_lambda_automation',
                    'status': 'skipped',
                    'message': 'Function does not exist'
                }
            raise
        
        # Update function configuration to disable automation
        current_env = function_config['Configuration'].get('Environment', {}).get('Variables', {})
        updated_env = current_env.copy()
        updated_env['AUTOMATION_DISABLED'] = 'true'
        updated_env['CLEANUP_IN_PROGRESS'] = 'true'
        
        lambda_client.update_function_configuration(
            FunctionName=function_name,
            Environment={'Variables': updated_env}
        )
        
        logger.info(f"Disabled automation for Lambda function: {function_name}")
        
        return {
            'operation': 'disable_lambda_automation',
            'status': 'success',
            'function_name': function_name,
            'message': 'Automation disabled successfully'
        }
        
    except Exception as e:
        logger.error(f"Failed to disable Lambda automation: {str(e)}")
        return {
            'operation': 'disable_lambda_automation',
            'status': 'failed',
            'error': str(e)
        }


def cleanup_lambda_event_mappings() -> Dict[str, Any]:
    """
    Clean up Lambda event source mappings.
    """
    try:
        logger.info("Cleaning up Lambda event source mappings")
        
        lambda_client = get_aws_client('lambda')
        mappings_cleaned = 0
        
        # List all event source mappings
        paginator = lambda_client.get_paginator('list_event_source_mappings')
        for page in paginator.paginate():
            for mapping in page['EventSourceMappings']:
                function_name = mapping.get('FunctionArn', '').split(':')[-1]
                
                # Check if this is a Cloudflare IP updater function
                if 'cloudflare-ip' in function_name.lower() or ENVIRONMENT in function_name:
                    try:
                        lambda_client.delete_event_source_mapping(
                            UUID=mapping['UUID']
                        )
                        mappings_cleaned += 1
                        logger.info(f"Deleted event source mapping: {mapping['UUID']}")
                    except Exception as e:
                        logger.warning(f"Failed to delete event source mapping {mapping['UUID']}: {str(e)}")
        
        return {
            'operation': 'cleanup_lambda_event_mappings',
            'status': 'success',
            'mappings_cleaned': mappings_cleaned
        }
        
    except Exception as e:
        logger.error(f"Failed to cleanup Lambda event source mappings: {str(e)}")
        return {
            'operation': 'cleanup_lambda_event_mappings',
            'status': 'failed',
            'error': str(e)
        }


def cleanup_lambda_versions_and_aliases() -> Dict[str, Any]:
    """
    Clean up Lambda function versions and aliases.
    """
    try:
        logger.info("Cleaning up Lambda function versions and aliases")
        
        lambda_client = get_aws_client('lambda')
        versions_cleaned = 0
        aliases_cleaned = 0
        
        # Get list of functions to clean up
        functions_to_clean = []
        if MAIN_LAMBDA_FUNCTION:
            functions_to_clean.append(MAIN_LAMBDA_FUNCTION)
        
        # Add cleanup function if it exists
        cleanup_function_name = f"cloudflare-ip-cleanup-{ENVIRONMENT}"
        functions_to_clean.append(cleanup_function_name)
        
        for function_name in functions_to_clean:
            try:
                # Check if function exists
                lambda_client.get_function(FunctionName=function_name)
                
                # List and delete aliases
                try:
                    aliases_response = lambda_client.list_aliases(FunctionName=function_name)
                    for alias in aliases_response['Aliases']:
                        if alias['Name'] != '$LATEST':
                            try:
                                lambda_client.delete_alias(
                                    FunctionName=function_name,
                                    Name=alias['Name']
                                )
                                aliases_cleaned += 1
                                logger.info(f"Deleted alias {alias['Name']} for function {function_name}")
                            except Exception as e:
                                logger.warning(f"Failed to delete alias {alias['Name']}: {str(e)}")
                except Exception as e:
                    logger.debug(f"No aliases to clean for function {function_name}: {str(e)}")
                
                # List and delete old versions (keep $LATEST and most recent)
                try:
                    versions_response = lambda_client.list_versions_by_function(FunctionName=function_name)
                    versions_to_delete = []
                    
                    for version in versions_response['Versions']:
                        if version['Version'] != '$LATEST':
                            try:
                                version_num = int(version['Version'])
                                versions_to_delete.append(version_num)
                            except ValueError:
                                continue
                    
                    # Keep only the latest 2 versions
                    versions_to_delete.sort(reverse=True)
                    if len(versions_to_delete) > 2:
                        for version_num in versions_to_delete[2:]:
                            try:
                                lambda_client.delete_function(
                                    FunctionName=function_name,
                                    Qualifier=str(version_num)
                                )
                                versions_cleaned += 1
                                logger.info(f"Deleted version {version_num} for function {function_name}")
                            except Exception as e:
                                logger.warning(f"Failed to delete version {version_num}: {str(e)}")
                                
                except Exception as e:
                    logger.debug(f"No versions to clean for function {function_name}: {str(e)}")
                    
            except ClientError as e:
                if e.response['Error']['Code'] == 'ResourceNotFoundException':
                    logger.debug(f"Function {function_name} does not exist")
                else:
                    logger.warning(f"Error processing function {function_name}: {str(e)}")
        
        return {
            'operation': 'cleanup_lambda_versions_and_aliases',
            'status': 'success',
            'versions_cleaned': versions_cleaned,
            'aliases_cleaned': aliases_cleaned
        }
        
    except Exception as e:
        logger.error(f"Failed to cleanup Lambda versions and aliases: {str(e)}")
        return {
            'operation': 'cleanup_lambda_versions_and_aliases',
            'status': 'failed',
            'error': str(e)
        }


def cleanup_lambda_environment_variables() -> Dict[str, Any]:
    """
    Clean up sensitive environment variables from Lambda functions.
    """
    try:
        logger.info("Cleaning up Lambda environment variables")
        
        lambda_client = get_aws_client('lambda')
        functions_cleaned = 0
        
        # Get list of functions to clean up
        functions_to_clean = []
        if MAIN_LAMBDA_FUNCTION:
            functions_to_clean.append(MAIN_LAMBDA_FUNCTION)
        
        cleanup_function_name = f"cloudflare-ip-cleanup-{ENVIRONMENT}"
        functions_to_clean.append(cleanup_function_name)
        
        # Sensitive environment variable keys to remove
        sensitive_keys = [
            'TERRAFORM_CLOUD_TOKEN',
            'AWS_ACCESS_KEY_ID',
            'AWS_SECRET_ACCESS_KEY',
            'TERRAFORM_CONFIG_S3_BUCKET',
            'TERRAFORM_STATE_S3_BUCKET'
        ]
        
        for function_name in functions_to_clean:
            try:
                # Get current function configuration
                function_config = lambda_client.get_function(FunctionName=function_name)
                current_env = function_config['Configuration'].get('Environment', {}).get('Variables', {})
                
                # Remove sensitive variables
                cleaned_env = {}
                removed_keys = []
                
                for key, value in current_env.items():
                    if key in sensitive_keys:
                        removed_keys.append(key)
                    else:
                        cleaned_env[key] = value
                
                # Add cleanup markers
                cleaned_env['CLEANUP_COMPLETED'] = 'true'
                cleaned_env['SENSITIVE_DATA_REMOVED'] = 'true'
                
                if removed_keys:
                    # Update function configuration
                    lambda_client.update_function_configuration(
                        FunctionName=function_name,
                        Environment={'Variables': cleaned_env}
                    )
                    functions_cleaned += 1
                    logger.info(f"Cleaned environment variables for {function_name}: {removed_keys}")
                
            except ClientError as e:
                if e.response['Error']['Code'] == 'ResourceNotFoundException':
                    logger.debug(f"Function {function_name} does not exist")
                else:
                    logger.warning(f"Error cleaning environment variables for {function_name}: {str(e)}")
        
        return {
            'operation': 'cleanup_lambda_environment_variables',
            'status': 'success',
            'functions_cleaned': functions_cleaned
        }
        
    except Exception as e:
        logger.error(f"Failed to cleanup Lambda environment variables: {str(e)}")
        return {
            'operation': 'cleanup_lambda_environment_variables',
            'status': 'failed',
            'error': str(e)
        }


def cleanup_lambda_concurrency_settings() -> Dict[str, Any]:
    """
    Clean up Lambda function concurrency settings.
    """
    try:
        logger.info("Cleaning up Lambda concurrency settings")
        
        lambda_client = get_aws_client('lambda')
        concurrency_cleaned = 0
        
        # Get list of functions to clean up
        functions_to_clean = []
        if MAIN_LAMBDA_FUNCTION:
            functions_to_clean.append(MAIN_LAMBDA_FUNCTION)
        
        cleanup_function_name = f"cloudflare-ip-cleanup-{ENVIRONMENT}"
        functions_to_clean.append(cleanup_function_name)
        
        for function_name in functions_to_clean:
            try:
                # Check if function has reserved concurrency
                try:
                    concurrency_response = lambda_client.get_provisioned_concurrency_config(
                        FunctionName=function_name,
                        Qualifier='$LATEST'
                    )
                    
                    # Delete provisioned concurrency
                    lambda_client.delete_provisioned_concurrency_config(
                        FunctionName=function_name,
                        Qualifier='$LATEST'
                    )
                    concurrency_cleaned += 1
                    logger.info(f"Deleted provisioned concurrency for {function_name}")
                    
                except ClientError as e:
                    if e.response['Error']['Code'] not in ['ResourceNotFoundException', 'ProvisionedConcurrencyConfigNotFoundException']:
                        logger.warning(f"Error checking provisioned concurrency for {function_name}: {str(e)}")
                
                # Remove reserved concurrency
                try:
                    lambda_client.delete_reserved_concurrency_config(FunctionName=function_name)
                    concurrency_cleaned += 1
                    logger.info(f"Deleted reserved concurrency for {function_name}")
                except ClientError as e:
                    if e.response['Error']['Code'] not in ['ResourceNotFoundException', 'ResourceConflictException']:
                        logger.warning(f"Error removing reserved concurrency for {function_name}: {str(e)}")
                        
            except ClientError as e:
                if e.response['Error']['Code'] == 'ResourceNotFoundException':
                    logger.debug(f"Function {function_name} does not exist")
                else:
                    logger.warning(f"Error processing concurrency for {function_name}: {str(e)}")
        
        return {
            'operation': 'cleanup_lambda_concurrency_settings',
            'status': 'success',
            'concurrency_cleaned': concurrency_cleaned
        }
        
    except Exception as e:
        logger.error(f"Failed to cleanup Lambda concurrency settings: {str(e)}")
        return {
            'operation': 'cleanup_lambda_concurrency_settings',
            'status': 'failed',
            'error': str(e)
        }anup tag
        try:
            lambda_client = get_aws_client('lambda')
            
            # List all Lambda functions and check tags
            paginator = lambda_client.get_paginator('list_functions')
            for page in paginator.paginate():
                for function in page['Functions']:
                    try:
                        tags_response = lambda_client.list_tags(Resource=function['FunctionArn'])
                        if tags_response.get('Tags', {}).get('CleanupGroup') == cleanup_group_tag:
                            logger.info(f"Found Lambda function with cleanup tag: {function['FunctionName']}")
                            # Note: We don't actually delete the function here as Terraform will handle it
                            # This is just for identification and logging
                    except Exception as e:
                        logger.debug(f"Could not check tags for function {function['FunctionName']}: {str(e)}")
        except Exception as e:
            logger.warning(f"Failed to check Lambda functions by tags: {str(e)}")
        
        # Clean up security groups with the cleanup tag
        try:
            ec2_client = get_aws_client('ec2')
            
            # Find security groups with the cleanup tag
            response = ec2_client.describe_security_groups(
                Filters=[
                    {
                        'Name': 'tag:CleanupGroup',
                        'Values': [cleanup_group_tag]
                    }
                ]
            )
            
            for sg in response['SecurityGroups']:
                logger.info(f"Found security group with cleanup tag: {sg['GroupId']}")
                # Note: We don't delete the security group here as Terraform will handle it
                # This is just for identification and logging
                
        except Exception as e:
            logger.warning(f"Failed to check security groups by tags: {str(e)}")
        
        # Clean up CloudWatch log groups with the cleanup tag
        try:
            logs_client = get_aws_client('logs')
            
            # List log groups and check for cleanup tag pattern
            paginator = logs_client.get_paginator('describe_log_groups')
            for page in paginator.paginate():
                for log_group in page['logGroups']:
                    if 'cloudflare-ip' in log_group['logGroupName']:
                        logger.info(f"Found log group for cleanup: {log_group['logGroupName']}")
                        # Note: We don't delete the log group here as Terraform will handle it
                        
        except Exception as e:
            logger.warning(f"Failed to check log groups by tags: {str(e)}")
        
        return {
            'operation': 'cleanup_resources_by_tags',
            'status': 'success',
            'cleanup_group_tag': cleanup_group_tag,
            'note': 'Resources identified for cleanup - actual deletion handled by Terraform'
        }
        
    except Exception as e:
        logger.error(f"Failed to cleanup resources by tags: {str(e)}")
        return {
            'operation': 'cleanup_resources_by_tags',
            'status': 'failed',
            'error': str(e)
        }


def send_cleanup_notification(cleanup_results: Dict[str, Any]):
    """
    Send notification about cleanup operations.
    """
    try:
        logger.info("Sending cleanup notification")
        
        # Create notification message
        message_lines = [
            "=== CLOUDFLARE IP UPDATER CLEANUP REPORT ===",
            f"Environment: {cleanup_results['environment']}",
            f"Cleanup Mode: {cleanup_results['cleanup_mode']}",
            f"Timestamp: {cleanup_results['timestamp']}",
            "",
            "OPERATIONS PERFORMED:"
        ]
        
        for operation in cleanup_results['operations']:
            status_emoji = "✅" if operation['status'] == 'success' else "⚠️" if operation['status'] == 'skipped' else "❌"
            message_lines.append(f"  {status_emoji} {operation['operation']}: {operation['status']}")
            
            if operation['status'] == 'failed' and 'error' in operation:
                message_lines.append(f"    Error: {operation['error']}")
        
        message_lines.extend([
            "",
            "=== END CLEANUP REPORT ==="
        ])
        
        message = "\n".join(message_lines)
        
        # Send notification
        get_aws_client('sns').publish(
            TopicArn=SNS_TOPIC_ARN,
            Subject=f"🧹 Cloudflare IP Cleanup Report - {ENVIRONMENT}",
            Message=message
        )
        
        logger.info("Cleanup notification sent successfully")
        
    except Exception as e:
        logger.error(f"Failed to send cleanup notification: {str(e)}")
def send
_cleanup_notification(cleanup_results: Dict[str, Any]) -> None:
    """
    Send cleanup notification via SNS.
    """
    try:
        logger.info("Sending cleanup notification")
        
        sns_client = get_aws_client('sns')
        
        # Determine notification type based on results
        success_count = sum(1 for op in cleanup_results['operations'] if op.get('status') == 'success')
        failed_count = sum(1 for op in cleanup_results['operations'] if op.get('status') == 'failed')
        total_count = len(cleanup_results['operations'])
        
        if failed_count == 0:
            subject = f"✅ Cloudflare IP Cleanup Completed - {cleanup_results['environment']}"
            notification_type = "SUCCESS"
        elif success_count > 0:
            subject = f"⚠️ Cloudflare IP Cleanup Partially Completed - {cleanup_results['environment']}"
            notification_type = "PARTIAL"
        else:
            subject = f"❌ Cloudflare IP Cleanup Failed - {cleanup_results['environment']}"
            notification_type = "ERROR"
        
        # Build detailed message
        message_parts = [
            f"Cloudflare IP Updater Cleanup Report",
            f"Environment: {cleanup_results['environment']}",
            f"Cleanup Mode: {cleanup_results['cleanup_mode']}",
            f"Timestamp: {cleanup_results['timestamp']}",
            f"",
            f"Summary:",
            f"- Total Operations: {total_count}",
            f"- Successful: {success_count}",
            f"- Failed: {failed_count}",
            f"",
            f"Operation Details:"
        ]
        
        for operation in cleanup_results['operations']:
            status_icon = "✅" if operation.get('status') == 'success' else "❌" if operation.get('status') == 'failed' else "⏭️"
            message_parts.append(f"{status_icon} {operation.get('operation', 'Unknown')}: {operation.get('status', 'unknown')}")
            
            if operation.get('error'):
                message_parts.append(f"   Error: {operation['error']}")
            elif operation.get('message'):
                message_parts.append(f"   {operation['message']}")
            
            # Add specific details for certain operations
            if operation.get('operation') == 'cleanup_security_group_rules' and operation.get('rules_removed'):
                message_parts.append(f"   Rules removed: {operation['rules_removed']}")
            elif operation.get('operation') == 'cleanup_additional_security_groups' and operation.get('groups_cleaned'):
                message_parts.append(f"   Groups cleaned: {operation['groups_cleaned']}")
            elif operation.get('operation') == 'cleanup_cloudwatch_resources' and operation.get('resources_cleaned'):
                message_parts.append(f"   Resources cleaned: {operation['resources_cleaned']}")
            elif operation.get('operation') == 'cleanup_resources_by_tags' and operation.get('cleanup_details'):
                message_parts.append(f"   Details: {', '.join(operation['cleanup_details'][:3])}")
                if len(operation['cleanup_details']) > 3:
                    message_parts.append(f"   ... and {len(operation['cleanup_details']) - 3} more")
        
        message = "\n".join(message_parts)
        
        # Send notification
        sns_client.publish(
            TopicArn=SNS_TOPIC_ARN,
            Subject=subject,
            Message=message
        )
        
        # Send custom CloudWatch metric
        try:
            cloudwatch_client = get_aws_client('cloudwatch')
            cloudwatch_client.put_metric_data(
                Namespace='CloudflareIPUpdater',
                MetricData=[
                    {
                        'MetricName': 'CleanupNotificationsSent',
                        'Value': 1,
                        'Unit': 'Count',
                        'Dimensions': [
                            {
                                'Name': 'NotificationType',
                                'Value': notification_type
                            },
                            {
                                'Name': 'Environment',
                                'Value': cleanup_results['environment']
                            }
                        ]
                    }
                ]
            )
        except Exception as metric_error:
            logger.warning(f"Failed to send CloudWatch metric: {str(metric_error)}")
        
        logger.info(f"Cleanup notification sent successfully: {notification_type}")
        
    except Exception as e:
        logger.error(f"Failed to send cleanup notification: {str(e)}")


def cleanup_enhanced_security_group(enhanced_sg_id: str) -> Dict[str, Any]:
    """
    Clean up enhanced security group if it exists.
    """
    try:
        logger.info(f"Cleaning up enhanced security group: {enhanced_sg_id}")
        
        if not enhanced_sg_id:
            return {
                'operation': 'cleanup_enhanced_security_group',
                'status': 'skipped',
                'message': 'Enhanced security group not configured'
            }
        
        ec2_client = get_aws_client('ec2')
        
        # Check if security group exists
        try:
            response = ec2_client.describe_security_groups(GroupIds=[enhanced_sg_id])
            security_group = response['SecurityGroups'][0]
        except ClientError as e:
            if e.response['Error']['Code'] == 'InvalidGroupId.NotFound':
                logger.info(f"Enhanced security group {enhanced_sg_id} does not exist")
                return {
                    'operation': 'cleanup_enhanced_security_group',
                    'status': 'skipped',
                    'message': 'Enhanced security group does not exist'
                }
            raise
        
        rules_removed = 0
        
        # Remove all ingress rules
        if security_group.get('IpPermissions'):
            try:
                ec2_client.revoke_security_group_ingress(
                    GroupId=enhanced_sg_id,
                    IpPermissions=security_group['IpPermissions']
                )
                rules_removed += len(security_group['IpPermissions'])
                logger.info(f"Removed {len(security_group['IpPermissions'])} ingress rules from enhanced security group")
            except ClientError as e:
                if e.response['Error']['Code'] != 'InvalidPermission.NotFound':
                    logger.warning(f"Failed to remove some ingress rules from enhanced SG: {str(e)}")
        
        # Remove custom egress rules (keep default)
        if security_group.get('IpPermissionsEgress'):
            custom_egress_rules = [
                rule for rule in security_group['IpPermissionsEgress']
                if not (rule.get('IpProtocol') == '-1' and 
                       rule.get('IpRanges') == [{'CidrIp': '0.0.0.0/0'}] and
                       rule.get('Ipv6Ranges') == [{'CidrIpv6': '::/0'}])
            ]
            
            if custom_egress_rules:
                try:
                    ec2_client.revoke_security_group_egress(
                        GroupId=enhanced_sg_id,
                        IpPermissions=custom_egress_rules
                    )
                    rules_removed += len(custom_egress_rules)
                    logger.info(f"Removed {len(custom_egress_rules)} custom egress rules from enhanced security group")
                except ClientError as e:
                    if e.response['Error']['Code'] != 'InvalidPermission.NotFound':
                        logger.warning(f"Failed to remove some egress rules from enhanced SG: {str(e)}")
        
        return {
            'operation': 'cleanup_enhanced_security_group',
            'status': 'success',
            'security_group_id': enhanced_sg_id,
            'rules_removed': rules_removed
        }
        
    except Exception as e:
        logger.error(f"Failed to cleanup enhanced security group: {str(e)}")
        return {
            'operation': 'cleanup_enhanced_security_group',
            'status': 'failed',
            'error': str(e)
        }


def cleanup_iam_resources() -> Dict[str, Any]:
    """
    Clean up IAM resources by removing policies and detaching roles.
    """
    try:
        logger.info("Cleaning up IAM resources")
        
        iam_client = boto3.client('iam')
        resources_cleaned = 0
        
        # Clean up main IAM role policies
        if MAIN_IAM_ROLE_NAME:
            try:
                # List and delete inline policies
                policies_response = iam_client.list_role_policies(RoleName=MAIN_IAM_ROLE_NAME)
                
                for policy_name in policies_response['PolicyNames']:
                    try:
                        iam_client.delete_role_policy(
                            RoleName=MAIN_IAM_ROLE_NAME,
                            PolicyName=policy_name
                        )
                        resources_cleaned += 1
                        logger.info(f"Deleted inline policy {policy_name} from role {MAIN_IAM_ROLE_NAME}")
                    except Exception as e:
                        logger.warning(f"Failed to delete policy {policy_name}: {str(e)}")
                
                # List and detach managed policies
                attached_policies_response = iam_client.list_attached_role_policies(RoleName=MAIN_IAM_ROLE_NAME)
                
                for policy in attached_policies_response['AttachedPolicies']:
                    try:
                        iam_client.detach_role_policy(
                            RoleName=MAIN_IAM_ROLE_NAME,
                            PolicyArn=policy['PolicyArn']
                        )
                        resources_cleaned += 1
                        logger.info(f"Detached managed policy {policy['PolicyName']} from role {MAIN_IAM_ROLE_NAME}")
                    except Exception as e:
                        logger.warning(f"Failed to detach policy {policy['PolicyName']}: {str(e)}")
                        
            except ClientError as e:
                if e.response['Error']['Code'] != 'NoSuchEntity':
                    logger.warning(f"Failed to process IAM role {MAIN_IAM_ROLE_NAME}: {str(e)}")
        
        return {
            'operation': 'cleanup_iam_resources',
            'status': 'success',
            'resources_cleaned': resources_cleaned
        }
        
    except Exception as e:
        logger.error(f"Failed to cleanup IAM resources: {str(e)}")
        return {
            'operation': 'cleanup_iam_resources',
            'status': 'failed',
            'error': str(e)
        }


# Add enhanced cleanup for terraform destroy that includes all new resources
def perform_enhanced_terraform_destroy_cleanup(cleanup_results: Dict[str, Any]) -> Dict[str, Any]:
    """
    Perform enhanced cleanup operations specifically for terraform destroy with all resources.
    """
    logger.info("Starting enhanced Terraform destroy cleanup operations")
    
    # All the existing cleanup operations
    cleanup_results = perform_terraform_destroy_cleanup(cleanup_results)
    
    # Additional cleanup for enhanced resources
    enhanced_sg_id = os.environ.get('ENHANCED_SECURITY_GROUP_ID', '')
    if enhanced_sg_id:
        cleanup_results['operations'].append(
            cleanup_enhanced_security_group(enhanced_sg_id)
        )
    
    # Clean up IAM resources
    cleanup_results['operations'].append(
        cleanup_iam_resources()
    )
    
    logger.info("Enhanced Terraform destroy cleanup operations completed")
    return cleanup_results


if __name__ == "__main__":
    # For local testing
    test_event = {
        "source": "terraform.destroy",
        "cleanup_type": "terraform_destroy",
        "environment": "test"
    }
    
    class MockContext:
        def __init__(self):
            self.function_name = "test-cleanup-function"
            self.function_version = "1"
            self.invoked_function_arn = "arn:aws:lambda:us-east-1:123456789012:function:test-cleanup-function"
            self.memory_limit_in_mb = "256"
            self.remaining_time_in_millis = lambda: 300000
    
    result = lambda_handler(test_event, MockContext())
    print(json.dumps(result, indent=2))