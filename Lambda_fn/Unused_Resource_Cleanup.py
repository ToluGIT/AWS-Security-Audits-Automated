import boto3
import json
import logging
from datetime import datetime, timedelta

logger = logging.getLogger()
logger.setLevel(logging.INFO)

ec2 = boto3.client('ec2')
s3 = boto3.client('s3')

def lambda_handler(event, context):
    """
    Lambda function to identify and remove unused AWS resources:
    1. Unused security groups
    2. Unused key pairs
    3. Unattached EBS volumes (older than 30 days)
    4. Unused Elastic IPs
    5. Unused network interfaces
    """
    
    cleanup_actions = []
    
    try:
        # Clean up unused security groups
        cleanup_unused_security_groups(cleanup_actions)
        
        # Clean up unused key pairs
        cleanup_unused_key_pairs(cleanup_actions)
        
        # Clean up unattached EBS volumes
        cleanup_unattached_ebs_volumes(cleanup_actions)
        
        # Clean up unused Elastic IPs
        cleanup_unused_elastic_ips(cleanup_actions)
        
        # Clean up unused network interfaces
        cleanup_unused_network_interfaces(cleanup_actions)
        
        # Generate cleanup report
        generate_cleanup_report(cleanup_actions)
        
        return {
            'statusCode': 200,
            'body': json.dumps({
                'message': 'Resource cleanup completed',
                'actions_taken': len(cleanup_actions),
                'details': cleanup_actions
            })
        }
        
    except Exception as e:
        logger.error(f"Error during resource cleanup: {str(e)}")
        return {
            'statusCode': 500,
            'body': json.dumps({'error': str(e)})
        }

def cleanup_unused_security_groups(cleanup_actions):
    """Identify and remove unused security groups."""
    
    try:
        logger.info("Starting security group cleanup...")
        
        # Get all security groups
        paginator = ec2.get_paginator('describe_security_groups')
        all_sgs = []
        for page in paginator.paginate():
            all_sgs.extend(page['SecurityGroups'])
        
        # Get security groups in use
        used_sgs = set()
        
        # Check EC2 instances
        instances_paginator = ec2.get_paginator('describe_instances')
        for page in instances_paginator.paginate():
            for reservation in page['Reservations']:
                for instance in reservation['Instances']:
                    if instance['State']['Name'] != 'terminated':
                        for sg in instance.get('SecurityGroups', []):
                            used_sgs.add(sg['GroupId'])
        
        # Check RDS instances
        try:
            rds = boto3.client('rds')
            rds_paginator = rds.get_paginator('describe_db_instances')
            for page in rds_paginator.paginate():
                for instance in page['DBInstances']:
                    for sg in instance.get('VpcSecurityGroups', []):
                        used_sgs.add(sg['VpcSecurityGroupId'])
        except Exception as e:
            logger.warning(f"Could not check RDS security groups: {str(e)}")
        
        # Check load balancers
        try:
            elb = boto3.client('elbv2')
            elb_paginator = elb.get_paginator('describe_load_balancers')
            for page in elb_paginator.paginate():
                for lb in page['LoadBalancers']:
                    for sg_id in lb.get('SecurityGroups', []):
                        used_sgs.add(sg_id)
        except Exception as e:
            logger.warning(f"Could not check load balancer security groups: {str(e)}")
        
        # Check network interfaces
        try:
            eni_paginator = ec2.get_paginator('describe_network_interfaces')
            for page in eni_paginator.paginate():
                for eni in page['NetworkInterfaces']:
                    for sg in eni.get('Groups', []):
                        used_sgs.add(sg['GroupId'])
        except Exception as e:
            logger.warning(f"Could not check network interface security groups: {str(e)}")
        
        # Check for security groups referenced by other security groups
        referenced_sgs = set()
        for sg in all_sgs:
            for rule in sg['IpPermissions'] + sg['IpPermissionsEgress']:
                for group_pair in rule.get('UserIdGroupPairs', []):
                    referenced_sgs.add(group_pair['GroupId'])
        
        used_sgs.update(referenced_sgs)
        
        # Find unused security groups
        for sg in all_sgs:
            sg_id = sg['GroupId']
            sg_name = sg['GroupName']
            
            # Skip default security groups
            if sg_name == 'default':
                continue
            
            if sg_id not in used_sgs:
                logger.info(f"Found unused security group: {sg_name} ({sg_id})")
                
                try:
                    # Delete the unused security group
                    ec2.delete_security_group(GroupId=sg_id)
                    
                    cleanup_actions.append({
                        'action': 'deleted_unused_security_group',
                        'resource_id': sg_id,
                        'resource_name': sg_name,
                        'timestamp': datetime.utcnow().isoformat()
                    })
                    
                    logger.info(f"Successfully deleted security group: {sg_name}")
                    
                except Exception as e:
                    logger.error(f"Failed to delete security group {sg_name}: {str(e)}")
        
    except Exception as e:
        logger.error(f"Error during security group cleanup: {str(e)}")

def cleanup_unused_key_pairs(cleanup_actions):
    """Identify and remove unused key pairs."""
    
    try:
        logger.info("Starting key pair cleanup...")
        
        # Get all key pairs
        response = ec2.describe_key_pairs()
        all_key_pairs = response['KeyPairs']
        
        # Get key pairs in use by running instances
        used_key_pairs = set()
        
        paginator = ec2.get_paginator('describe_instances')
        for page in paginator.paginate():
            for reservation in page['Reservations']:
                for instance in reservation['Instances']:
                    if instance['State']['Name'] != 'terminated':
                        key_name = instance.get('KeyName')
                        if key_name:
                            used_key_pairs.add(key_name)
        
        # Find unused key pairs
        for key_pair in all_key_pairs:
            key_name = key_pair['KeyName']
            
            if key_name not in used_key_pairs:
                logger.info(f"Found unused key pair: {key_name}")
                
                try:
                    # Delete the unused key pair
                    ec2.delete_key_pair(KeyName=key_name)
                    
                    cleanup_actions.append({
                        'action': 'deleted_unused_key_pair',
                        'resource_id': key_name,
                        'resource_name': key_name,
                        'timestamp': datetime.utcnow().isoformat()
                    })
                    
                    logger.info(f"Successfully deleted key pair: {key_name}")
                    
                except Exception as e:
                    logger.error(f"Failed to delete key pair {key_name}: {str(e)}")
        
    except Exception as e:
        logger.error(f"Error during key pair cleanup: {str(e)}")

def cleanup_unattached_ebs_volumes(cleanup_actions):
    """Identify and remove unattached EBS volumes older than 30 days."""
    
    try:
        logger.info("Starting EBS volume cleanup...")
        
        # Get all volumes
        paginator = ec2.get_paginator('describe_volumes')
        cutoff_date = datetime.utcnow() - timedelta(days=30)
        
        for page in paginator.paginate():
            for volume in page['Volumes']:
                volume_id = volume['VolumeId']
                volume_state = volume['State']
                create_time = volume['CreateTime'].replace(tzinfo=None)
                
                # Check if volume is unattached and older than 30 days
                if (volume_state == 'available' and 
                    create_time < cutoff_date):
                    
                    logger.info(f"Found old unattached volume: {volume_id} (created: {create_time})")
                    
                    try:
                        # Create a snapshot before deletion for safety
                        snapshot_response = ec2.create_snapshot(
                            VolumeId=volume_id,
                            Description=f"Backup snapshot before cleanup deletion - {datetime.utcnow().isoformat()}"
                        )
                        snapshot_id = snapshot_response['SnapshotId']
                        
                        # Wait a moment for snapshot to initialize
                        logger.info(f"Created backup snapshot {snapshot_id} for volume {volume_id}")
                        
                        # Delete the volume
                        ec2.delete_volume(VolumeId=volume_id)
                        
                        cleanup_actions.append({
                            'action': 'deleted_unattached_volume',
                            'resource_id': volume_id,
                            'backup_snapshot_id': snapshot_id,
                            'volume_size': volume.get('Size', 0),
                            'created_date': create_time.isoformat(),
                            'timestamp': datetime.utcnow().isoformat()
                        })
                        
                        logger.info(f"Successfully deleted volume: {volume_id}")
                        
                    except Exception as e:
                        logger.error(f"Failed to delete volume {volume_id}: {str(e)}")
        
    except Exception as e:
        logger.error(f"Error during EBS volume cleanup: {str(e)}")

def cleanup_unused_elastic_ips(cleanup_actions):
    """Identify and release unused Elastic IP addresses."""
    
    try:
        logger.info("Starting Elastic IP cleanup...")
        
        # Get all Elastic IPs
        response = ec2.describe_addresses()
        addresses = response['Addresses']
        
        for address in addresses:
            public_ip = address['PublicIp']
            allocation_id = address.get('AllocationId')
            
            # Check if the EIP is not associated with any instance or network interface
            if 'InstanceId' not in address and 'NetworkInterfaceId' not in address:
                logger.info(f"Found unused Elastic IP: {public_ip}")
                
                try:
                    # Release the unused Elastic IP
                    if allocation_id:
                        ec2.release_address(AllocationId=allocation_id)
                    else:
                        # Classic Elastic IP
                        ec2.release_address(PublicIp=public_ip)
                    
                    cleanup_actions.append({
                        'action': 'released_unused_elastic_ip',
                        'resource_id': allocation_id or public_ip,
                        'public_ip': public_ip,
                        'timestamp': datetime.utcnow().isoformat()
                    })
                    
                    logger.info(f"Successfully released Elastic IP: {public_ip}")
                    
                except Exception as e:
                    logger.error(f"Failed to release Elastic IP {public_ip}: {str(e)}")
        
    except Exception as e:
        logger.error(f"Error during Elastic IP cleanup: {str(e)}")

def cleanup_unused_network_interfaces(cleanup_actions):
    """Identify and remove unused network interfaces."""
    
    try:
        logger.info("Starting network interface cleanup...")
        
        # Get all network interfaces
        paginator = ec2.get_paginator('describe_network_interfaces')
        
        for page in paginator.paginate():
            for eni in page['NetworkInterfaces']:
                eni_id = eni['NetworkInterfaceId']
                eni_status = eni['Status']
                attachment = eni.get('Attachment')
                
                # Check if the ENI is available (not attached) and not managed by AWS services
                if (eni_status == 'available' and 
                    not attachment and 
                    not eni.get('Description', '').startswith('AWS') and
                    eni.get('RequesterManaged', False) == False):
                    
                    logger.info(f"Found unused network interface: {eni_id}")
                    
                    try:
                        # Delete the unused network interface
                        ec2.delete_network_interface(NetworkInterfaceId=eni_id)
                        
                        cleanup_actions.append({
                            'action': 'deleted_unused_network_interface',
                            'resource_id': eni_id,
                            'description': eni.get('Description', ''),
                            'timestamp': datetime.utcnow().isoformat()
                        })
                        
                        logger.info(f"Successfully deleted network interface: {eni_id}")
                        
                    except Exception as e:
                        logger.error(f"Failed to delete network interface {eni_id}: {str(e)}")
        
    except Exception as e:
        logger.error(f"Error during network interface cleanup: {str(e)}")

def generate_cleanup_report(actions):
    """Generate and upload resource cleanup report to S3."""
    
    try:
        timestamp = datetime.utcnow().strftime('%Y-%m-%d_%H-%M-%S')
        
        # Calculate cost savings (approximate)
        cost_savings = calculate_cost_savings(actions)
        
        report = {
            'scan_timestamp': timestamp,
            'total_actions': len(actions),
            'actions': actions,
            'estimated_monthly_savings': cost_savings,
            'summary': {
                'security_groups_deleted': len([a for a in actions if a['action'] == 'deleted_unused_security_group']),
                'key_pairs_deleted': len([a for a in actions if a['action'] == 'deleted_unused_key_pair']),
                'volumes_deleted': len([a for a in actions if a['action'] == 'deleted_unattached_volume']),
                'elastic_ips_released': len([a for a in actions if a['action'] == 'released_unused_elastic_ip']),
                'network_interfaces_deleted': len([a for a in actions if a['action'] == 'deleted_unused_network_interface'])
            }
        }
        
        bucket_name = 'resource-cleanup-reports-bucket'  # Configure this
        file_name = f'resource-cleanup-report-{timestamp}.json'
        
        s3.put_object(
            Bucket=bucket_name,
            Key=file_name,
            Body=json.dumps(report, indent=2),
            ContentType='application/json'
        )
        
        logger.info(f"Resource cleanup report uploaded to S3: {file_name}")
        
    except Exception as e:
        logger.error(f"Failed to generate cleanup report: {str(e)}")

def calculate_cost_savings(actions):
    """Calculate approximate monthly cost savings from cleanup actions."""
    
    savings = 0
    
    for action in actions:
        if action['action'] == 'deleted_unattached_volume':
            # EBS GP2 cost: ~$0.10 per GB per month
            volume_size = action.get('volume_size', 0)
            savings += volume_size * 0.10
        
        elif action['action'] == 'released_unused_elastic_ip':
            # Elastic IP cost when not attached: $3.65 per month
            savings += 3.65
    
    return round(savings, 2)