import boto3
import json
import logging
from datetime import datetime, timedelta

logger = logging.getLogger()
logger.setLevel(logging.INFO)

rds = boto3.client('rds')
ec2 = boto3.client('ec2')
s3 = boto3.client('s3')

def lambda_handler(event, context):
    """
    Lambda function to harden RDS security by:
    1. Enabling encryption at rest for unencrypted instances
    2. Ensuring automated backups and snapshots
    3. Reviewing and hardening security groups
    4. Enabling performance insights and monitoring
    """
    
    remediation_actions = []
    
    try:
        # Process RDS instances
        process_rds_instances(remediation_actions)
        
        # Process RDS clusters (Aurora)
        process_rds_clusters(remediation_actions)
        
        # Check and harden RDS security groups
        harden_rds_security_groups(remediation_actions)
        
        # Generate remediation report
        generate_rds_security_report(remediation_actions)
        
        return {
            'statusCode': 200,
            'body': json.dumps({
                'message': 'RDS security hardening completed',
                'actions_taken': len(remediation_actions),
                'details': remediation_actions
            })
        }
        
    except Exception as e:
        logger.error(f"Error during RDS security hardening: {str(e)}")
        return {
            'statusCode': 500,
            'body': json.dumps({'error': str(e)})
        }

def process_rds_instances(remediation_actions):
    """Process and harden individual RDS instances."""
    
    try:
        paginator = rds.get_paginator('describe_db_instances')
        
        for page in paginator.paginate():
            for instance in page['DBInstances']:
                db_instance_id = instance['DBInstanceIdentifier']
                logger.info(f"Processing RDS instance: {db_instance_id}")
                
                # Check encryption status
                if not instance.get('StorageEncrypted', False):
                    logger.warning(f"RDS instance {db_instance_id} is not encrypted")
                    
                    # Create encrypted copy (requires manual intervention for data migration)
                    create_encrypted_instance_copy(instance, remediation_actions)
                
                # Check automated backups
                if not instance.get('BackupRetentionPeriod', 0) > 0:
                    logger.warning(f"RDS instance {db_instance_id} has no automated backups")
                    
                    # Enable automated backups
                    enable_automated_backups(db_instance_id, remediation_actions)
                
                # Check deletion protection
                if not instance.get('DeletionProtection', False):
                    logger.warning(f"RDS instance {db_instance_id} has deletion protection disabled")
                    
                    # Enable deletion protection
                    enable_deletion_protection(db_instance_id, remediation_actions)
                
                # Check performance insights
                if not instance.get('PerformanceInsightsEnabled', False):
                    logger.info(f"Enabling performance insights for {db_instance_id}")
                    
                    # Enable performance insights
                    enable_performance_insights(db_instance_id, remediation_actions)
                
                # Check monitoring
                if not instance.get('MonitoringInterval', 0) > 0:
                    logger.info(f"Enabling enhanced monitoring for {db_instance_id}")
                    
                    # Enable enhanced monitoring
                    enable_enhanced_monitoring(db_instance_id, remediation_actions)
                
    except Exception as e:
        logger.error(f"Error processing RDS instances: {str(e)}")

def process_rds_clusters(remediation_actions):
    """Process and harden RDS clusters (Aurora)."""
    
    try:
        paginator = rds.get_paginator('describe_db_clusters')
        
        for page in paginator.paginate():
            for cluster in page['DBClusters']:
                cluster_id = cluster['DBClusterIdentifier']
                logger.info(f"Processing RDS cluster: {cluster_id}")
                
                # Check encryption status
                if not cluster.get('StorageEncrypted', False):
                    logger.warning(f"RDS cluster {cluster_id} is not encrypted")
                    
                    # Create encrypted cluster copy
                    create_encrypted_cluster_copy(cluster, remediation_actions)
                
                # Check automated backups
                if not cluster.get('BackupRetentionPeriod', 0) > 0:
                    logger.warning(f"RDS cluster {cluster_id} has no automated backups")
                    
                    # Enable automated backups for cluster
                    enable_cluster_automated_backups(cluster_id, remediation_actions)
                
                # Check deletion protection
                if not cluster.get('DeletionProtection', False):
                    logger.warning(f"RDS cluster {cluster_id} has deletion protection disabled")
                    
                    # Enable deletion protection for cluster
                    enable_cluster_deletion_protection(cluster_id, remediation_actions)
                
    except Exception as e:
        logger.error(f"Error processing RDS clusters: {str(e)}")

def create_encrypted_instance_copy(instance, remediation_actions):
    """Create an encrypted copy of an unencrypted RDS instance."""
    
    try:
        db_instance_id = instance['DBInstanceIdentifier']
        
        # Create a snapshot first
        snapshot_id = f"{db_instance_id}-encryption-snapshot-{datetime.utcnow().strftime('%Y%m%d%H%M%S')}"
        
        rds.create_db_snapshot(
            DBSnapshotIdentifier=snapshot_id,
            DBInstanceIdentifier=db_instance_id
        )
        
        logger.info(f"Created snapshot {snapshot_id} for encryption")
        
        # Note: Creating encrypted instance from snapshot requires manual intervention
        # as it involves downtime and data migration
        remediation_actions.append({
            'action': 'encryption_snapshot_created',
            'db_instance_id': db_instance_id,
            'snapshot_id': snapshot_id,
            'timestamp': datetime.utcnow().isoformat(),
            'next_steps': 'Manual intervention required to create encrypted instance from snapshot'
        })
        
    except Exception as e:
        logger.error(f"Error creating encrypted copy for {instance['DBInstanceIdentifier']}: {str(e)}")

def create_encrypted_cluster_copy(cluster, remediation_actions):
    """Create an encrypted copy of an unencrypted RDS cluster."""
    
    try:
        cluster_id = cluster['DBClusterIdentifier']
        
        # Create a cluster snapshot first
        snapshot_id = f"{cluster_id}-encryption-snapshot-{datetime.utcnow().strftime('%Y%m%d%H%M%S')}"
        
        rds.create_db_cluster_snapshot(
            DBClusterSnapshotIdentifier=snapshot_id,
            DBClusterIdentifier=cluster_id
        )
        
        logger.info(f"Created cluster snapshot {snapshot_id} for encryption")
        
        remediation_actions.append({
            'action': 'cluster_encryption_snapshot_created',
            'db_cluster_id': cluster_id,
            'snapshot_id': snapshot_id,
            'timestamp': datetime.utcnow().isoformat(),
            'next_steps': 'Manual intervention required to create encrypted cluster from snapshot'
        })
        
    except Exception as e:
        logger.error(f"Error creating encrypted copy for cluster {cluster['DBClusterIdentifier']}: {str(e)}")

def enable_automated_backups(db_instance_id, remediation_actions):
    """Enable automated backups for RDS instance."""
    
    try:
        rds.modify_db_instance(
            DBInstanceIdentifier=db_instance_id,
            BackupRetentionPeriod=7,  # 7 days retention
            PreferredBackupWindow='03:00-04:00',  # 3-4 AM UTC
            ApplyImmediately=False  # Apply during maintenance window
        )
        
        remediation_actions.append({
            'action': 'enabled_automated_backups',
            'db_instance_id': db_instance_id,
            'backup_retention_period': 7,
            'timestamp': datetime.utcnow().isoformat()
        })
        
        logger.info(f"Enabled automated backups for {db_instance_id}")
        
    except Exception as e:
        logger.error(f"Error enabling automated backups for {db_instance_id}: {str(e)}")

def enable_cluster_automated_backups(cluster_id, remediation_actions):
    """Enable automated backups for RDS cluster."""
    
    try:
        rds.modify_db_cluster(
            DBClusterIdentifier=cluster_id,
            BackupRetentionPeriod=7,  # 7 days retention
            PreferredBackupWindow='03:00-04:00',  # 3-4 AM UTC
            ApplyImmediately=False  # Apply during maintenance window
        )
        
        remediation_actions.append({
            'action': 'enabled_cluster_automated_backups',
            'db_cluster_id': cluster_id,
            'backup_retention_period': 7,
            'timestamp': datetime.utcnow().isoformat()
        })
        
        logger.info(f"Enabled automated backups for cluster {cluster_id}")
        
    except Exception as e:
        logger.error(f"Error enabling automated backups for cluster {cluster_id}: {str(e)}")

def enable_deletion_protection(db_instance_id, remediation_actions):
    """Enable deletion protection for RDS instance."""
    
    try:
        rds.modify_db_instance(
            DBInstanceIdentifier=db_instance_id,
            DeletionProtection=True,
            ApplyImmediately=True
        )
        
        remediation_actions.append({
            'action': 'enabled_deletion_protection',
            'db_instance_id': db_instance_id,
            'timestamp': datetime.utcnow().isoformat()
        })
        
        logger.info(f"Enabled deletion protection for {db_instance_id}")
        
    except Exception as e:
        logger.error(f"Error enabling deletion protection for {db_instance_id}: {str(e)}")

def enable_cluster_deletion_protection(cluster_id, remediation_actions):
    """Enable deletion protection for RDS cluster."""
    
    try:
        rds.modify_db_cluster(
            DBClusterIdentifier=cluster_id,
            DeletionProtection=True,
            ApplyImmediately=True
        )
        
        remediation_actions.append({
            'action': 'enabled_cluster_deletion_protection',
            'db_cluster_id': cluster_id,
            'timestamp': datetime.utcnow().isoformat()
        })
        
        logger.info(f"Enabled deletion protection for cluster {cluster_id}")
        
    except Exception as e:
        logger.error(f"Error enabling deletion protection for cluster {cluster_id}: {str(e)}")

def enable_performance_insights(db_instance_id, remediation_actions):
    """Enable performance insights for RDS instance."""
    
    try:
        rds.modify_db_instance(
            DBInstanceIdentifier=db_instance_id,
            EnablePerformanceInsights=True,
            PerformanceInsightsRetentionPeriod=7,  # 7 days (free tier)
            ApplyImmediately=False
        )
        
        remediation_actions.append({
            'action': 'enabled_performance_insights',
            'db_instance_id': db_instance_id,
            'timestamp': datetime.utcnow().isoformat()
        })
        
        logger.info(f"Enabled performance insights for {db_instance_id}")
        
    except Exception as e:
        logger.error(f"Error enabling performance insights for {db_instance_id}: {str(e)}")

def enable_enhanced_monitoring(db_instance_id, remediation_actions):
    """Enable enhanced monitoring for RDS instance."""
    
    try:
        # First, we need to create or use an IAM role for enhanced monitoring
        monitoring_role_arn = create_monitoring_role()
        
        rds.modify_db_instance(
            DBInstanceIdentifier=db_instance_id,
            MonitoringInterval=60,  # 60 seconds
            MonitoringRoleArn=monitoring_role_arn,
            ApplyImmediately=False
        )
        
        remediation_actions.append({
            'action': 'enabled_enhanced_monitoring',
            'db_instance_id': db_instance_id,
            'monitoring_interval': 60,
            'timestamp': datetime.utcnow().isoformat()
        })
        
        logger.info(f"Enabled enhanced monitoring for {db_instance_id}")
        
    except Exception as e:
        logger.error(f"Error enabling enhanced monitoring for {db_instance_id}: {str(e)}")

def create_monitoring_role():
    """Create IAM role for RDS enhanced monitoring."""
    
    try:
        iam = boto3.client('iam')
        role_name = 'rds-monitoring-role'
        
        # Check if role already exists
        try:
            role = iam.get_role(RoleName=role_name)
            return role['Role']['Arn']
        except iam.exceptions.NoSuchEntityException:
            pass
        
        # Create the role
        trust_policy = {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Allow",
                    "Principal": {
                        "Service": "monitoring.rds.amazonaws.com"
                    },
                    "Action": "sts:AssumeRole"
                }
            ]
        }
        
        role = iam.create_role(
            RoleName=role_name,
            AssumeRolePolicyDocument=json.dumps(trust_policy),
            Path='/',
            Description='Role for RDS enhanced monitoring'
        )
        
        # Attach the AWS managed policy
        iam.attach_role_policy(
            RoleName=role_name,
            PolicyArn='arn:aws:iam::aws:policy/service-role/AmazonRDSEnhancedMonitoringRole'
        )
        
        return role['Role']['Arn']
        
    except Exception as e:
        logger.error(f"Error creating monitoring role: {str(e)}")
        return None

def harden_rds_security_groups(remediation_actions):
    """Check and harden security groups used by RDS instances."""
    
    try:
        # Get all RDS instances and their security groups
        rds_security_groups = set()
        
        paginator = rds.get_paginator('describe_db_instances')
        for page in paginator.paginate():
            for instance in page['DBInstances']:
                for sg in instance.get('VpcSecurityGroups', []):
                    rds_security_groups.add(sg['VpcSecurityGroupId'])
        
        # Check each security group
        for sg_id in rds_security_groups:
            logger.info(f"Checking RDS security group: {sg_id}")
            
            response = ec2.describe_security_groups(GroupIds=[sg_id])
            sg = response['SecurityGroups'][0]
            
            # Check for overly permissive rules
            for rule in sg['IpPermissions']:
                # Check for public access to database ports
                for ip_range in rule.get('IpRanges', []):
                    if ip_range.get('CidrIp') == '0.0.0.0/0':
                        # Check if it's a database port
                        from_port = rule.get('FromPort', 0)
                        to_port = rule.get('ToPort', 0)
                        
                        database_ports = [1433, 1521, 3306, 5432, 5984, 6379, 8529, 9042, 27017]
                        
                        if from_port in database_ports or to_port in database_ports:
                            logger.warning(f"Found public database access in SG {sg_id} on port {from_port}-{to_port}")
                            
                            # Remove the overly permissive rule
                            try:
                                ec2.revoke_security_group_ingress(
                                    GroupId=sg_id,
                                    IpPermissions=[rule]
                                )
                                
                                remediation_actions.append({
                                    'action': 'removed_public_database_access',
                                    'security_group_id': sg_id,
                                    'port_range': f"{from_port}-{to_port}",
                                    'timestamp': datetime.utcnow().isoformat()
                                })
                                
                                logger.info(f"Removed public access rule from SG {sg_id}")
                                
                            except Exception as e:
                                logger.error(f"Error removing rule from SG {sg_id}: {str(e)}")
        
    except Exception as e:
        logger.error(f"Error hardening RDS security groups: {str(e)}")

def generate_rds_security_report(actions):
    """Generate and upload RDS security remediation report to S3."""
    
    try:
        timestamp = datetime.utcnow().strftime('%Y-%m-%d_%H-%M-%S')
        report = {
            'scan_timestamp': timestamp,
            'total_actions': len(actions),
            'actions': actions,
            'summary': {
                'encryption_snapshots_created': len([a for a in actions if 'encryption_snapshot' in a['action']]),
                'automated_backups_enabled': len([a for a in actions if 'automated_backups' in a['action']]),
                'deletion_protection_enabled': len([a for a in actions if 'deletion_protection' in a['action']]),
                'performance_insights_enabled': len([a for a in actions if 'performance_insights' in a['action']]),
                'enhanced_monitoring_enabled': len([a for a in actions if 'enhanced_monitoring' in a['action']]),
                'security_groups_hardened': len([a for a in actions if 'public_database_access' in a['action']])
            }
        }
        
        bucket_name = 'rds-security-reports-bucket'  # Configure this
        file_name = f'rds-security-report-{timestamp}.json'
        
        s3.put_object(
            Bucket=bucket_name,
            Key=file_name,
            Body=json.dumps(report, indent=2),
            ContentType='application/json'
        )
        
        logger.info(f"RDS security report uploaded to S3: {file_name}")
        
    except Exception as e:
        logger.error(f"Failed to generate RDS security report: {str(e)}")