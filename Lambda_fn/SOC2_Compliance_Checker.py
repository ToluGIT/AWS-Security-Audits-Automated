import boto3
import json
import logging
from datetime import datetime, timedelta

logger = logging.getLogger()
logger.setLevel(logging.INFO)

def lambda_handler(event, context):
    """
    Lambda function to perform SOC 2 compliance checks across AWS environment.
    SOC 2 focuses on Security, Availability, Processing Integrity, Confidentiality, and Privacy.
    """
    
    compliance_findings = []
    
    try:
        # Security Controls (CC6)
        check_security_controls(compliance_findings)
        
        # System Operations (CC7)
        check_system_operations(compliance_findings)
        
        # Change Management (CC8)
        check_change_management(compliance_findings)
        
        # Risk Assessment (CC9)
        check_risk_assessment(compliance_findings)
        
        # Vendor and Business Partner Management (CC10)
        check_vendor_management(compliance_findings)
        
        # Availability (A1)
        check_availability_controls(compliance_findings)
        
        # Confidentiality (C1)
        check_confidentiality_controls(compliance_findings)
        
        # Generate compliance report
        generate_soc2_compliance_report(compliance_findings)
        
        return {
            'statusCode': 200,
            'body': json.dumps({
                'message': 'SOC 2 compliance check completed',
                'total_findings': len(compliance_findings),
                'non_compliant_items': len([f for f in compliance_findings if f['compliance_status'] == 'NON_COMPLIANT']),
                'details': compliance_findings
            })
        }
        
    except Exception as e:
        logger.error(f"Error during SOC 2 compliance check: {str(e)}")
        return {
            'statusCode': 500,
            'body': json.dumps({'error': str(e)})
        }

def check_security_controls(findings):
    """Check Security Controls (CC6) - Logical and Physical Access Controls."""
    
    logger.info("Checking Security Controls (CC6)...")
    
    # Check IAM password policy
    check_iam_password_policy(findings)
    
    # Check MFA enforcement
    check_mfa_enforcement(findings)
    
    # Check root account usage
    check_root_account_usage(findings)
    
    # Check security group configurations
    check_security_group_compliance(findings)
    
    # Check VPC configurations
    check_vpc_security_compliance(findings)

def check_iam_password_policy(findings):
    """Check IAM password policy compliance."""
    
    try:
        iam = boto3.client('iam')
        
        try:
            password_policy = iam.get_account_password_policy()['PasswordPolicy']
            
            # SOC 2 password requirements
            requirements = {
                'MinimumPasswordLength': 14,
                'RequireUppercaseCharacters': True,
                'RequireLowercaseCharacters': True,
                'RequireNumbers': True,
                'RequireSymbols': True,
                'MaxPasswordAge': 90,
                'PasswordReusePrevention': 12
            }
            
            non_compliant_items = []
            
            for req, expected in requirements.items():
                actual = password_policy.get(req)
                
                if req == 'MinimumPasswordLength':
                    if actual < expected:
                        non_compliant_items.append(f"Password length {actual} < required {expected}")
                elif req == 'MaxPasswordAge':
                    if actual > expected:
                        non_compliant_items.append(f"Max password age {actual} > recommended {expected}")
                elif req == 'PasswordReusePrevention':
                    if actual < expected:
                        non_compliant_items.append(f"Password reuse prevention {actual} < required {expected}")
                else:
                    if actual != expected:
                        non_compliant_items.append(f"{req}: {actual} != required {expected}")
            
            status = 'COMPLIANT' if not non_compliant_items else 'NON_COMPLIANT'
            
            findings.append({
                'control': 'CC6.1',
                'title': 'IAM Password Policy',
                'compliance_status': status,
                'details': non_compliant_items if non_compliant_items else ['Password policy meets SOC 2 requirements'],
                'timestamp': datetime.utcnow().isoformat()
            })
            
        except iam.exceptions.NoSuchEntityException:
            findings.append({
                'control': 'CC6.1',
                'title': 'IAM Password Policy',
                'compliance_status': 'NON_COMPLIANT',
                'details': ['No account password policy configured'],
                'timestamp': datetime.utcnow().isoformat()
            })
            
    except Exception as e:
        logger.error(f"Error checking password policy: {str(e)}")

def check_mfa_enforcement(findings):
    """Check MFA enforcement for privileged users."""
    
    try:
        iam = boto3.client('iam')
        
        # Get all users
        paginator = iam.get_paginator('list_users')
        non_mfa_users = []
        
        for page in paginator.paginate():
            for user in page['Users']:
                username = user['UserName']
                
                # Check if user has MFA device
                mfa_devices = iam.list_mfa_devices(UserName=username)['MFADevices']
                
                # Check if user has admin permissions
                has_admin_permissions = check_user_admin_permissions(iam, username)
                
                if has_admin_permissions and not mfa_devices:
                    non_mfa_users.append(username)
        
        status = 'COMPLIANT' if not non_mfa_users else 'NON_COMPLIANT'
        details = ['All privileged users have MFA enabled'] if not non_mfa_users else [f'Users without MFA: {", ".join(non_mfa_users)}']
        
        findings.append({
            'control': 'CC6.2',
            'title': 'MFA Enforcement for Privileged Users',
            'compliance_status': status,
            'details': details,
            'timestamp': datetime.utcnow().isoformat()
        })
        
    except Exception as e:
        logger.error(f"Error checking MFA enforcement: {str(e)}")

def check_user_admin_permissions(iam, username):
    """Check if user has administrative permissions."""
    
    try:
        # Check attached policies
        attached_policies = iam.list_attached_user_policies(UserName=username)['AttachedPolicies']
        
        for policy in attached_policies:
            if 'Admin' in policy['PolicyName'] or policy['PolicyArn'].endswith('AdministratorAccess'):
                return True
        
        # Check group memberships
        groups = iam.get_groups_for_user(UserName=username)['Groups']
        
        for group in groups:
            group_policies = iam.list_attached_group_policies(GroupName=group['GroupName'])['AttachedPolicies']
            for policy in group_policies:
                if 'Admin' in policy['PolicyName'] or policy['PolicyArn'].endswith('AdministratorAccess'):
                    return True
        
        return False
        
    except Exception:
        return False

def check_root_account_usage(findings):
    """Check root account usage compliance."""
    
    try:
        cloudtrail = boto3.client('cloudtrail')
        
        # Look for root account usage in the last 30 days
        end_time = datetime.utcnow()
        start_time = end_time - timedelta(days=30)
        
        events = cloudtrail.lookup_events(
            LookupAttributes=[
                {
                    'AttributeKey': 'Username',
                    'AttributeValue': 'root'
                }
            ],
            StartTime=start_time,
            EndTime=end_time
        )
        
        root_events = events.get('Events', [])
        
        # Filter out routine events
        significant_events = [
            event for event in root_events 
            if event['EventName'] not in ['ConsoleLogin', 'AssumeRole', 'GetSessionToken']
        ]
        
        status = 'COMPLIANT' if not significant_events else 'NON_COMPLIANT'
        details = ['No significant root account usage detected'] if not significant_events else [f'Root account used {len(significant_events)} times in last 30 days']
        
        findings.append({
            'control': 'CC6.3',
            'title': 'Root Account Usage Monitoring',
            'compliance_status': status,
            'details': details,
            'timestamp': datetime.utcnow().isoformat()
        })
        
    except Exception as e:
        logger.error(f"Error checking root account usage: {str(e)}")

def check_security_group_compliance(findings):
    """Check security group compliance with SOC 2."""
    
    try:
        ec2 = boto3.client('ec2')
        
        # Get all security groups
        paginator = ec2.get_paginator('describe_security_groups')
        non_compliant_sgs = []
        
        for page in paginator.paginate():
            for sg in page['SecurityGroups']:
                sg_id = sg['GroupId']
                
                # Check for overly permissive rules
                for rule in sg['IpPermissions']:
                    for ip_range in rule.get('IpRanges', []):
                        if ip_range.get('CidrIp') == '0.0.0.0/0':
                            # Allow HTTPS and HTTP from anywhere, but flag others
                            from_port = rule.get('FromPort', 0)
                            
                            if from_port not in [80, 443]:
                                non_compliant_sgs.append({
                                    'security_group_id': sg_id,
                                    'port': from_port,
                                    'issue': 'Public access to non-web ports'
                                })
        
        status = 'COMPLIANT' if not non_compliant_sgs else 'NON_COMPLIANT'
        details = ['Security groups follow least privilege principle'] if not non_compliant_sgs else [f'{len(non_compliant_sgs)} security groups with overly permissive rules']
        
        findings.append({
            'control': 'CC6.4',
            'title': 'Security Group Configuration',
            'compliance_status': status,
            'details': details,
            'non_compliant_items': non_compliant_sgs,
            'timestamp': datetime.utcnow().isoformat()
        })
        
    except Exception as e:
        logger.error(f"Error checking security groups: {str(e)}")

def check_vpc_security_compliance(findings):
    """Check VPC security compliance."""
    
    try:
        ec2 = boto3.client('ec2')
        
        # Check VPC flow logs
        vpcs = ec2.describe_vpcs()['Vpcs']
        vpcs_without_flow_logs = []
        
        flow_logs = ec2.describe_flow_logs()['FlowLogs']
        vpc_with_logs = set([fl['ResourceId'] for fl in flow_logs if fl['ResourceType'] == 'VPC'])
        
        for vpc in vpcs:
            if vpc['VpcId'] not in vpc_with_logs:
                vpcs_without_flow_logs.append(vpc['VpcId'])
        
        status = 'COMPLIANT' if not vpcs_without_flow_logs else 'NON_COMPLIANT'
        details = ['All VPCs have flow logs enabled'] if not vpcs_without_flow_logs else [f'VPCs without flow logs: {", ".join(vpcs_without_flow_logs)}']
        
        findings.append({
            'control': 'CC6.5',
            'title': 'VPC Flow Logs Configuration',
            'compliance_status': status,
            'details': details,
            'timestamp': datetime.utcnow().isoformat()
        })
        
    except Exception as e:
        logger.error(f"Error checking VPC compliance: {str(e)}")

def check_system_operations(findings):
    """Check System Operations (CC7) - System Monitoring."""
    
    logger.info("Checking System Operations (CC7)...")
    
    # Check CloudTrail configuration
    check_cloudtrail_compliance(findings)
    
    # Check CloudWatch monitoring
    check_cloudwatch_compliance(findings)
    
    # Check AWS Config compliance
    check_config_compliance(findings)

def check_cloudtrail_compliance(findings):
    """Check CloudTrail compliance for audit logging."""
    
    try:
        cloudtrail = boto3.client('cloudtrail')
        
        trails = cloudtrail.describe_trails()['trailList']
        
        compliant_issues = []
        
        if not trails:
            compliant_issues.append('No CloudTrail configured')
        else:
            for trail in trails:
                trail_name = trail['Name']
                
                # Check if trail is logging
                status = cloudtrail.get_trail_status(Name=trail_name)
                
                if not status['IsLogging']:
                    compliant_issues.append(f'Trail {trail_name} is not logging')
                
                # Check if trail includes global services
                if not trail.get('IncludeGlobalServiceEvents', False):
                    compliant_issues.append(f'Trail {trail_name} does not include global service events')
                
                # Check if trail is multi-region
                if not trail.get('IsMultiRegionTrail', False):
                    compliant_issues.append(f'Trail {trail_name} is not multi-region')
                
                # Check log file validation
                if not trail.get('LogFileValidationEnabled', False):
                    compliant_issues.append(f'Trail {trail_name} does not have log file validation enabled')
        
        status = 'COMPLIANT' if not compliant_issues else 'NON_COMPLIANT'
        details = ['CloudTrail properly configured for audit logging'] if not compliant_issues else compliant_issues
        
        findings.append({
            'control': 'CC7.1',
            'title': 'CloudTrail Audit Logging',
            'compliance_status': status,
            'details': details,
            'timestamp': datetime.utcnow().isoformat()
        })
        
    except Exception as e:
        logger.error(f"Error checking CloudTrail compliance: {str(e)}")

def check_cloudwatch_compliance(findings):
    """Check CloudWatch monitoring compliance."""
    
    try:
        cloudwatch = boto3.client('cloudwatch')
        logs = boto3.client('logs')
        
        # Check for security-related CloudWatch alarms
        alarms = cloudwatch.describe_alarms()['MetricAlarms']
        
        required_alarms = [
            'root-usage',
            'unauthorized-api-calls',
            'console-without-mfa',
            'iam-policy-changes',
            'cloudtrail-config-changes',
            'security-group-changes'
        ]
        
        existing_alarms = [alarm['AlarmName'].lower() for alarm in alarms]
        missing_alarms = [req for req in required_alarms if not any(req in existing for existing in existing_alarms)]
        
        # Check log retention
        log_groups = logs.describe_log_groups()['logGroups']
        short_retention_logs = []
        
        for log_group in log_groups:
            retention = log_group.get('retentionInDays', 0)
            if retention < 365:  # SOC 2 typically requires 1 year retention
                short_retention_logs.append(log_group['logGroupName'])
        
        issues = []
        if missing_alarms:
            issues.append(f'Missing security alarms: {", ".join(missing_alarms)}')
        if short_retention_logs:
            issues.append(f'Log groups with insufficient retention: {len(short_retention_logs)} groups')
        
        status = 'COMPLIANT' if not issues else 'NON_COMPLIANT'
        details = ['CloudWatch monitoring properly configured'] if not issues else issues
        
        findings.append({
            'control': 'CC7.2',
            'title': 'CloudWatch Monitoring and Alerting',
            'compliance_status': status,
            'details': details,
            'timestamp': datetime.utcnow().isoformat()
        })
        
    except Exception as e:
        logger.error(f"Error checking CloudWatch compliance: {str(e)}")

def check_config_compliance(findings):
    """Check AWS Config compliance."""
    
    try:
        config = boto3.client('config')
        
        try:
            config_recorders = config.describe_configuration_recorders()['ConfigurationRecorders']
            delivery_channels = config.describe_delivery_channels()['DeliveryChannels']
            
            issues = []
            
            if not config_recorders:
                issues.append('No AWS Config recorders configured')
            else:
                for recorder in config_recorders:
                    if not recorder.get('recordingGroup', {}).get('allSupported', False):
                        issues.append('Config recorder not recording all resources')
            
            if not delivery_channels:
                issues.append('No AWS Config delivery channels configured')
            
            status = 'COMPLIANT' if not issues else 'NON_COMPLIANT'
            details = ['AWS Config properly configured'] if not issues else issues
            
        except Exception:
            status = 'NON_COMPLIANT'
            details = ['AWS Config is not configured']
        
        findings.append({
            'control': 'CC7.3',
            'title': 'AWS Config Configuration Management',
            'compliance_status': status,
            'details': details,
            'timestamp': datetime.utcnow().isoformat()
        })
        
    except Exception as e:
        logger.error(f"Error checking Config compliance: {str(e)}")

def check_change_management(findings):
    """Check Change Management (CC8) controls."""
    
    logger.info("Checking Change Management (CC8)...")
    
    # This would typically integrate with change management systems
    # For now, we'll check for infrastructure as code usage
    
    findings.append({
        'control': 'CC8.1',
        'title': 'Infrastructure as Code Usage',
        'compliance_status': 'MANUAL_REVIEW',
        'details': ['Manual review required for change management processes'],
        'timestamp': datetime.utcnow().isoformat()
    })

def check_risk_assessment(findings):
    """Check Risk Assessment (CC9) controls."""
    
    logger.info("Checking Risk Assessment (CC9)...")
    
    # Check for GuardDuty (threat detection)
    check_guardduty_compliance(findings)

def check_guardduty_compliance(findings):
    """Check GuardDuty threat detection compliance."""
    
    try:
        guardduty = boto3.client('guardduty')
        
        try:
            detectors = guardduty.list_detectors()['DetectorIds']
            
            if not detectors:
                status = 'NON_COMPLIANT'
                details = ['GuardDuty not enabled']
            else:
                # Check if detectors are enabled
                enabled_detectors = []
                for detector_id in detectors:
                    detector = guardduty.get_detector(DetectorId=detector_id)
                    if detector['Status'] == 'ENABLED':
                        enabled_detectors.append(detector_id)
                
                status = 'COMPLIANT' if enabled_detectors else 'NON_COMPLIANT'
                details = [f'GuardDuty enabled with {len(enabled_detectors)} active detectors'] if enabled_detectors else ['GuardDuty detectors not enabled']
        
        except Exception:
            status = 'NON_COMPLIANT'
            details = ['GuardDuty not available or not configured']
        
        findings.append({
            'control': 'CC9.1',
            'title': 'Threat Detection with GuardDuty',
            'compliance_status': status,
            'details': details,
            'timestamp': datetime.utcnow().isoformat()
        })
        
    except Exception as e:
        logger.error(f"Error checking GuardDuty compliance: {str(e)}")

def check_vendor_management(findings):
    """Check Vendor and Business Partner Management (CC10)."""
    
    # This is typically a manual process
    findings.append({
        'control': 'CC10.1',
        'title': 'Third-party Risk Management',
        'compliance_status': 'MANUAL_REVIEW',
        'details': ['Manual review required for third-party services and vendor management'],
        'timestamp': datetime.utcnow().isoformat()
    })

def check_availability_controls(findings):
    """Check Availability (A1) controls."""
    
    logger.info("Checking Availability Controls (A1)...")
    
    # Check for backup configurations
    check_backup_compliance(findings)
    
    # Check for multi-AZ deployments
    check_multi_az_compliance(findings)

def check_backup_compliance(findings):
    """Check backup compliance for availability."""
    
    try:
        # Check EBS snapshot policies
        ec2 = boto3.client('ec2')
        
        volumes = ec2.describe_volumes()['Volumes']
        volumes_without_snapshots = []
        
        for volume in volumes:
            volume_id = volume['VolumeId']
            
            # Check for recent snapshots (within 7 days)
            snapshots = ec2.describe_snapshots(
                OwnerIds=['self'],
                Filters=[
                    {'Name': 'volume-id', 'Values': [volume_id]},
                    {'Name': 'start-time', 'Values': [(datetime.utcnow() - timedelta(days=7)).strftime('%Y-%m-%d')]}
                ]
            )['Snapshots']
            
            if not snapshots:
                volumes_without_snapshots.append(volume_id)
        
        status = 'COMPLIANT' if not volumes_without_snapshots else 'NON_COMPLIANT'
        details = ['All volumes have recent backups'] if not volumes_without_snapshots else [f'{len(volumes_without_snapshots)} volumes without recent snapshots']
        
        findings.append({
            'control': 'A1.1',
            'title': 'Backup and Recovery Procedures',
            'compliance_status': status,
            'details': details,
            'timestamp': datetime.utcnow().isoformat()
        })
        
    except Exception as e:
        logger.error(f"Error checking backup compliance: {str(e)}")

def check_multi_az_compliance(findings):
    """Check multi-AZ deployment compliance."""
    
    try:
        rds = boto3.client('rds')
        
        # Check RDS instances for multi-AZ
        db_instances = rds.describe_db_instances()['DBInstances']
        single_az_instances = []
        
        for instance in db_instances:
            if not instance.get('MultiAZ', False):
                single_az_instances.append(instance['DBInstanceIdentifier'])
        
        status = 'COMPLIANT' if not single_az_instances else 'NON_COMPLIANT'
        details = ['All RDS instances are multi-AZ'] if not single_az_instances else [f'Single-AZ RDS instances: {", ".join(single_az_instances)}']
        
        findings.append({
            'control': 'A1.2',
            'title': 'Multi-AZ Deployment for High Availability',
            'compliance_status': status,
            'details': details,
            'timestamp': datetime.utcnow().isoformat()
        })
        
    except Exception as e:
        logger.error(f"Error checking multi-AZ compliance: {str(e)}")

def check_confidentiality_controls(findings):
    """Check Confidentiality (C1) controls."""
    
    logger.info("Checking Confidentiality Controls (C1)...")
    
    # Check encryption at rest
    check_encryption_at_rest(findings)
    
    # Check encryption in transit
    check_encryption_in_transit(findings)

def check_encryption_at_rest(findings):
    """Check encryption at rest compliance."""
    
    try:
        ec2 = boto3.client('ec2')
        rds = boto3.client('rds')
        s3 = boto3.client('s3')
        
        unencrypted_resources = []
        
        # Check EBS volumes
        volumes = ec2.describe_volumes()['Volumes']
        for volume in volumes:
            if not volume.get('Encrypted', False):
                unencrypted_resources.append(f"EBS Volume: {volume['VolumeId']}")
        
        # Check RDS instances
        try:
            db_instances = rds.describe_db_instances()['DBInstances']
            for instance in db_instances:
                if not instance.get('StorageEncrypted', False):
                    unencrypted_resources.append(f"RDS Instance: {instance['DBInstanceIdentifier']}")
        except Exception:
            pass
        
        # Check S3 buckets (sample check)
        try:
            buckets = s3.list_buckets()['Buckets']
            for bucket in buckets[:5]:  # Check first 5 buckets as sample
                bucket_name = bucket['Name']
                try:
                    encryption = s3.get_bucket_encryption(Bucket=bucket_name)
                except Exception:
                    unencrypted_resources.append(f"S3 Bucket: {bucket_name}")
        except Exception:
            pass
        
        status = 'COMPLIANT' if not unencrypted_resources else 'NON_COMPLIANT'
        details = ['All checked resources are encrypted at rest'] if not unencrypted_resources else [f'Unencrypted resources found: {len(unencrypted_resources)}']
        
        findings.append({
            'control': 'C1.1',
            'title': 'Encryption at Rest',
            'compliance_status': status,
            'details': details,
            'unencrypted_resources': unencrypted_resources,
            'timestamp': datetime.utcnow().isoformat()
        })
        
    except Exception as e:
        logger.error(f"Error checking encryption at rest: {str(e)}")

def check_encryption_in_transit(findings):
    """Check encryption in transit compliance."""
    
    try:
        elbv2 = boto3.client('elbv2')
        
        # Check load balancers for HTTPS listeners
        load_balancers = elbv2.describe_load_balancers()['LoadBalancers']
        non_https_lbs = []
        
        for lb in load_balancers:
            lb_arn = lb['LoadBalancerArn']
            listeners = elbv2.describe_listeners(LoadBalancerArn=lb_arn)['Listeners']
            
            has_https = any(listener['Protocol'] == 'HTTPS' for listener in listeners)
            has_http_only = any(listener['Protocol'] == 'HTTP' for listener in listeners)
            
            if has_http_only and not has_https:
                non_https_lbs.append(lb['LoadBalancerName'])
        
        status = 'COMPLIANT' if not non_https_lbs else 'NON_COMPLIANT'
        details = ['All load balancers use HTTPS'] if not non_https_lbs else [f'Load balancers without HTTPS: {", ".join(non_https_lbs)}']
        
        findings.append({
            'control': 'C1.2',
            'title': 'Encryption in Transit',
            'compliance_status': status,
            'details': details,
            'timestamp': datetime.utcnow().isoformat()
        })
        
    except Exception as e:
        logger.error(f"Error checking encryption in transit: {str(e)}")

def generate_soc2_compliance_report(findings):
    """Generate and upload SOC 2 compliance report to S3."""
    
    try:
        s3 = boto3.client('s3')
        timestamp = datetime.utcnow().strftime('%Y-%m-%d_%H-%M-%S')
        
        # Calculate compliance summary
        total_findings = len(findings)
        compliant_count = len([f for f in findings if f['compliance_status'] == 'COMPLIANT'])
        non_compliant_count = len([f for f in findings if f['compliance_status'] == 'NON_COMPLIANT'])
        manual_review_count = len([f for f in findings if f['compliance_status'] == 'MANUAL_REVIEW'])
        
        compliance_percentage = (compliant_count / total_findings * 100) if total_findings > 0 else 0
        
        report = {
            'assessment_timestamp': timestamp,
            'compliance_summary': {
                'total_controls_checked': total_findings,
                'compliant_controls': compliant_count,
                'non_compliant_controls': non_compliant_count,
                'manual_review_required': manual_review_count,
                'compliance_percentage': round(compliance_percentage, 2)
            },
            'findings_by_category': {
                'security_controls': [f for f in findings if f['control'].startswith('CC6')],
                'system_operations': [f for f in findings if f['control'].startswith('CC7')],
                'change_management': [f for f in findings if f['control'].startswith('CC8')],
                'risk_assessment': [f for f in findings if f['control'].startswith('CC9')],
                'vendor_management': [f for f in findings if f['control'].startswith('CC10')],
                'availability': [f for f in findings if f['control'].startswith('A1')],
                'confidentiality': [f for f in findings if f['control'].startswith('C1')]
            },
            'all_findings': findings,
            'recommendations': generate_recommendations(findings)
        }
        
        bucket_name = 'soc2-compliance-reports-bucket'  # Configure this
        file_name = f'soc2-compliance-report-{timestamp}.json'
        
        s3.put_object(
            Bucket=bucket_name,
            Key=file_name,
            Body=json.dumps(report, indent=2),
            ContentType='application/json'
        )
        
        logger.info(f"SOC 2 compliance report uploaded to S3: {file_name}")
        
    except Exception as e:
        logger.error(f"Failed to generate SOC 2 compliance report: {str(e)}")

def generate_recommendations(findings):
    """Generate recommendations based on findings."""
    
    recommendations = []
    
    non_compliant_findings = [f for f in findings if f['compliance_status'] == 'NON_COMPLIANT']
    
    for finding in non_compliant_findings:
        control = finding['control']
        
        if control == 'CC6.1':
            recommendations.append("Implement a strong password policy meeting SOC 2 requirements")
        elif control == 'CC6.2':
            recommendations.append("Enforce MFA for all privileged users")
        elif control == 'CC6.3':
            recommendations.append("Implement root account monitoring and restrict root account usage")
        elif control == 'CC7.1':
            recommendations.append("Configure CloudTrail with proper logging, multi-region, and log file validation")
        elif control == 'CC7.2':
            recommendations.append("Implement CloudWatch security alarms and extend log retention to 1 year")
        elif control == 'A1.1':
            recommendations.append("Implement automated backup procedures for all critical resources")
        elif control == 'A1.2':
            recommendations.append("Deploy RDS instances in multi-AZ configuration for high availability")
        elif control == 'C1.1':
            recommendations.append("Enable encryption at rest for all data storage resources")
        elif control == 'C1.2':
            recommendations.append("Implement HTTPS/TLS for all data in transit")
    
    return recommendations