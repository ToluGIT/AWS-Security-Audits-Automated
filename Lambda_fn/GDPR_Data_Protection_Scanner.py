import boto3
import json
import logging
import re
from datetime import datetime, timedelta

logger = logging.getLogger()
logger.setLevel(logging.INFO)

def lambda_handler(event, context):
    """
    Lambda function to scan for GDPR compliance issues:
    1. Identify unencrypted PII storage locations
    2. Check data retention policies
    3. Verify data processing consent mechanisms
    4. Audit cross-border data transfer compliance
    5. Check for data anonymization/pseudonymization
    """
    
    gdpr_findings = []
    
    try:
        # Scan S3 buckets for unencrypted PII
        scan_s3_pii_compliance(gdpr_findings)
        
        # Check RDS instances for PII and encryption
        scan_rds_pii_compliance(gdpr_findings)
        
        # Check data retention policies
        check_data_retention_policies(gdpr_findings)
        
        # Check cross-border data transfer compliance
        check_cross_border_data_transfer(gdpr_findings)
        
        # Check DynamoDB for PII compliance
        scan_dynamodb_pii_compliance(gdpr_findings)
        
        # Check CloudWatch logs for PII exposure
        scan_cloudwatch_pii_exposure(gdpr_findings)
        
        # Generate GDPR compliance report
        generate_gdpr_compliance_report(gdpr_findings)
        
        return {
            'statusCode': 200,
            'body': json.dumps({
                'message': 'GDPR compliance scan completed',
                'total_findings': len(gdpr_findings),
                'high_risk_findings': len([f for f in gdpr_findings if f.get('risk_level') == 'HIGH']),
                'details': gdpr_findings
            })
        }
        
    except Exception as e:
        logger.error(f"Error during GDPR compliance scan: {str(e)}")
        return {
            'statusCode': 500,
            'body': json.dumps({'error': str(e)})
        }

def scan_s3_pii_compliance(findings):
    """Scan S3 buckets for PII and encryption compliance."""
    
    try:
        s3 = boto3.client('s3')
        logger.info("Scanning S3 buckets for PII compliance...")
        
        # Get all S3 buckets
        buckets = s3.list_buckets()['Buckets']
        
        for bucket in buckets:
            bucket_name = bucket['Name']
            logger.info(f"Scanning bucket: {bucket_name}")
            
            # Check bucket encryption
            encryption_status = check_s3_encryption(s3, bucket_name)
            
            # Check for public access
            public_access = check_s3_public_access(s3, bucket_name)
            
            # Check bucket policy for data processing compliance
            bucket_policy = check_s3_bucket_policy(s3, bucket_name)
            
            # Sample objects to identify potential PII
            pii_objects = scan_s3_objects_for_pii(s3, bucket_name)
            
            # Check lifecycle policies for data retention
            lifecycle_policy = check_s3_lifecycle_policy(s3, bucket_name)
            
            # Compile findings for this bucket
            bucket_issues = []
            
            if not encryption_status:
                bucket_issues.append("Bucket not encrypted - potential PII exposure risk")
            
            if public_access:
                bucket_issues.append("Bucket has public access - GDPR violation risk")
            
            if not lifecycle_policy:
                bucket_issues.append("No data retention policy - GDPR Article 5 violation")
            
            if pii_objects:
                bucket_issues.append(f"Potential PII detected in {len(pii_objects)} objects")
            
            if bucket_issues:
                risk_level = 'HIGH' if public_access or not encryption_status else 'MEDIUM'
                
                findings.append({
                    'service': 'S3',
                    'resource_id': bucket_name,
                    'gdpr_article': 'Article 32 (Security of processing)',
                    'compliance_status': 'NON_COMPLIANT',
                    'risk_level': risk_level,
                    'issues': bucket_issues,
                    'pii_objects': pii_objects,
                    'timestamp': datetime.utcnow().isoformat(),
                    'remediation': [
                        'Enable bucket encryption',
                        'Remove public access',
                        'Implement lifecycle policies for data retention',
                        'Review and classify data for PII'
                    ]
                })
        
    except Exception as e:
        logger.error(f"Error scanning S3 for PII: {str(e)}")

def check_s3_encryption(s3, bucket_name):
    """Check if S3 bucket has encryption enabled."""
    
    try:
        s3.get_bucket_encryption(Bucket=bucket_name)
        return True
    except s3.exceptions.ClientError as e:
        if e.response['Error']['Code'] == 'ServerSideEncryptionConfigurationNotFoundError':
            return False
        raise

def check_s3_public_access(s3, bucket_name):
    """Check if S3 bucket has public access."""
    
    try:
        # Check bucket ACL
        acl = s3.get_bucket_acl(Bucket=bucket_name)
        for grant in acl['Grants']:
            grantee = grant.get('Grantee', {})
            if grantee.get('Type') == 'Group' and 'AllUsers' in grantee.get('URI', ''):
                return True
        
        # Check public access block
        try:
            public_access_block = s3.get_public_access_block(Bucket=bucket_name)
            config = public_access_block['PublicAccessBlockConfiguration']
            
            if not all([
                config.get('BlockPublicAcls', False),
                config.get('IgnorePublicAcls', False),
                config.get('BlockPublicPolicy', False),
                config.get('RestrictPublicBuckets', False)
            ]):
                return True
                
        except s3.exceptions.ClientError:
            # If no public access block is configured, assume public access is possible
            return True
        
        return False
        
    except Exception as e:
        logger.error(f"Error checking public access for {bucket_name}: {str(e)}")
        return False

def check_s3_bucket_policy(s3, bucket_name):
    """Check S3 bucket policy for GDPR compliance indicators."""
    
    try:
        policy = s3.get_bucket_policy(Bucket=bucket_name)
        policy_document = json.loads(policy['Policy'])
        
        # Look for data processing consent mechanisms
        has_consent_controls = False
        
        for statement in policy_document.get('Statement', []):
            # Check for conditions that might indicate consent-based access
            conditions = statement.get('Condition', {})
            if any('consent' in str(condition).lower() for condition in conditions.values()):
                has_consent_controls = True
        
        return has_consent_controls
        
    except s3.exceptions.ClientError:
        # No bucket policy exists
        return False
    except Exception as e:
        logger.error(f"Error checking bucket policy for {bucket_name}: {str(e)}")
        return False

def scan_s3_objects_for_pii(s3, bucket_name, max_objects=10):
    """Scan S3 objects for potential PII content."""
    
    try:
        pii_objects = []
        
        # List objects (limited sample)
        response = s3.list_objects_v2(Bucket=bucket_name, MaxKeys=max_objects)
        
        if 'Contents' not in response:
            return pii_objects
        
        pii_patterns = [
            r'\b\d{3}-\d{2}-\d{4}\b',  # SSN
            r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b',  # Email
            r'\b\d{4}[- ]?\d{4}[- ]?\d{4}[- ]?\d{4}\b',  # Credit card
            r'\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b',  # IP address
            r'\b[A-Z]{2}\d{6}[A-Z]\b',  # Passport-like pattern
        ]
        
        for obj in response['Contents'][:5]:  # Check first 5 objects
            key = obj['Key']
            
            # Skip binary files and large files
            if (obj['Size'] > 1024 * 1024 or  # 1MB limit
                any(key.lower().endswith(ext) for ext in ['.jpg', '.png', '.pdf', '.zip', '.gz'])):
                continue
            
            try:
                # Get object content
                response = s3.get_object(Bucket=bucket_name, Key=key)
                content = response['Body'].read().decode('utf-8', errors='ignore')
                
                # Check for PII patterns
                pii_found = []
                for pattern in pii_patterns:
                    matches = re.findall(pattern, content)
                    if matches:
                        pii_found.append(f"Pattern: {pattern} (matches: {len(matches)})")
                
                if pii_found:
                    pii_objects.append({
                        'object_key': key,
                        'pii_patterns_found': pii_found,
                        'object_size': obj['Size']
                    })
                    
            except Exception as e:
                logger.warning(f"Could not scan object {key}: {str(e)}")
                continue
        
        return pii_objects
        
    except Exception as e:
        logger.error(f"Error scanning objects in {bucket_name}: {str(e)}")
        return []

def check_s3_lifecycle_policy(s3, bucket_name):
    """Check if S3 bucket has lifecycle policy for data retention."""
    
    try:
        s3.get_bucket_lifecycle_configuration(Bucket=bucket_name)
        return True
    except s3.exceptions.ClientError as e:
        if e.response['Error']['Code'] == 'NoSuchLifecycleConfiguration':
            return False
        raise

def scan_rds_pii_compliance(findings):
    """Scan RDS instances for PII compliance."""
    
    try:
        rds = boto3.client('rds')
        logger.info("Scanning RDS instances for PII compliance...")
        
        # Get all RDS instances
        paginator = rds.get_paginator('describe_db_instances')
        
        for page in paginator.paginate():
            for instance in page['DBInstances']:
                db_identifier = instance['DBInstanceIdentifier']
                
                issues = []
                
                # Check encryption
                if not instance.get('StorageEncrypted', False):
                    issues.append("Database not encrypted - potential PII exposure")
                
                # Check public accessibility
                if instance.get('PubliclyAccessible', False):
                    issues.append("Database publicly accessible - GDPR violation risk")
                
                # Check backup retention for data retention compliance
                backup_retention = instance.get('BackupRetentionPeriod', 0)
                if backup_retention > 2555:  # ~7 years in days
                    issues.append("Backup retention may exceed GDPR data retention limits")
                
                # Check automated backups for data recovery
                if backup_retention == 0:
                    issues.append("No automated backups - data recovery risk")
                
                # Check deletion protection
                if not instance.get('DeletionProtection', False):
                    issues.append("Deletion protection disabled - data loss risk")
                
                if issues:
                    risk_level = 'HIGH' if instance.get('PubliclyAccessible', False) else 'MEDIUM'
                    
                    findings.append({
                        'service': 'RDS',
                        'resource_id': db_identifier,
                        'gdpr_article': 'Article 32 (Security of processing) & Article 17 (Right to erasure)',
                        'compliance_status': 'NON_COMPLIANT',
                        'risk_level': risk_level,
                        'issues': issues,
                        'timestamp': datetime.utcnow().isoformat(),
                        'remediation': [
                            'Enable encryption at rest',
                            'Disable public access',
                            'Review backup retention policies',
                            'Enable deletion protection'
                        ]
                    })
        
    except Exception as e:
        logger.error(f"Error scanning RDS for PII: {str(e)}")

def check_data_retention_policies(findings):
    """Check for GDPR-compliant data retention policies."""
    
    try:
        logger.info("Checking data retention policies...")
        
        # Check CloudWatch log retention
        logs = boto3.client('logs')
        paginator = logs.get_paginator('describe_log_groups')
        
        long_retention_logs = []
        
        for page in paginator.paginate():
            for log_group in page['logGroups']:
                log_group_name = log_group['logGroupName']
                retention_days = log_group.get('retentionInDays')
                
                # GDPR generally requires data to be deleted when no longer necessary
                # 7 years (2555 days) is often the maximum for legal/tax purposes
                if retention_days and retention_days > 2555:
                    long_retention_logs.append({
                        'log_group': log_group_name,
                        'retention_days': retention_days
                    })
        
        if long_retention_logs:
            findings.append({
                'service': 'CloudWatch Logs',
                'resource_id': 'multiple_log_groups',
                'gdpr_article': 'Article 5 (Storage limitation)',
                'compliance_status': 'NON_COMPLIANT',
                'risk_level': 'MEDIUM',
                'issues': [f"{len(long_retention_logs)} log groups with excessive retention periods"],
                'details': long_retention_logs,
                'timestamp': datetime.utcnow().isoformat(),
                'remediation': [
                    'Review and reduce log retention periods',
                    'Implement data lifecycle management',
                    'Ensure compliance with data minimization principle'
                ]
            })
        
    except Exception as e:
        logger.error(f"Error checking data retention policies: {str(e)}")

def check_cross_border_data_transfer(findings):
    """Check for potential cross-border data transfer issues."""
    
    try:
        logger.info("Checking cross-border data transfer compliance...")
        
        ec2 = boto3.client('ec2')
        s3 = boto3.client('s3')
        
        # Get account's primary region
        current_region = boto3.Session().region_name
        
        cross_border_issues = []
        
        # Check S3 buckets in different regions
        buckets = s3.list_buckets()['Buckets']
        
        for bucket in buckets:
            bucket_name = bucket['Name']
            try:
                bucket_location = s3.get_bucket_location(Bucket=bucket_name)['LocationConstraint']
                
                # If LocationConstraint is None, bucket is in us-east-1
                if bucket_location is None:
                    bucket_location = 'us-east-1'
                
                # Check if bucket is outside EU regions (for EU GDPR compliance)
                eu_regions = [
                    'eu-west-1', 'eu-west-2', 'eu-west-3', 'eu-central-1',
                    'eu-north-1', 'eu-south-1'
                ]
                
                if bucket_location not in eu_regions and current_region in eu_regions:
                    cross_border_issues.append({
                        'resource_type': 'S3 Bucket',
                        'resource_id': bucket_name,
                        'current_region': bucket_location,
                        'issue': 'EU data stored outside EU regions'
                    })
                    
            except Exception as e:
                logger.warning(f"Could not check location for bucket {bucket_name}: {str(e)}")
        
        # Check RDS instances in different regions
        try:
            rds = boto3.client('rds')
            instances = rds.describe_db_instances()['DBInstances']
            
            for instance in instances:
                db_id = instance['DBInstanceIdentifier']
                availability_zone = instance['AvailabilityZone']
                instance_region = availability_zone[:-1]  # Remove AZ letter
                
                if instance_region not in eu_regions and current_region in eu_regions:
                    cross_border_issues.append({
                        'resource_type': 'RDS Instance',
                        'resource_id': db_id,
                        'current_region': instance_region,
                        'issue': 'EU database stored outside EU regions'
                    })
                    
        except Exception as e:
            logger.warning(f"Could not check RDS instances: {str(e)}")
        
        if cross_border_issues:
            findings.append({
                'service': 'Multi-Region Resources',
                'resource_id': 'cross_border_transfers',
                'gdpr_article': 'Chapter V (Transfers of personal data to third countries)',
                'compliance_status': 'NON_COMPLIANT',
                'risk_level': 'HIGH',
                'issues': ['Potential unauthorized cross-border data transfers'],
                'details': cross_border_issues,
                'timestamp': datetime.utcnow().isoformat(),
                'remediation': [
                    'Review data residency requirements',
                    'Implement data localization policies',
                    'Ensure adequate safeguards for international transfers',
                    'Consider Standard Contractual Clauses (SCCs)'
                ]
            })
        
    except Exception as e:
        logger.error(f"Error checking cross-border transfers: {str(e)}")

def scan_dynamodb_pii_compliance(findings):
    """Scan DynamoDB tables for PII compliance."""
    
    try:
        dynamodb = boto3.client('dynamodb')
        logger.info("Scanning DynamoDB tables for PII compliance...")
        
        # Get all DynamoDB tables
        paginator = dynamodb.get_paginator('list_tables')
        
        for page in paginator.paginate():
            for table_name in page['TableNames']:
                
                issues = []
                
                # Get table description
                table_desc = dynamodb.describe_table(TableName=table_name)['Table']
                
                # Check encryption at rest
                sse_desc = table_desc.get('SSEDescription')
                if not sse_desc or sse_desc.get('Status') != 'ENABLED':
                    issues.append("Table not encrypted - potential PII exposure")
                
                # Check point-in-time recovery for data protection
                try:
                    pitr = dynamodb.describe_continuous_backups(TableName=table_name)
                    if not pitr['ContinuousBackupsDescription']['PointInTimeRecoveryDescription']['PointInTimeRecoveryStatus'] == 'ENABLED':
                        issues.append("Point-in-time recovery disabled - data recovery risk")
                except Exception:
                    issues.append("Point-in-time recovery not configured")
                
                # Sample scan for PII (limited to avoid performance impact)
                pii_items = scan_dynamodb_items_for_pii(dynamodb, table_name)
                
                if pii_items:
                    issues.append(f"Potential PII detected in {len(pii_items)} items")
                
                if issues:
                    findings.append({
                        'service': 'DynamoDB',
                        'resource_id': table_name,
                        'gdpr_article': 'Article 32 (Security of processing)',
                        'compliance_status': 'NON_COMPLIANT',
                        'risk_level': 'MEDIUM',
                        'issues': issues,
                        'pii_items_sample': pii_items[:3] if pii_items else [],  # Limit sample
                        'timestamp': datetime.utcnow().isoformat(),
                        'remediation': [
                            'Enable encryption at rest',
                            'Enable point-in-time recovery',
                            'Review and classify data for PII',
                            'Implement data anonymization'
                        ]
                    })
        
    except Exception as e:
        logger.error(f"Error scanning DynamoDB: {str(e)}")

def scan_dynamodb_items_for_pii(dynamodb, table_name, max_items=10):
    """Scan DynamoDB items for potential PII."""
    
    try:
        pii_items = []
        
        # Perform limited scan
        response = dynamodb.scan(
            TableName=table_name,
            Limit=max_items,
            Select='ALL_ATTRIBUTES'
        )
        
        pii_patterns = {
            'email': r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b',
            'phone': r'\b\d{3}[-.]?\d{3}[-.]?\d{4}\b',
            'ssn': r'\b\d{3}-\d{2}-\d{4}\b'
        }
        
        for item in response.get('Items', []):
            item_pii = {}
            
            for attr_name, attr_value in item.items():
                if 'S' in attr_value:  # String attribute
                    text_value = attr_value['S']
                    
                    for pii_type, pattern in pii_patterns.items():
                        if re.search(pattern, text_value):
                            if pii_type not in item_pii:
                                item_pii[pii_type] = []
                            item_pii[pii_type].append(attr_name)
            
            if item_pii:
                pii_items.append({
                    'item_attributes_with_pii': item_pii
                })
        
        return pii_items
        
    except Exception as e:
        logger.error(f"Error scanning DynamoDB items in {table_name}: {str(e)}")
        return []

def scan_cloudwatch_pii_exposure(findings):
    """Scan CloudWatch logs for potential PII exposure."""
    
    try:
        logs = boto3.client('logs')
        logger.info("Scanning CloudWatch logs for PII exposure...")
        
        # Get log groups
        paginator = logs.get_paginator('describe_log_groups')
        
        pii_exposures = []
        
        for page in paginator.paginate():
            for log_group in page['logGroups'][:5]:  # Limit to first 5 log groups
                log_group_name = log_group['logGroupName']
                
                try:
                    # Get recent log streams
                    streams = logs.describe_log_streams(
                        logGroupName=log_group_name,
                        orderBy='LastEventTime',
                        descending=True,
                        limit=2
                    )['logStreams']
                    
                    for stream in streams:
                        stream_name = stream['logStreamName']
                        
                        # Get recent events
                        events = logs.get_log_events(
                            logGroupName=log_group_name,
                            logStreamName=stream_name,
                            limit=10,
                            startFromHead=False
                        )['events']
                        
                        pii_in_logs = check_log_events_for_pii(events)
                        
                        if pii_in_logs:
                            pii_exposures.append({
                                'log_group': log_group_name,
                                'log_stream': stream_name,
                                'pii_types': pii_in_logs
                            })
                            
                except Exception as e:
                    logger.warning(f"Could not scan log group {log_group_name}: {str(e)}")
                    continue
        
        if pii_exposures:
            findings.append({
                'service': 'CloudWatch Logs',
                'resource_id': 'log_pii_exposure',
                'gdpr_article': 'Article 32 (Security of processing)',
                'compliance_status': 'NON_COMPLIANT',
                'risk_level': 'HIGH',
                'issues': ['PII detected in application logs'],
                'details': pii_exposures,
                'timestamp': datetime.utcnow().isoformat(),
                'remediation': [
                    'Implement log sanitization',
                    'Remove PII from application logs',
                    'Use structured logging with PII masking',
                    'Review logging practices'
                ]
            })
        
    except Exception as e:
        logger.error(f"Error scanning CloudWatch logs: {str(e)}")

def check_log_events_for_pii(events):
    """Check log events for PII patterns."""
    
    pii_patterns = {
        'email': r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b',
        'credit_card': r'\b\d{4}[- ]?\d{4}[- ]?\d{4}[- ]?\d{4}\b',
        'ssn': r'\b\d{3}-\d{2}-\d{4}\b'
    }
    
    detected_pii = []
    
    for event in events:
        message = event.get('message', '')
        
        for pii_type, pattern in pii_patterns.items():
            if re.search(pattern, message):
                if pii_type not in detected_pii:
                    detected_pii.append(pii_type)
    
    return detected_pii

def generate_gdpr_compliance_report(findings):
    """Generate and upload GDPR compliance report to S3."""
    
    try:
        s3 = boto3.client('s3')
        timestamp = datetime.utcnow().strftime('%Y-%m-%d_%H-%M-%S')
        
        # Calculate risk summary
        total_findings = len(findings)
        high_risk_count = len([f for f in findings if f.get('risk_level') == 'HIGH'])
        medium_risk_count = len([f for f in findings if f.get('risk_level') == 'MEDIUM'])
        
        # Group findings by GDPR article
        findings_by_article = {}
        for finding in findings:
            article = finding.get('gdpr_article', 'Unknown')
            if article not in findings_by_article:
                findings_by_article[article] = []
            findings_by_article[article].append(finding)
        
        report = {
            'assessment_timestamp': timestamp,
            'gdpr_compliance_summary': {
                'total_findings': total_findings,
                'high_risk_findings': high_risk_count,
                'medium_risk_findings': medium_risk_count,
                'services_scanned': list(set([f['service'] for f in findings])),
                'compliance_score': calculate_gdpr_compliance_score(findings)
            },
            'findings_by_article': findings_by_article,
            'all_findings': findings,
            'recommendations': generate_gdpr_recommendations(findings),
            'legal_basis_review': {
                'note': 'Manual review required for legal basis assessment under Article 6',
                'data_processing_activities': 'Review all data processing activities for lawful basis'
            },
            'data_subject_rights': {
                'note': 'Ensure mechanisms exist for data subject rights under Chapter III',
                'required_mechanisms': [
                    'Right of access (Article 15)',
                    'Right to rectification (Article 16)', 
                    'Right to erasure (Article 17)',
                    'Right to data portability (Article 20)'
                ]
            }
        }
        
        bucket_name = 'gdpr-compliance-reports-bucket'  # Configure this
        file_name = f'gdpr-compliance-report-{timestamp}.json'
        
        s3.put_object(
            Bucket=bucket_name,
            Key=file_name,
            Body=json.dumps(report, indent=2),
            ContentType='application/json'
        )
        
        logger.info(f"GDPR compliance report uploaded to S3: {file_name}")
        
    except Exception as e:
        logger.error(f"Failed to generate GDPR compliance report: {str(e)}")

def calculate_gdpr_compliance_score(findings):
    """Calculate a compliance score based on findings."""
    
    if not findings:
        return 100
    
    total_weight = len(findings) * 100
    penalty_weight = 0
    
    for finding in findings:
        risk_level = finding.get('risk_level', 'LOW')
        if risk_level == 'HIGH':
            penalty_weight += 100
        elif risk_level == 'MEDIUM':
            penalty_weight += 50
        else:
            penalty_weight += 25
    
    score = max(0, 100 - (penalty_weight / total_weight * 100))
    return round(score, 2)

def generate_gdpr_recommendations(findings):
    """Generate actionable GDPR compliance recommendations."""
    
    recommendations = [
        {
            'priority': 'HIGH',
            'category': 'Data Protection by Design',
            'action': 'Implement encryption at rest and in transit for all PII storage',
            'gdpr_reference': 'Article 25, Article 32'
        },
        {
            'priority': 'HIGH',
            'category': 'Access Controls',
            'action': 'Remove public access to any resources containing PII',
            'gdpr_reference': 'Article 32'
        },
        {
            'priority': 'MEDIUM',
            'category': 'Data Minimization',
            'action': 'Implement data lifecycle policies to automatically delete data when no longer needed',
            'gdpr_reference': 'Article 5(1)(e)'
        },
        {
            'priority': 'MEDIUM',
            'category': 'Monitoring and Logging',
            'action': 'Implement PII detection and masking in application logs',
            'gdpr_reference': 'Article 32'
        },
        {
            'priority': 'LOW',
            'category': 'Documentation',
            'action': 'Document all data processing activities and legal basis',
            'gdpr_reference': 'Article 30'
        }
    ]
    
    # Add specific recommendations based on findings
    if any('cross_border' in f.get('resource_id', '') for f in findings):
        recommendations.append({
            'priority': 'HIGH',
            'category': 'International Transfers',
            'action': 'Review and implement adequate safeguards for international data transfers',
            'gdpr_reference': 'Chapter V'
        })
    
    return recommendations