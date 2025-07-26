import boto3
import json
import logging
from datetime import datetime

logger = logging.getLogger()
logger.setLevel(logging.INFO)

iam = boto3.client('iam')
s3 = boto3.client('s3')

def lambda_handler(event, context):
    """
    Lambda function to harden IAM policies by removing overly permissive policies
    and replacing them with least-privilege alternatives.
    """
    
    remediation_actions = []
    
    try:
        # Get all IAM policies (customer-managed only)
        paginator = iam.get_paginator('list_policies')
        policies = []
        
        for page in paginator.paginate(Scope='Local'):
            policies.extend(page['Policies'])
        
        for policy in policies:
            policy_arn = policy['Arn']
            policy_name = policy['PolicyName']
            
            logger.info(f"Analyzing policy: {policy_name}")
            
            # Get the policy document
            policy_version = iam.get_policy_version(
                PolicyArn=policy_arn,
                VersionId=policy['DefaultVersionId']
            )
            
            policy_document = policy_version['PolicyVersion']['Document']
            
            # Check for overly permissive policies
            if is_overly_permissive(policy_document):
                logger.warning(f"Found overly permissive policy: {policy_name}")
                
                # Create hardened version
                hardened_policy = harden_policy(policy_document)
                
                if hardened_policy != policy_document:
                    # Create new policy version
                    try:
                        new_version = iam.create_policy_version(
                            PolicyArn=policy_arn,
                            PolicyDocument=json.dumps(hardened_policy)
                        )
                        
                        # Set as default version
                        iam.set_default_policy_version(
                            PolicyArn=policy_arn,
                            VersionId=new_version['PolicyVersion']['VersionId']
                        )
                        
                        remediation_actions.append({
                            'action': 'policy_hardened',
                            'policy_name': policy_name,
                            'policy_arn': policy_arn,
                            'timestamp': datetime.utcnow().isoformat()
                        })
                        
                        logger.info(f"Successfully hardened policy: {policy_name}")
                        
                    except Exception as e:
                        logger.error(f"Failed to harden policy {policy_name}: {str(e)}")
                        
        # Check for overly permissive inline policies on users
        check_user_inline_policies(remediation_actions)
        
        # Check for overly permissive inline policies on roles
        check_role_inline_policies(remediation_actions)
        
        # Generate report
        generate_remediation_report(remediation_actions)
        
        return {
            'statusCode': 200,
            'body': json.dumps({
                'message': 'IAM policy hardening completed',
                'actions_taken': len(remediation_actions),
                'details': remediation_actions
            })
        }
        
    except Exception as e:
        logger.error(f"Error during IAM policy hardening: {str(e)}")
        return {
            'statusCode': 500,
            'body': json.dumps({'error': str(e)})
        }

def is_overly_permissive(policy_document):
    """Check if a policy is overly permissive."""
    
    risky_patterns = [
        # Full admin access
        {'Effect': 'Allow', 'Action': '*', 'Resource': '*'},
        # Wildcard actions on sensitive resources
        {'Action': ['*'], 'Resource': '*'},
        # Dangerous IAM permissions
        {'Action': ['iam:*']},
        # Root-like permissions
        {'Action': ['*:*']},
    ]
    
    statements = policy_document.get('Statement', [])
    if not isinstance(statements, list):
        statements = [statements]
    
    for statement in statements:
        if statement.get('Effect') == 'Allow':
            action = statement.get('Action', [])
            resource = statement.get('Resource', [])
            
            # Convert to list for consistent checking
            if isinstance(action, str):
                action = [action]
            if isinstance(resource, str):
                resource = [resource]
                
            # Check for wildcard permissions
            if '*' in action and '*' in resource:
                return True
                
            # Check for IAM admin permissions
            if any('iam:*' in a for a in action):
                return True
                
            # Check for dangerous combinations
            dangerous_actions = [
                'iam:CreateRole', 'iam:AttachRolePolicy', 'iam:PutRolePolicy',
                'iam:CreateUser', 'iam:AttachUserPolicy', 'iam:PutUserPolicy',
                'sts:AssumeRole'
            ]
            
            if any(da in action for da in dangerous_actions) and '*' in resource:
                return True
    
    return False

def harden_policy(policy_document):
    """Create a hardened version of an overly permissive policy."""
    
    hardened_policy = json.loads(json.dumps(policy_document))  # Deep copy
    statements = hardened_policy.get('Statement', [])
    
    if not isinstance(statements, list):
        statements = [statements]
        hardened_policy['Statement'] = statements
    
    for i, statement in enumerate(statements):
        if statement.get('Effect') == 'Allow':
            action = statement.get('Action', [])
            resource = statement.get('Resource', [])
            
            # Convert to list for consistent processing
            if isinstance(action, str):
                action = [action]
            if isinstance(resource, str):
                resource = [resource]
            
            # Remove wildcard permissions and replace with specific ones
            if '*' in action:
                # Replace with common safe actions
                safe_actions = [
                    's3:GetObject', 's3:ListBucket',
                    'ec2:DescribeInstances', 'ec2:DescribeImages',
                    'logs:CreateLogGroup', 'logs:CreateLogStream', 'logs:PutLogEvents'
                ]
                action = [a for a in action if a != '*'] + safe_actions
                
            # Restrict overly broad IAM permissions
            restricted_iam_actions = []
            for a in action:
                if 'iam:*' in a:
                    # Replace with specific read-only IAM permissions
                    restricted_iam_actions.extend([
                        'iam:GetUser', 'iam:GetRole', 'iam:ListUsers', 'iam:ListRoles'
                    ])
                else:
                    restricted_iam_actions.append(a)
            
            action = restricted_iam_actions
            
            # Restrict wildcard resources
            if '*' in resource:
                # Add condition to limit scope
                if 'Condition' not in statement:
                    statement['Condition'] = {}
                
                # Add IP restriction condition as example
                statement['Condition']['IpAddress'] = {
                    'aws:SourceIp': ['10.0.0.0/8', '172.16.0.0/12', '192.168.0.0/16']
                }
            
            # Update the statement
            statements[i]['Action'] = action if len(action) > 1 else action[0]
            statements[i]['Resource'] = resource if len(resource) > 1 else resource[0]
    
    return hardened_policy

def check_user_inline_policies(remediation_actions):
    """Check and remediate overly permissive inline policies on users."""
    
    try:
        paginator = iam.get_paginator('list_users')
        
        for page in paginator.paginate():
            for user in page['Users']:
                username = user['UserName']
                
                # Get inline policies for this user
                inline_policies = iam.list_user_policies(UserName=username)
                
                for policy_name in inline_policies['PolicyNames']:
                    policy_doc = iam.get_user_policy(
                        UserName=username,
                        PolicyName=policy_name
                    )
                    
                    if is_overly_permissive(policy_doc['PolicyDocument']):
                        logger.warning(f"Found overly permissive inline policy on user {username}: {policy_name}")
                        
                        # Delete the overly permissive inline policy
                        iam.delete_user_policy(
                            UserName=username,
                            PolicyName=policy_name
                        )
                        
                        remediation_actions.append({
                            'action': 'removed_permissive_inline_policy',
                            'user_name': username,
                            'policy_name': policy_name,
                            'timestamp': datetime.utcnow().isoformat()
                        })
                        
                        logger.info(f"Removed overly permissive inline policy {policy_name} from user {username}")
                        
    except Exception as e:
        logger.error(f"Error checking user inline policies: {str(e)}")

def check_role_inline_policies(remediation_actions):
    """Check and remediate overly permissive inline policies on roles."""
    
    try:
        paginator = iam.get_paginator('list_roles')
        
        for page in paginator.paginate():
            for role in page['Roles']:
                role_name = role['RoleName']
                
                # Skip AWS service roles
                if role_name.startswith('AWS') or 'aws-' in role_name.lower():
                    continue
                
                # Get inline policies for this role
                inline_policies = iam.list_role_policies(RoleName=role_name)
                
                for policy_name in inline_policies['PolicyNames']:
                    policy_doc = iam.get_role_policy(
                        RoleName=role_name,
                        PolicyName=policy_name
                    )
                    
                    if is_overly_permissive(policy_doc['PolicyDocument']):
                        logger.warning(f"Found overly permissive inline policy on role {role_name}: {policy_name}")
                        
                        # Delete the overly permissive inline policy
                        iam.delete_role_policy(
                            RoleName=role_name,
                            PolicyName=policy_name
                        )
                        
                        remediation_actions.append({
                            'action': 'removed_permissive_inline_policy',
                            'role_name': role_name,
                            'policy_name': policy_name,
                            'timestamp': datetime.utcnow().isoformat()
                        })
                        
                        logger.info(f"Removed overly permissive inline policy {policy_name} from role {role_name}")
                        
    except Exception as e:
        logger.error(f"Error checking role inline policies: {str(e)}")

def generate_remediation_report(actions):
    """Generate and upload remediation report to S3."""
    
    try:
        timestamp = datetime.utcnow().strftime('%Y-%m-%d_%H-%M-%S')
        report = {
            'scan_timestamp': timestamp,
            'total_actions': len(actions),
            'actions': actions,
            'summary': {
                'policies_hardened': len([a for a in actions if a['action'] == 'policy_hardened']),
                'inline_policies_removed': len([a for a in actions if a['action'] == 'removed_permissive_inline_policy'])
            }
        }
        
        bucket_name = 'iam-security-reports-bucket'  # Configure this
        file_name = f'iam-hardening-report-{timestamp}.json'
        
        s3.put_object(
            Bucket=bucket_name,
            Key=file_name,
            Body=json.dumps(report, indent=2),
            ContentType='application/json'
        )
        
        logger.info(f"Remediation report uploaded to S3: {file_name}")
        
    except Exception as e:
        logger.error(f"Failed to generate remediation report: {str(e)}")