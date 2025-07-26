<div align="center">
  <h1>AWS Security Audits Automation Scripts</h1>
</div>

<p align="center">A collection of automated security audit tools and remediation scripts for AWS environments.</p>


## Features

### Security Scanning Tools
- **Prowler Integration**: Daily automated security assessments using Prowler
- **ScoutSuite Integration**: Daily security scans using ScoutSuite
- **AWS Trusted Advisor**: Automated reporting of AWS Trusted Advisor check results

### Automated Remediation Functions
- **EBS Volume Encryption**: Automatically identifies and encrypts unencrypted EBS volumes
- **EBS Volume Compliance**: Monitors and notifies about oversized EBS volumes
- **Security Group Remediation**: Automatically removes overly permissive SSH rules (0.0.0.0/0 on port 22)
- **IAM Policy Hardening**: Identifies and removes overly permissive IAM policies
- **RDS Security Hardening**: Enables encryption, backups, and security configurations for RDS
- **Unused Resource Cleanup**: Identifies and removes unused AWS resources to reduce costs

### Compliance & Assessment Functions
- **SOC 2 Compliance Checker**: Validates AWS environment against SOC 2 security controls
- **GDPR Data Protection Scanner**: Scans for unencrypted PII and GDPR compliance violations

## Prerequisites

<table>
  <tr>
    <td>AWS Account</td>
    <td>GitHub Actions</td>
  </tr>
  <tr>
    <td>Python 3.9+</td>
    <td>AWS CLI</td>
  </tr>
</table>

## Repository Structure

```
.
├── .github/workflows/
│   ├── prowler.yml        # GitHub Actions workflow for Prowler
│   └── scoutsuite.yml     # GitHub Actions workflow for ScoutSuite
├── AWS_Trusted_Advisor/
│   └── Lambda_function.py # Trusted Advisor reporting function
├── Lambda_fn/
│   ├── EBS_Volume_compliance_notification.py  # Volume size monitoring
│   ├── EBS_Volume_Encryption.py               # EBS encryption remediation
│   ├── SG-Remediation.py                      # Security group cleanup
│   ├── IAM_Policy_Hardening.py                # IAM policy remediation
│   ├── RDS_Security_Hardening.py              # RDS security improvements
│   ├── Unused_Resource_Cleanup.py             # Resource cleanup automation
│   ├── SOC2_Compliance_Checker.py             # SOC 2 compliance validation
│   └── GDPR_Data_Protection_Scanner.py        # GDPR compliance scanning
└── Prowler_Codedeploy/
    └── buildspec.yml      # AWS CodeBuild specification for Prowler
```

## Setup Instructions

<details>
<summary><b>1. GitHub Actions Configuration</b></summary>
<br>
Set up the following secrets in your GitHub repository:

- `ROLE_TO_ASSUME`: ARN of the IAM role to assume
- `AWS_REGION`: Your AWS region
- `S3_BUCKET_URI`: S3 bucket URI for Prowler reports
- `S3_BUCKET_URI2`: S3 bucket URI for ScoutSuite reports
</details>

<details>
<summary><b>2. AWS Configuration</b></summary>
<br>

1. Create an IAM role (OIDC) with appropriate permissions for GitHub Actions
2. Configure S3 buckets for storing security reports
3. Set up Lambda functions for remediation tasks
</details>

<details>
<summary><b>3. Lambda Functions Deployment</b></summary>
<br>
Deploy the following Lambda functions:

**Security Remediation Functions:**
- EBS Volume Encryption Remediation
- EBS Volume Compliance Monitoring
- Security Group Rules Remediation
- IAM Policy Hardening
- RDS Security Hardening
- Unused Resource Cleanup

**Assessment & Compliance Functions:**
- Trusted Advisor Reporting
- SOC 2 Compliance Checker
- GDPR Data Protection Scanner
</details>

## Security Scanning Schedule

<table>
  <tr>
    <th>Service</th>
    <th>Schedule</th>
  </tr>
  <tr>
    <td>Prowler</td>
    <td>Daily at 2:00 UTC</td>
  </tr>
  <tr>
    <td>ScoutSuite</td>
    <td>Daily at 3:00 UTC</td>
  </tr>
  <tr>
    <td>Trusted Advisor</td>
    <td>Configurable through Lambda trigger</td>
  </tr>
</table>

## Lambda Functions Documentation

### Security Remediation Functions

<details>
<summary><b>1. EBS Volume Encryption (EBS_Volume_Encryption.py)</b></summary>
<br>

**What it does:**
- Scans all EC2 instances for unencrypted root volumes
- Automatically creates encrypted copies without data loss

**How it works:**
1. Creates a snapshot of the unencrypted volume
2. Stops the instance temporarily
3. Creates an encrypted volume from the snapshot
4. Replaces the old volume with the encrypted one
5. Restarts the instance with full encryption

**Best practices:**
- Schedule during maintenance windows
- Test with non-production instances first
- Monitor CloudWatch logs for any issues
- Verify instance functionality after encryption

**Trigger:** Manual execution or scheduled CloudWatch Events
</details>

<details>
<summary><b>2. Security Group Remediation (SG-Remediation.py)</b></summary>
<br>

**What it does:**
- Monitors security group modifications in real-time
- Automatically removes dangerous SSH access rules (0.0.0.0/0:22)
- Prevents accidental exposure of SSH services to the internet

**How it works:**
1. Listens to CloudTrail events for security group changes
2. Analyzes new or modified ingress rules
3. Identifies rules allowing SSH access from anywhere
4. Automatically revokes the dangerous rules
5. Logs all remediation actions for audit trails

**Best practices:**
- Deploy with CloudTrail and CloudWatch Events triggers
- Whitelist specific security groups if needed
- Monitor remediation logs regularly
- Test with non-critical security groups initially

**Trigger:** CloudTrail API events (real-time)
</details>

<details>
<summary><b>3. IAM Policy Hardening (IAM_Policy_Hardening.py)</b></summary>
<br>

**What it does:**
- Scans all customer-managed IAM policies for excessive permissions
- Removes wildcard permissions and replaces with specific actions
- Eliminates overly permissive inline policies on users and roles

**Key security improvements:**
- Converts `"Action": "*"` to specific safe actions
- Restricts `"iam:*"` to read-only IAM permissions
- Adds IP address conditions to limit access scope
- Removes inline policies entirely

**Best practices:**
- Run in test mode first to review proposed changes
- Backup existing policies before modification
- Coordinate with application teams for service accounts
- Monitor application functionality after policy changes

**Trigger:** Scheduled execution (weekly recommended)
</details>

<details>
<summary><b>4. RDS Security Hardening (RDS_Security_Hardening.py)</b></summary>
<br>

**What it does:**
- Enhances RDS security across instances and Aurora clusters
- Enables encryption, backups, monitoring, and access controls
- Hardens database security groups automatically

**Security enhancements:**
- **Encryption:** Creates encrypted snapshots for migration planning
- **Backups:** Enables 7-day automated backups with optimal timing
- **Monitoring:** Activates Performance Insights and Enhanced Monitoring
- **Protection:** Enables deletion protection and removes public access
- **Network:** Removes public database access from security groups

**Best practices:**
- Schedule during low-traffic periods
- Review encryption migration plans carefully
- Coordinate database maintenance windows
- Monitor database performance after changes

**Trigger:** Scheduled execution (monthly recommended)
</details>

<details>
<summary><b>5. Unused Resource Cleanup (Unused_Resource_Cleanup.py)</b></summary>
<br>

**What it does:**
- Identifies and removes unused AWS resources to reduce costs
- Creates safety backups before any destructive operations
- Calculates potential monthly savings from cleanup actions

**Resources cleaned up:**
- **Security Groups:** Unused groups (excluding default and referenced)
- **Key Pairs:** Keys not associated with any running instances
- **EBS Volumes:** Unattached volumes older than 30 days (with backup snapshots)
- **Elastic IPs:** Unassociated IP addresses
- **Network Interfaces:** Unused ENIs not managed by AWS services

**Cost savings:**
- EBS volumes: ~$0.10/GB/month
- Elastic IPs: ~$3.65/month per unused IP
- Detailed savings report included in output

**Best practices:**
- Review cleanup reports before running in production
- Verify backup snapshots are created successfully
- Run weekly during off-peak hours
- Monitor for any service disruptions after cleanup

**Trigger:** Scheduled execution (weekly recommended)
</details>

### Assessment & Compliance Functions

<details>
<summary><b>6. SOC 2 Compliance Checker (SOC2_Compliance_Checker.py)</b></summary>
<br>

**What it does:**
- Validates your AWS environment against SOC 2 Trust Service Criteria
- Provides detailed compliance scoring and remediation guidance
- Covers Security, Availability, and Confidentiality controls

**SOC 2 Controls assessed:**
- **CC6 (Security):** IAM password policy, MFA enforcement, root account usage
- **CC7 (System Operations):** CloudTrail logging, CloudWatch monitoring, AWS Config
- **CC8 (Change Management):** Infrastructure as code usage assessment
- **CC9 (Risk Assessment):** GuardDuty threat detection capabilities
- **A1 (Availability):** Backup procedures, multi-AZ deployments
- **C1 (Confidentiality):** Encryption at rest and in transit

**Compliance scoring:**
- Calculates overall compliance percentage
- Prioritizes findings by risk level (HIGH/MEDIUM/LOW)
- Provides specific remediation steps for each control

**Best practices:**
- Run monthly for compliance reporting
- Address HIGH priority findings immediately
- Use reports for audit preparation
- Track compliance improvements over time

**Trigger:** Scheduled execution (monthly recommended)
</details>

<details>
<summary><b>7. GDPR Data Protection Scanner (GDPR_Data_Protection_Scanner.py)</b></summary>
<br>

**What it does:**
- Scans AWS services for GDPR compliance violations
- Identifies unencrypted PII storage locations
- Validates data retention and cross-border transfer policies

**GDPR compliance checks:**
- **Article 32 (Security):** Encryption at rest/transit for PII storage
- **Article 5 (Storage Limitation):** Data retention policy validation
- **Chapter V (International Transfers):** Cross-border data transfer compliance
- **Article 17 (Right to Erasure):** Data lifecycle management

**Services scanned:**
- **S3 Buckets:** PII detection, encryption status, public access, lifecycle policies
- **RDS Instances:** Database encryption, public accessibility, backup retention
- **DynamoDB Tables:** Encryption settings, PII content analysis
- **CloudWatch Logs:** PII exposure in application logs

**Risk assessment:**
- HIGH: Public access to PII, unencrypted sensitive data
- MEDIUM: Missing data retention policies, cross-border transfers
- Provides specific GDPR article references for each finding

**Best practices:**
- Run before any data processing audits
- Address HIGH risk findings immediately
- Document remediation actions for compliance records
- Review data processing activities regularly

**Trigger:** Scheduled execution (quarterly recommended)
</details>

<details>
<summary><b>8. EBS Volume Compliance Notification (EBS_Volume_compliance_notification.py)</b></summary>
<br>

**What it does:**
- Monitors EBS volumes for size compliance policies
- Sends SNS notifications when volumes exceed defined limits
- Tracks volume usage patterns and growth trends

**Compliance monitoring:**
- Default threshold: 30GB volume size limit
- Monitors both attached and unattached volumes
- Provides detailed instance and volume relationship mapping

**Best practices:**
- Configure SNS topics for appropriate team notifications
- Adjust size thresholds based on organizational policies
- Schedule regular execution for proactive monitoring
- Use reports to plan capacity and cost optimization

**Trigger:** Scheduled execution (daily recommended)
</details>

<details>
<summary><b>9. AWS Trusted Advisor Integration (Lambda_function.py)</b></summary>
<br>

**What it does:**
- Fetches all AWS Trusted Advisor check results programmatically
- Consolidates security, performance, and cost recommendations
- Creates structured reports for automated processing

**Requirements:**
- AWS Business or Enterprise Support plan
- Appropriate IAM permissions for Support API access

**Report categories:**
- Security recommendations and vulnerabilities
- Performance optimization suggestions
- Cost optimization opportunities
- Service limit warnings

**Best practices:**
- Schedule daily execution during off-peak hours
- Integrate with notification systems for critical findings
- Use reports to track security posture improvements
- Coordinate with cost optimization initiatives

**Trigger:** Scheduled execution (daily recommended)
</details>

## Deployment and Usage Guide

### Quick Start Deployment

1. **Clone the repository:**
   ```bash
   git clone https://github.com/ToluGIT/AWS-Security-Audits-Automated.git
   cd AWS-Security-Audits-Automated
   ```

2. **Configure S3 buckets for reports:**
   ```bash
   # Create buckets for different report types
   aws s3 mb s3://your-security-reports-bucket
   aws s3 mb s3://your-prowler-reports-bucket
   aws s3 mb s3://your-compliance-reports-bucket
   ```

3. **Deploy Lambda functions:**
   ```bash
   # Package each function with dependencies
   cd Lambda_fn
   zip -r iam_policy_hardening.zip IAM_Policy_Hardening.py
   aws lambda create-function --function-name IAM-Policy-Hardening \
     --runtime python3.9 --role arn:aws:iam::123456789012:role/lambda-execution-role \
     --handler IAM_Policy_Hardening.lambda_handler --zip-file fileb://iam_policy_hardening.zip
   ```

### Recommended Execution Schedule

| Function | Frequency | Reason | Best Time |
|----------|-----------|---------|-----------|
| **SOC 2 Compliance Checker** | Monthly | Compliance reporting cycle | 1st of month, 9 AM UTC |
| **GDPR Data Protection Scanner** | Quarterly | Regulatory audit preparation | 1st of quarter, 10 AM UTC |
| **IAM Policy Hardening** | Weekly | Security policy drift prevention | Sunday, 2 AM UTC |
| **RDS Security Hardening** | Monthly | Database security maintenance | 2nd Sunday, 3 AM UTC |
| **Unused Resource Cleanup** | Weekly | Cost optimization | Friday, 11 PM UTC |
| **EBS Volume Encryption** | On-demand | As needed for new instances | Manual trigger |
| **Security Group Remediation** | Real-time | Immediate threat response | CloudTrail trigger |
| **EBS Volume Compliance** | Daily | Proactive monitoring | 6 AM UTC |
| **Trusted Advisor Integration** | Daily | Continuous improvement | 4 AM UTC |

### Architecture Patterns

#### Pattern 1: Real-time Security Response
```
CloudTrail → CloudWatch Events → Lambda → Immediate Remediation
```
- **Use for:** Security Group Remediation
- **Benefits:** Instant threat mitigation, minimal exposure window
- **Configuration:** Enable CloudTrail data events, create EventBridge rules

#### Pattern 2: Scheduled Compliance Assessment
```
CloudWatch Events → Lambda → S3 Reports → SNS Notifications
```
- **Use for:** SOC 2, GDPR compliance checks
- **Benefits:** Regular compliance monitoring, audit trail generation
- **Configuration:** Create scheduled EventBridge rules, configure SNS topics

#### Pattern 3: Cost-Optimized Cleanup
```
CloudWatch Events → Lambda → Backup Creation → Resource Deletion → Cost Reports
```
- **Use for:** Unused Resource Cleanup
- **Benefits:** Safe resource removal, cost tracking
- **Configuration:** Schedule during low-usage periods, enable detailed billing

### Monitoring and Alerting

#### CloudWatch Metrics to Track
- **Execution Success Rate:** `AWS/Lambda/Errors`
- **Processing Time:** `AWS/Lambda/Duration`
- **Cost Savings:** Custom metric from cleanup functions
- **Compliance Score:** Custom metric from assessment functions
- **Security Findings:** Custom metric from remediation functions

#### Recommended Alarms
```bash
# Lambda function failure alarm
aws cloudwatch put-metric-alarm \
  --alarm-name "Security-Lambda-Failures" \
  --alarm-description "Alert on security function failures" \
  --metric-name Errors \
  --namespace AWS/Lambda \
  --statistic Sum \
  --period 300 \
  --threshold 1 \
  --comparison-operator GreaterThanOrEqualToThreshold \
  --evaluation-periods 1
```

### Security Configuration

#### Required IAM Permissions by Function

**IAM Policy Hardening:**
```json
{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Effect": "Allow",
            "Action": [
                "iam:ListPolicies",
                "iam:GetPolicy",
                "iam:GetPolicyVersion",
                "iam:CreatePolicyVersion",
                "iam:SetDefaultPolicyVersion",
                "iam:ListUsers",
                "iam:ListRoles",
                "iam:ListUserPolicies",
                "iam:ListRolePolicies",
                "iam:GetUserPolicy",
                "iam:GetRolePolicy",
                "iam:DeleteUserPolicy",
                "iam:DeleteRolePolicy"
            ],
            "Resource": "*"
        }
    ]
}
```

**RDS Security Hardening:**
```json
{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Effect": "Allow",
            "Action": [
                "rds:DescribeDBInstances",
                "rds:DescribeDBClusters",
                "rds:ModifyDBInstance",
                "rds:ModifyDBCluster",
                "rds:CreateDBSnapshot",
                "rds:CreateDBClusterSnapshot",
                "ec2:DescribeSecurityGroups",
                "ec2:RevokeSecurityGroupIngress"
            ],
            "Resource": "*"
        }
    ]
}
```

### Testing Strategy

#### Pre-Production Testing
1. **Create test environment:** Deploy to isolated AWS account
2. **Use sample resources:** Create test instances, databases, policies
3. **Validate functionality:** Ensure each function works as expected
4. **Check safety mechanisms:** Verify backup creation, rollback procedures
5. **Performance testing:** Monitor execution times and memory usage

#### Production Rollout
1. **Gradual deployment:** Start with less critical functions
2. **Monitor closely:** Watch CloudWatch logs and metrics
3. **Team communication:** Notify relevant teams before major changes
4. **Rollback plan:** Have procedures to disable functions if needed
5. **Documentation:** Update runbooks and incident response procedures


## Reports and Output

All security functions automatically generate detailed reports stored in S3 for audit trails and analysis:

<table>
  <tr>
    <th>Report Type</th>
    <th>S3 Path</th>
    <th>Content</th>
  </tr>
  <tr>
    <td><strong>Prowler Scans</strong></td>
    <td><code>s3://<bucket>/reports/<timestamp>/</code></td>
    <td>HTML security assessment reports</td>
  </tr>
  <tr>
    <td><strong>ScoutSuite Scans</strong></td>
    <td><code>s3://<bucket>/scout-reports/<timestamp>/</code></td>
    <td>Multi-cloud security audit findings</td>
  </tr>
  <tr>
    <td><strong>Trusted Advisor</strong></td>
    <td><code>s3://<bucket>/trusted-advisor-report-<timestamp>.json</code></td>
    <td>AWS native security recommendations</td>
  </tr>
  <tr>
    <td><strong>IAM Policy Hardening</strong></td>
    <td><code>s3://<bucket>/iam-hardening-report-<timestamp>.json</code></td>
    <td>Policy modifications and removed permissions</td>
  </tr>
  <tr>
    <td><strong>RDS Security Hardening</strong></td>
    <td><code>s3://<bucket>/rds-security-report-<timestamp>.json</code></td>
    <td>Database security improvements and snapshots</td>
  </tr>
  <tr>
    <td><strong>Resource Cleanup</strong></td>
    <td><code>s3://<bucket>/resource-cleanup-report-<timestamp>.json</code></td>
    <td>Deleted resources and cost savings calculations</td>
  </tr>
  <tr>
    <td><strong>SOC 2 Compliance</strong></td>
    <td><code>s3://<bucket>/soc2-compliance-report-<timestamp>.json</code></td>
    <td>Control compliance status and remediation steps</td>
  </tr>
  <tr>
    <td><strong>GDPR Data Protection</strong></td>
    <td><code>s3://<bucket>/gdpr-compliance-report-<timestamp>.json</code></td>
    <td>PII exposure findings and privacy compliance</td>
  </tr>
</table>

### Report Analysis 

#### Quick Status Dashboard (CloudWatch)
```bash
# Create custom dashboard for security metrics
aws cloudwatch put-dashboard --dashboard-name "Security-Automation-Dashboard" \
  --dashboard-body file://dashboard-config.json
```

#### Report Aggregation Script
```python
# Combine reports for executive summary
import boto3
import json
from datetime import datetime, timedelta

def generate_weekly_security_summary():
    s3 = boto3.client('s3')
    
    # Aggregate findings from all security reports
    compliance_score = calculate_overall_compliance()
    cost_savings = aggregate_cleanup_savings()
    security_improvements = count_remediation_actions()
    
    summary = {
        'week_ending': datetime.now().isoformat(),
        'overall_compliance_score': compliance_score,
        'monthly_cost_savings': cost_savings,
        'security_actions_taken': security_improvements,
        'recommendations': generate_executive_recommendations()
    }
    
    return summary
```

## Getting the Most Value

### Start Small, Scale Smart
1. **Week 1:** Deploy Security Group Remediation for immediate threat response
2. **Week 2:** Add EBS Volume Encryption for data protection
3. **Week 3:** Enable Unused Resource Cleanup for cost savings
4. **Month 1:** Implement compliance functions (SOC 2, GDPR) for audit readiness

### Key Success Metrics
- **Security Posture:** Track compliance scores over time
- **Cost Optimization:** Monitor monthly savings from resource cleanup  
- **Operational Efficiency:** Measure reduction in manual security tasks
- **Audit Readiness:** Assess time saved during compliance assessments

### Common Pitfalls to Avoid
**Running all functions immediately** - Start gradual deployment  
**Ignoring test environments** - Always validate in non-production first  
**Skipping monitoring setup** - CloudWatch alarms are essential  
**Missing team coordination** - Communicate changes to affected teams  
**Forgetting backup verification** - Ensure safety mechanisms work properly  


