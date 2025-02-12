<div align="center">
  <h1>AWS Security Audits Automation</h1>
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

## Prerequisites

<table>
  <tr>
    <td>✅ AWS Account with appropriate permissions</td>
    <td>✅ GitHub Actions enabled repository</td>
  </tr>
  <tr>
    <td>✅ Python 3.9+</td>
    <td>✅ AWS CLI configured with appropriate credentials</td>
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
│   ├── EBS_Volume_compliance_notification.py
│   ├── EBS_Volume_Encryption.py
│   └── SG-Remediation.py
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

1. Create an IAM role with appropriate permissions for GitHub Actions
2. Configure S3 buckets for storing security reports
3. Set up Lambda functions for remediation tasks
</details>

<details>
<summary><b>3. Lambda Functions Deployment</b></summary>
<br>
Deploy the following Lambda functions:

- EBS Volume Encryption Remediation
- EBS Volume Compliance Monitoring
- Security Group Rules Remediation
- Trusted Advisor Reporting
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

## Script Functionality

### Lambda Functions

<details>
<summary><b>1. EBS Volume Encryption (EBS_Volume_Encryption.py)</b></summary>
<br>

- Identifies EC2 instances with unencrypted root volumes
- Creates encrypted snapshots of unencrypted volumes
- Replaces unencrypted volumes with encrypted ones
- Handles the full lifecycle: stop instance → detach volume → attach encrypted volume → start instance
- Maintains data integrity throughout the encryption process
</details>

<details>
<summary><b>2. EBS Volume Compliance Notification (EBS_Volume_compliance_notification.py)</b></summary>
<br>

- Monitors EBS volumes for size compliance
- Checks against maximum volume size limit (30GB)
- Sends SNS notifications when volumes exceed the size limit
- Tracks volume attachments to EC2 instances
- Provides detailed reporting including instance ID and volume size
</details>

<details>
<summary><b>3. Security Group Remediation (SG-Remediation.py)</b></summary>
<br>

- Monitors security group changes in real-time
- Automatically detects overly permissive SSH rules (0.0.0.0/0 on port 22)
- Removes non-compliant security group rules
- Logs remediation actions for audit purposes
- Helps maintain security group compliance
</details>

## Future Enhancements

<details>
<summary><b>New Scripts</b></summary>
<br>

Security Features:
- IAM user access key rotation automation
- S3 bucket policy compliance checker
- CloudTrail logging validator
- VPC flow logs enablement checker
- KMS key rotation validator
- AWS Config rule automation
</details>

<details>
<summary><b>Existing Script Enhancements</b></summary>
<br>

Technical Improvements:
- Adding support for multiple AWS regions in EBS encryption
- Expanding security group remediation to cover additional ports
- Enhanced reporting capabilities for volume compliance
- Integration with additional notification channels
- Support for custom compliance rules
- Advanced filtering and tagging support
- Backup verification for encrypted volumes
- Multi-account support for all functions
</details>

## Reports

Security scan reports are automatically uploaded to S3 with the following structure:

<table>
  <tr>
    <th>Report Type</th>
    <th>S3 Path</th>
  </tr>
  <tr>
    <td>Prowler</td>
    <td><code>s3://<bucket>/reports/<timestamp>/</code></td>
  </tr>
  <tr>
    <td>ScoutSuite</td>
    <td><code>s3://<bucket>/scout-reports/<timestamp>/</code></td>
  </tr>
  <tr>
    <td>Trusted Advisor</td>
    <td><code>s3://<bucket>/trusted-advisor-report-<timestamp>.json</code></td>
  </tr>
</table>
      
---
<div align="center">
  <p>Made with ❤️ for AWS Security</p>
</div>
