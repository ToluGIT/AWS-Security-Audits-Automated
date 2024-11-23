import boto3
import json
import logging
from datetime import datetime

# Set up logging
logger = logging.getLogger()
logger.setLevel(logging.INFO)

def lambda_handler(event, context):
    # AWS client setup
    support_client = boto3.client('support', region_name='us-east-1')  
    s3_client = boto3.client('s3', region_name='us-east-1')  
    bucket_name = 'trusted-advisor-reports-tid'
    
    try:
 
        response = support_client.describe_trusted_advisor_checks(language='en')
        checks = response['checks']
        
     
        results = {}
        for check in checks:
            check_id = check['id']
            check_name = check['name']
            logger.info(f"Fetching results for Trusted Advisor check: {check_name}")
            
       
            check_result = support_client.describe_trusted_advisor_check_result(
                checkId=check_id
            )
            results[check_name] = check_result['result']
        

        timestamp = datetime.utcnow().strftime('%Y-%m-%d_%H-%M-%S')
        file_name = f'trusted-advisor-report-{timestamp}.json'
        

        logger.info(f"Uploading report to S3 bucket: {bucket_name}")
        s3_client.put_object(
            Bucket=bucket_name,
            Key=file_name,
            Body=json.dumps(results),
            ContentType='application/json'
        )
        
        logger.info(f"Successfully uploaded report: {file_name}")
        return {
            'statusCode': 200,
            'body': f"Trusted Advisor report successfully uploaded to {file_name}"
        }
    
    except Exception as e:
        logger.error(f"Error: {str(e)}")
        return {
            'statusCode': 500,
            'body': f"Error: {str(e)}"
        }
