import boto3

ec2 = boto3.client('ec2')
sns = boto3.client('sns')

MAX_VOLUME_SIZE = 30 
SNS_TOPIC_ARN = "arn:aws:sns:xxxxxxxxx"

def lambda_handler(event, context):
    instance_id = event['detail']['resourceId']
    print(f"Checking instance: {instance_id}")
    
    response = ec2.describe_instances(InstanceIds=[instance_id])
    for reservation in response['Reservations']:
        for instance in reservation['Instances']:
            for volume in instance.get('BlockDeviceMappings', []):
                volume_id = volume['Ebs']['VolumeId']
                volume_info = ec2.describe_volumes(VolumeIds=[volume_id])
                size = volume_info['Volumes'][0]['Size']
                
                if size > MAX_VOLUME_SIZE:
                    print(f"Volume {volume_id} is oversized: {size} GiB")
                    sns.publish(
                        TopicArn=SNS_TOPIC_ARN,
                        Message=f"Volume {volume_id} attached to instance {instance_id} is {size} GiB, exceeding the limit of {MAX_VOLUME_SIZE} GiB.",
                        Subject="Oversized EBS Volume Detected"
                    )
