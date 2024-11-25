import boto3

ec2 = boto3.client('ec2')

def lambda_handler(event, context):
    # Extract the SG-ID and rule details from event by triggered service
    sg_id = event['detail']['requestParameters']['groupId']
    print(f"Checking security group: {sg_id}")
    
    response = ec2.describe_security_groups(GroupIds=[sg_id])
    for sg in response['SecurityGroups']:
        for permission in sg['IpPermissions']:
            for ip_range in permission.get('IpRanges', []):
                if ip_range.get('CidrIp') == '0.0.0.0/0' and permission.get('FromPort') == 22:
                    print("Found overly permissive SSH rule. Removing...")
                    #Revoke the non-compliant rule
                    ec2.revoke_security_group_ingress(
                        GroupId=sg_id,
                        IpPermissions=[permission]
                    )
                    print("Removed the overly permissive rule.")
