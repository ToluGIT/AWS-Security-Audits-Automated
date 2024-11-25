import boto3
import time

ec2 = boto3.client("ec2")

def wait_for_instance_state(instance_id, desired_state):
    """Wait until the instance reaches the desired state (e.g., stopped, running)."""
    while True:
        instance = ec2.describe_instances(InstanceIds=[instance_id])["Reservations"][0]["Instances"][0]
        current_state = instance["State"]["Name"]
        if current_state == desired_state:
            break
        print(f"Waiting for instance {instance_id} to reach state '{desired_state}', current state: '{current_state}'")
        time.sleep(5)

def lambda_handler(event, context):
    try:
        # Get all instances
        instances = ec2.describe_instances()["Reservations"]
        for reservation in instances:
            for instance in reservation["Instances"]:
                instance_id = instance["InstanceId"]

                # Get root device details
                root_device_name = instance["RootDeviceName"]
                block_devices = instance["BlockDeviceMappings"]

                # Initialize volume_id and find the root volume
                volume_id = None
                for block_device in block_devices:
                    if block_device["DeviceName"] == root_device_name:
                        volume_id = block_device["Ebs"]["VolumeId"]
                        break

                if not volume_id:
                    print(f"Instance {instance_id} does not have a root volume. Skipping...")
                    continue

                # Check if the root volume is encrypted
                volume = ec2.describe_volumes(VolumeIds=[volume_id])["Volumes"][0]
                if volume["Encrypted"]:
                    print(f"Volume {volume_id} of instance {instance_id} is already encrypted. Skipping...")
                    continue

                print(f"Volume {volume_id} of instance {instance_id} is not encrypted. Starting remediation...")

                # Step 1: Create a snapshot of the unencrypted volume
                print(f"Creating snapshot of volume {volume_id}")
                snapshot_response = ec2.create_snapshot(VolumeId=volume_id, Description="Snapshot for encryption")
                snapshot_id = snapshot_response["SnapshotId"]
                print(f"Snapshot {snapshot_id} created")

                # Wait for the snapshot to complete
                while True:
                    snapshot_status = ec2.describe_snapshots(SnapshotIds=[snapshot_id])["Snapshots"][0]["State"]
                    if snapshot_status == "completed":
                        print(f"Snapshot {snapshot_id} completed")
                        break
                    print(f"Waiting for snapshot {snapshot_id} to complete, current status: {snapshot_status}")
                    time.sleep(10)

                # Step 2: Create an encrypted volume from the snapshot
                print(f"Creating encrypted volume from snapshot {snapshot_id}")
                encrypted_volume_response = ec2.create_volume(
                    SnapshotId=snapshot_id,
                    AvailabilityZone=volume["AvailabilityZone"],
                    Encrypted=True,
                    VolumeType=volume["VolumeType"]
                )
                encrypted_volume_id = encrypted_volume_response["VolumeId"]
                print(f"Encrypted volume {encrypted_volume_id} created")

                # Wait for the encrypted volume to become available
                while True:
                    volume_status = ec2.describe_volumes(VolumeIds=[encrypted_volume_id])["Volumes"][0]["State"]
                    if volume_status == "available":
                        print(f"Encrypted volume {encrypted_volume_id} is available")
                        break
                    print(f"Waiting for encrypted volume {encrypted_volume_id} to become available, current status: {volume_status}")
                    time.sleep(10)

                # Step 3: Stop the instance
                print(f"Stopping instance {instance_id}")
                ec2.stop_instances(InstanceIds=[instance_id])
                wait_for_instance_state(instance_id, "stopped")
                print(f"Instance {instance_id} is stopped")

                # Step 4: Detach the unencrypted volume
                print(f"Detaching volume {volume_id}")
                ec2.detach_volume(VolumeId=volume_id, InstanceId=instance_id)
                while True:
                    volume_state = ec2.describe_volumes(VolumeIds=[volume_id])["Volumes"][0]["State"]
                    if volume_state == "available":
                        print(f"Volume {volume_id} detached successfully")
                        break
                    print(f"Waiting for volume {volume_id} to detach, current state: {volume_state}")
                    time.sleep(5)

                # Step 5: Attach the encrypted volume
                print(f"Attaching encrypted volume {encrypted_volume_id} to instance {instance_id}")
                ec2.attach_volume(
                    VolumeId=encrypted_volume_id,
                    InstanceId=instance_id,
                    Device=root_device_name
                )
                print(f"Encrypted volume {encrypted_volume_id} attached to instance {instance_id}")

                # Step 6: Start the instance
                print(f"Starting instance {instance_id}")
                ec2.start_instances(InstanceIds=[instance_id])
                wait_for_instance_state(instance_id, "running")
                print(f"Instance {instance_id} is running with encrypted root volume {encrypted_volume_id}")

                # Step 7: Cleanup unused resources
                # Delete the old unencrypted volume
                print(f"Deleting old volume {volume_id}")
                ec2.delete_volume(VolumeId=volume_id)
                print(f"Old volume {volume_id} deleted")

                # Delete the snapshot used to create the encrypted volume
                print(f"Deleting snapshot {snapshot_id}")
                ec2.delete_snapshot(SnapshotId=snapshot_id)
                print(f"Snapshot {snapshot_id} deleted")

        return {
            "statusCode": 200,
            "body": "Remediation completed for all instances"
        }

    except Exception as e:
        print(f"Error during remediation: {str(e)}")
        raise
