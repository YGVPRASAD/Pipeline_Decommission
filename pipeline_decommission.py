"""
This Module is to Delete Multiple Stacks
Author: Hitachi Vantara
Contributor: Vara
Date: 18-10-2021

1. Decomission of all the foundational components in the target account.
2. Update the IPAM Dynamodb making the CIDR avilable.
"""

import sys
from os import environ
import logging
import argparse
import time
import boto3
import botocore
from boto3.dynamodb.conditions import Key
from botocore.exceptions import ClientError

LOGGER = logging.getLogger(__name__)
LOGFORMAT = "%(levelname)s: %(message)s"
LOGGER = logging.getLogger("Delete Stacks")
LOGLEVEL = environ.get("logLevel", "INFO")
logging.basicConfig(format=LOGFORMAT, level=LOGLEVEL)
LOGGER.setLevel(logging.getLevelName(LOGLEVEL))


PARSER = argparse.ArgumentParser(description="This Module decomission the target account")

PARSER.add_argument("-a", "--action", help='stack actions(delete,update)', required=True)
#PARSER.add_argument("-r", "--region", type=str, required=True)

ARGS = PARSER.parse_args()

#StackRegion = ARGS.region
StackRegion = environ['RegionName']
AccountName = environ['AccountType']
num = environ['num']


def boto3_client(resource_type, region_name, session_name):
    """
    Function to get the aws credentials
    Args:
       resource_type (str): Resource type to initilize (Ex: ec2, s3)
       session_name(obj): contains assume role object
    """
    try:
        if "role_arn" in environ:
            client = boto3.client('sts')
            response = client.assume_role(RoleArn=environ[role_arn],
                                          RoleSessionName=session_name)
            service_client = boto3.client(
                resource_type, region_name=region_name,
                aws_access_key_id=response['Credentials']['AccessKeyId'],
                aws_secret_access_key=response['Credentials']['SecretAccessKey'],
                aws_session_token=response['Credentials']['SessionToken']
                )
        else:
            service_client = boto3.client(resource_type, region_name)
    except Exception as error:
        LOGGER.info("Failed to assume the role for Account: %s", str(error))
        raise
    return service_client


def boto3_resource(resource_type, region_name, session_name):
    """
    Function to get the aws credentials
    Args:
       resource_type (str): Resource type to initilize (Ex: ec2, s3)
       session_name(obj): contains assume role object
    """
    try:
        if "role_arn" in environ:
            client = boto3.client('sts')
            response = client.assume_role(RoleArn=environ[role_arn],
                                          RoleSessionName=session_name)
            service_resource = boto3.resource(
                resource_type, region_name=region_name,
                aws_access_key_id=response['Credentials']['AccessKeyId'],
                aws_secret_access_key=response['Credentials']['SecretAccessKey'],
                aws_session_token=response['Credentials']['SessionToken']
                )
        else:
            service_resource = boto3.resource(resource_type, region_name)
    except Exception as error:
        LOGGER.info("Failed to assume the role for Account: %s", str(error))
        raise
    return service_resource


def get_vpc_cidr(account_name):
    """
    Function to get the vpc cidr from account metadata
    Args:
       account_name (str): Account name (Ex: EXSBX42)
    """
    db_resource = boto3_resource('dynamodb', 'eu-west-1', 'dbsen')
    table = db_resource.Table('NVSGISRCC-AccountMetadataDB')
    #db_resource = boto3.resource('dynamodb', 'eu-west-1', 'dbsen')
    #table = db_resource.Table('NVSGISRCC-AccountMetadataDB')
    response = table.query(KeyConditionExpression=Key('accountIdentifier').eq(account_name))
    for cidr in response['Items']:
        if cidr['vpcCidr']:
            vpc_cidr = cidr['vpcCidr']
        else:
            vpc_cidr = None
    return vpc_cidr

def stack_exists(region_name, stack_name):
    """
    Function to get the status of the stack
    Args:
       region_name (str): Region name (Ex: us-east-1)
       stack_name (str): Stack name (Ex: 'NVSGISEXSBX42-BILLING-BUDGET')
    """
    cft_client = boto3_client('cloudformation', region_name, 'cftlist')
    stacks = cft_client.list_stacks()['StackSummaries']
    for stack in stacks:
        if stack['StackStatus'] == 'DELETE_COMPLETE':
            continue
        if stack_name == stack['StackName']:
            return True
    return False

def deletebillingbudgetalarms():
    """
    Function to delete Billing Budget and Billing Alarms stacks
    """
    try:
        stack_deletion_status = []
        cft_client = boto3_client('cloudformation', 'us-east-1', 'cftlist')
        cloud_billing_stack = ['NVSGIS'+AccountName+num+'-BILLING-BUDGET',
         'NVSGIS'+AccountName+num+'-BILLING-ALARMS']
        for stack_name in cloud_billing_stack:
            if stack_exists('us-east-1', stack_name):
                cft_client.delete_stack(StackName=stack_name)
                LOGGER.info("Deleting %s", stack_name)

                waiter = cft_client.get_waiter('stack_delete_complete')
                waiter_response = waiter.wait(StackName=stack_name)
                if waiter_response is None:
                    LOGGER.info("Stack %s is deleted successfully", stack_name)
                    stack_deletion_status.append(True)
                else:
                    LOGGER.info("Deletion of stack failed")
                    stack_deletion_status.append(False)
            else:
                LOGGER.info("%s Stack Name does not exist", stack_name)
                stack_deletion_status.append(True)
        return stack_deletion_status
    except ClientError as error:
        LOGGER.info(error)
        LOGGER.info("Error Occured while deleting the stack %s", stack_name)
        return False

def deletes3bucket():
    """
    Function to delete S3 Logs stack
    """
    try:
        cftclient = boto3_client('cloudformation', StackRegion, 'cftlist')
        s3client = boto3.client('s3', StackRegion)
        s3resource = boto3.resource('s3', StackRegion)
        s3bucketnames = []
        stack_name = 'NVSGIS'+AccountName+num+'-S3-LOGS'
        if stack_exists(StackRegion, stack_name):
            cftresponse = cftclient.describe_stack_events(
                StackName=stack_name
            )
            for s3bucketname in cftresponse["StackEvents"]:
                s3bucketnames.append(s3bucketname["PhysicalResourceId"])
            LOGGER.info(s3bucketnames)
            for s3name in s3bucketnames:
                bucket = s3resource.Bucket(s3name)
                if bucket.creation_date:
                    s3response = s3client.list_objects(
                        Bucket=s3name
                    )
                    if "Contents" in s3response:
                        for objects in s3response["Contents"]:
                            obj = objects["Key"]
                            objresponse = s3client.delete_object(
                                Bucket=s3name,
                                Key=obj
                            )
                        LOGGER.info("Deleting Objects in progress")
                    else:
                        LOGGER.info("No Objects or files are Present")
                else:
                    LOGGER.info("%s bucket does not exist", s3name)
            delcftresponse = cftclient.delete_stack(
                StackName=stack_name
            )
            LOGGER.info("%s Deleting in progress", stack_name)
            waiter = cft_client.get_waiter('stack_delete_complete')
            waiter_response = waiter.wait(StackName=stack_name)
            if waiter_response is None:
                LOGGER.info("Stack %s is deleted successfully", stack_name)
            else:
                LOGGER.info("Deletion of stack failed")
        else:
            LOGGER.info("%s Stack Name does not exist", stack_name)
    except ClientError as error:
        LOGGER.info(error)

def deleteami():
    """
    Function to delete AMI
    """
    try:
        amiclient = boto3.client('ec2', StackRegion)
        amiresponse = amiclient.describe_images(
            Filters=[
                {
                    'Name': 'tag:Name',
                    'Values': [
                        'NVS*',
                    ]
                },
            ]
        )
        imageidlist = []
        for images in amiresponse["Images"]:
            imageidlist.append(images["ImageId"])
        LOGGER.info(imageidlist)
        for imageid in imageidlist:
            response = amiclient.deregister_image(
                ImageId=imageid
            )
    except ClientError as error:
        LOGGER.info(error)

def deleteconfigkmscloudtrail():
    """
    Function to delete Config, Cloudtrail and KMS stacks
    """
    try:
        stack_deletion_status = []
        ec2 = boto3_client('ec2', StackRegion, 'ec2list')
        regionlist = [region['RegionName'] for region in ec2.describe_regions()['Regions']]
        for region_name in regionlist:
            cft_client = boto3_client('cloudformation', region_name, 'cftlist')
            LOGGER.info("Region Name: %s", region_name)
            cloud_kms_stack = ['NVSGIS'+AccountName+num+'-CONFIG',
            'NVSGIS'+AccountName+num+'-CLOUDTRAIL',
            'NVSGIS'+AccountName+num+'-KMS']
            for stack_name in cloud_kms_stack:
                if stack_exists(region_name, stack_name):
                    cft_client.delete_stack(StackName=stack_name)
                    LOGGER.info("Deleting %s", stack_name)

                    waiter = cft_client.get_waiter('stack_delete_complete')
                    waiter_response = waiter.wait(StackName=stack_name)
                    if waiter_response is None:
                        LOGGER.info("Stack %s is deleted successfully", stack_name)
                        stack_deletion_status.append(True)
                    else:
                        LOGGER.info("Deletion of stack failed")
                        stack_deletion_status.append(False)
                else:
                    LOGGER.info("%s Stack Name does not exist", stack_name)
                    stack_deletion_status.append(True)
        return stack_deletion_status
    except ClientError as error:
        LOGGER.info("Error Occure in deleting the stack %s", stack_name)
        return False


def stack_deletion():
    '''
    stack deletion of each foundational component service
    '''
    ###delete stack###
    exsbx_services = ['PRIVATE-LINKS', 'CONFIG-RULES', 'S3-PLATFORM',
     'S3PUBACCESSLMF', 'ORACLE-OPTIONGROUP', 'MYSQL-OPTIONGROUP',
     'MSSQL-OPTIONGROUP', 'VPC-PEERING', 'VPC-FLOWLOG', 'VPC-SECURITYGROUPS', 'VPC']
    #EERSTD = ['EC2', 'S3', 'SG', 'IGW', 'VPC']

    try:
        cft_client = boto3_client('cloudformation', StackRegion, 'cftlist')
        stack_deletion_status = []
        for service_name in exsbx_services:
            stack_name = 'NVSGIS'+AccountName+num+'-'+service_name
            LOGGER.info("StackName of "+service_name +  stack_name)
            if service_name == 'PRIVATE-LINKS':
                deletebillingbudgetalarms()

            if service_name == 'VPC-SECURITYGROUPS':
                list_interface()
                cloudkms_status = deleteconfigkmscloudtrail()
                stack_deletion_status.extend(cloudkms_status)
                deleteami()
                deletes3bucket()

            if stack_exists(StackRegion, stack_name):
                cft_client.delete_stack(StackName=stack_name)
                LOGGER.info("Deleting %s", stack_name)
                waiter = cft_client.get_waiter('stack_delete_complete')
                waiter_response = waiter.wait(StackName=stack_name)
                if waiter_response is None:
                    LOGGER.info("Stack %s is deleted successfully", stack_name)
                    stack_deletion_status.append(True)
                else:
                    LOGGER.info("Deletion of stack failed")
                    stack_deletion_status.append(False)
            else:
                LOGGER.info("%s Stack Name does not exist", stack_name)
                stack_deletion_status.append(True)
        return stack_deletion_status
    except ClientError as error:
        LOGGER.info(error)
        LOGGER.info("Error in %s", stack_name)
        return False

def list_instances_by_vpcid_value(vpcid):
    """
    Function to get the list of instances by VPC Id
    Args:
       vpcid (str): VPC Id
    """
    try:
        ec2client = boto3.client('ec2', StackRegion)
        response = ec2client.describe_instances(
            Filters=[
                {
                    'Name': 'vpc-id',
                    'Values': [vpcid]
                }
            ]
        )
        instanceIdlist = []
        ec2namelist=[]
        for reservation in (response["Reservations"]):
            for instance in reservation["Instances"]:
                instanceIdlist.append(instance["InstanceId"])
                key = instance["Tags"]
                def search_value(name):
                    for keyval in key:
                        if name.lower() == keyval['Key'].lower():
                            return keyval['Value']

                ec2instancekey = 'Name'
                if (search_value(ec2instancekey) != None):
                    INSTANCE_NAME = search_value(ec2instancekey)
                else:
                    LOGGER.info("Item is not found")

                ec2namelist.append(INSTANCE_NAME)
        LOGGER.info(ec2namelist)
        LOGGER.info(instanceIdlist)
        instanceresponse = ec2client.terminate_instances(
            InstanceIds=instanceIdlist
        )
        time.sleep(300)
        return instanceIdlist
        return ec2namelist
    except ClientError as error:
        LOGGER.info(error)


def list_interface():
    """
    Function to get the list of interfaces
    """
    client = boto3.client('cloudformation', StackRegion)
    vpcclient = boto3.client('ec2', StackRegion)
    stack_name = 'NVSGIS'+AccountName+num+'-VPC-SECURITYGROUPS'
    try:
        if stack_exists(StackRegion, stack_name):
            describestack = client.describe_stack_resources(
                StackName=stack_name
            )
            securitygroupsids = []
            networkinterfaceids = []

            for sgids in describestack['StackResources']:
                if "sg-" in sgids:
                    securitygroupsids.append(sgids['PhysicalResourceId'])
            LOGGER.info(securitygroupsids)
            describe_sg = vpcclient.describe_security_groups(
                GroupIds=securitygroupsids
            )
            for vpcid in describe_sg['SecurityGroups']:
                LOGGER.info(vpcid["VpcId"])
                list_instances_by_vpcid_value(vpcid["VpcId"])
            for sgid in securitygroupsids:
                describe_ni = vpcclient.describe_network_interfaces(
                    Filters=[
                        {
                            'Name': 'group-id',
                            'Values': [sgid]
                        },
                    ]
                )
                for niids in describe_ni['NetworkInterfaces']:
                    networkinterfaceids.append(niids['NetworkInterfaceId'])
                    if (niids['Status']) == "in-use":
                        if (niids['InterfaceType']) == "vpc_endpoint":
                            description = niids["Description"]
                            LOGGER.info(description)
                            desc = description.split()
                            vpcendpointid = str(desc[-1])
                            LOGGER.info(vpcendpointid)
                            deletevpcendpoint = vpcclient.delete_vpc_endpoints(
                                VpcEndpointIds=[ vpcendpointid ]
                            )
                            time.sleep(300)

            LOGGER.info(networkinterfaceids)
            if not networkinterfaceids:
                LOGGER.info("Networkinterfaceids list is empty")
            else:
                for interfaceids in networkinterfaceids:
                    delete_ni = vpcclient.delete_network_interface(
                        NetworkInterfaceId=interfaceids
                    )

            return securitygroupsids
        else:
            LOGGER.info("{} Stack Name does not exist".format(stack_name))
    except ClientError as error:
        LOGGER.info(error)

def dynamodb_update():
    """
    Function to update the DynamoDB Table
    """
    try:
        dynamodb = boto3_resource('dynamodb', 'eu-west-1', 'dbsen')
        table = dynamodb.Table('NVSGISRCC-IPAM-TST-V1')
        account_name = AccountName+num
        vpc_cidr = get_vpc_cidr(account_name)
        response = table.update_item(Key={'cidr': vpc_cidr},
            UpdateExpression="SET #vpc_identifier = :v, #ritm = :r, #timestamp = :t",
            ExpressionAttributeValues={':v': "",
                ':r': "", ':t': ""},
            ExpressionAttributeNames={
                "#vpc_identifier": "vpc_identifier",
                "#ritm": "ritm",
                "#timestamp": "timestamp"
            },
            ReturnValues="UPDATED_NEW"
        )
        LOGGER.info("NVSGISRCC-IPAM-TST-V1 table has been updated successfully")
        return response
    except ClientError as error:
        LOGGER.info(error)
    return None

def main():
    '''
    Main function
    '''
    if ARGS.action == 'delete':
        state = stack_deletion()
    elif ARGS.action == 'update':
        update_response = dynamodb_update()
        LOGGER.info(update_response)
        state = [True]
    return state

if __name__ == '__main__':
    state = main()
    if False in state:
        sys.exit(1)