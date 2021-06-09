"""
This Module is to Delete Transit Gateway Propergation and Association Stack
Author: Hitachi Vantara
Contributor: Vara
Date: 18-10-2021
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

PARSER.add_argument("-a", "--action", help='stack actions(delete,update)', required=False)
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


def stack_exists(region_name, stack_name):
    """
    Function to get the status of the stack
    Args:
       region_name (str): Region name (Ex: us-east-1)
       stack_name (str): Stack name (Ex: 'NVSGISEXSBX42-TGW-ASSOC-PROP-TST')
    """
    cft_client = boto3_client('cloudformation', region_name, 'cftlist')
    stacks = cft_client.list_stacks()['StackSummaries']
    for stack in stacks:
        if stack['StackStatus'] == 'DELETE_COMPLETE':
            continue
        if stack_name == stack['StackName']:
            return True
    return False

def deletetransit():
    """
    Function to delete Transit Gateway Propergation and Association Stack
    """
    try:
        stack_deletion_status = []
        cft_client = boto3_client('cloudformation', StackRegion, 'cftlist')
        LOGGER.info("Region Name: %s", StackRegion)
        cloud_transit_stack = ['NVSGISDMZTST-'+AccountName+num+'-TGW-ASSOC-PROP-TST']
        for stack_name in cloud_transit_stack:
            if stack_exists(StackRegion, stack_name):
                for rotate in range(4):
                    cft_client.delete_stack(StackName=stack_name)
                    LOGGER.info("Deleting %s", stack_name)
                    time.sleep(300)
                waiter = cft_client.get_waiter('stack_delete_complete')
                waiter_response = waiter.wait(StackName=stack_name)
                if waiter_response is None:
                    LOGGER.info("Stack "+stack_name+" is deleted successfully")
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

def deletecvpne():
    """
    Function to delete DMZ Stack
    """
    try:
        stack_deletion_status = []
        cft_client = boto3_client('cloudformation', StackRegion, 'cftlist')
        LOGGER.info("Region Name: %s", StackRegion)
        cloud_transit_stack = ['NVSGISDMZTST-'+AccountName+num+'-CVPNE-TST']
        for stack_name in cloud_transit_stack:
            if stack_exists(StackRegion, stack_name):
                cft_client.delete_stack(StackName=stack_name)
                LOGGER.info("Deleting %s", stack_name)
                waiter = cft_client.get_waiter('stack_delete_complete')
                waiter_response = waiter.wait(StackName=stack_name)
                if waiter_response is None:
                    LOGGER.info("Stack "+stack_name+" is deleted successfully")
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

def main():
    '''
    Main function
    '''
    state1 = deletetransit()
    state2 = deletecvpne()
    LOGGER.info(state1)
    LOGGER.info(state2)
    return state1
    return state2

if __name__ == '__main__':
    state = main()
    if False in state:
        sys.exit(1)