"""
This Module is to get the stack tags and DynamoDB items and compare with env variables
Author: Hitachi Vantara
Contributor: Vara
Date: 18-10-2021
"""
import sys
from os import environ
import logging
import argparse
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

PARSER.add_argument("-a", "--action", help='stack actions(dynamodbitems,stacktags)', required=True)
#PARSER.add_argument("-r", "--region", type=str, required=True)

ARGS = PARSER.parse_args()

#StackRegion = ARGS.region
StackRegion = environ['RegionName']
AccountName = environ['AccountType']
num = environ['num']

BillingContact = environ['BillingContact']
ClarityID = environ['ClarityID']
CostCenter = environ['CostCenter']
EmailAddress = environ['EmailAddress']
Owner = environ['Owner']
ProjectName = environ['ProjectName']
RITM = environ['RITM']


tag_dynamodb = {"billingContact": BillingContact, "clarityId": ClarityID, "costCenter": CostCenter,
 "emailAddress": EmailAddress, "owner": Owner, "projectName": ProjectName, "refRitm": RITM}
LOGGER.info(tag_dynamodb)
tag_stack = {"BillingContact": BillingContact, "ClarityID": ClarityID,
 "CostCenter": CostCenter, "Owner": Owner}
LOGGER.info(tag_stack)

def stacktag():
    """
    Function to get the stack tags
    """
    tag_status = []
    client = boto3.client('cloudformation', StackRegion)
    response = client.describe_stacks(
        StackName='NVSGIS'+AccountName+num+'-VPC'
    )
    #LOGGER.info(response)
    stack = response["Stacks"][0]["Tags"]
    LOGGER.info(stack)
    all_stack_tags = {tag['Key']: tag['Value'] for tag in stack}
    LOGGER.info(all_stack_tags)
    stack_tags = dict((k, all_stack_tags[k]) for k in ['CostCenter', 'ClarityID',
     'Owner', 'BillingContact']
                                        if k in all_stack_tags)
    LOGGER.info(stack_tags)
    if tag_stack == stack_tags:
        LOGGER.info("Input Parameters are matched with CFT Stack tags")
        tag_status.append(True)
    else:
        LOGGER.info("Input Parameters are not matched with CFT Stack tags")
        tag_status.append(False)
    return tag_status

def dynamodbitem():
    """
    Function to get the DynamoDB items
    """
    tag_status = []
    accno = AccountName+num
    dynamodb_resource = boto3.resource('dynamodb', 'eu-west-1')
    table_name = "NVSGISRCC-AccountMetadataDB"
    table = dynamodb_resource.Table(table_name)
    response = table.get_item(
        Key={
            'accountIdentifier': accno
        }
    )
    LOGGER.info(response['Item'])
    test_dict = response['Item']
    dynamodb_items = dict((k, test_dict[k]) for k in ['refRitm', 'costCenter', 'projectName',
     'clarityId', 'emailAddress', 'owner', 'billingContact']
                                        if k in test_dict)
    LOGGER.info(dynamodb_items)
    if tag_dynamodb == dynamodb_items:
        LOGGER.info("Input Parameters are matched with Account Metadata tags in Dynamodb table")
        tag_status.append(True)
    else:
        LOGGER.info("Input Parameters are not matched with Account Metadata tags in Dynamodb table")
        tag_status.append(False)
    return tag_status

def main():
    '''
    Main function
    '''
    if ARGS.action == 'dynamodbitems':
        state = dynamodbitem()
    elif ARGS.action == 'stacktags':
        state = stacktag()
    return state

if __name__ == '__main__':
    state = main()
    if False in state:
        sys.exit(1)