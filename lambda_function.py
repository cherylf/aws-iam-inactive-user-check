import boto3
from botocore.exceptions import ClientError
from botocore.config import Config
import datetime
import fnmatch
import json
import os
import re
import logging
from delete_user import delete_user


logger = logging.getLogger()
logging.basicConfig(
    format="[%(asctime)s] %(levelname)s [%(module)s.%(funcName)s:%(lineno)d] %(message)s", datefmt="%H:%M:%S"
)
logger.setLevel(os.getenv('log_level', logging.INFO))

# Configure boto retries
BOTO_CONFIG = Config(retries=dict(max_attempts=5))

# Define the default resource to report to Config Rules
DEFAULT_RESOURCE_TYPE = 'AWS::IAM::User'

CONFIG_ROLE_TIMEOUT_SECONDS = 900

# Set to True to get the lambda to assume the Role attached on the Config service (useful for cross-account).
ASSUME_ROLE_MODE = False

# Evaluation strings for Config evaluations
COMPLIANT = 'COMPLIANT'
NON_COMPLIANT = 'NON_COMPLIANT'


# This gets the client after assuming the Config service role either in the same AWS account or cross-account.
def get_client(service, execution_role_arn):
    if not ASSUME_ROLE_MODE:
        return boto3.client(service)
    credentials = get_assume_role_credentials(execution_role_arn)
    return boto3.client(service, aws_access_key_id=credentials['AccessKeyId'],
                        aws_secret_access_key=credentials['SecretAccessKey'],
                        aws_session_token=credentials['SessionToken'],
                        config=BOTO_CONFIG
                        )


def get_assume_role_credentials(execution_role_arn):
    sts_client = boto3.client('sts')
    try:
        assume_role_response = sts_client.assume_role(RoleArn=execution_role_arn,
                                                      RoleSessionName="configLambdaExecution",
                                                      DurationSeconds=CONFIG_ROLE_TIMEOUT_SECONDS)
        return assume_role_response['Credentials']
    except ClientError as ex:
        if 'AccessDenied' in ex.response['Error']['Code']:
            ex.response['Error']['Message'] = "AWS Config does not have permission to assume the IAM role."
        else:
            ex.response['Error']['Message'] = "InternalError"
            ex.response['Error']['Code'] = "InternalError"
        raise ex


# Validates user pathname whitelist as passed via AWS Config parameters and returns a list of comma separated patterns.
def validate_whitelist(unvalidated_user_pattern_whitelist):
    # Names of users, groups, roles must be alphanumeric, including the following common
    # characters: plus (+), equal (=), comma (,), period (.), at (@), underscore (_), and hyphen (-).
    valid_character_regex = '^[-a-zA-Z0-9+=,.@_/|*]+'

    if not unvalidated_user_pattern_whitelist:
        return None

    regex = re.compile(valid_character_regex)
    if not regex.search(unvalidated_user_pattern_whitelist):
        raise ValueError("[Error] Provided whitelist has invalid characters")

    return unvalidated_user_pattern_whitelist.split('|')


# This uses Unix filename pattern matching (as opposed to regular expressions), as documented here:
# https://docs.python.org/3.7/library/fnmatch.html.  Please note that if using a wildcard, e.g. "*", you should use
# it sparingly/appropriately.
# If the username matches the pattern, then it is whitelisted
def is_whitelisted_user(user_name, pattern_list):
    if not pattern_list:
        return False
    # If user_name matches pattern, then return True, else False
    for pattern in pattern_list:
        if fnmatch.fnmatch(user_name, pattern):
            # whitelisted
            logger.info(f"{user_name} is whitelisted")
            return True

    # not whitelisted
    return False

# Quarantine inactive user by removing password and deactivating access keys
def quarantine_inactive_user(client, user_name):
    # Remove password
    try:
        response = client.delete_login_profile(
            UserName=user_name
        )
    except ClientError as ex:
        if 'AccessDenied' in ex.response['Error']['Code']:
            ex.response['Error']['Message'] = "Lambda Execution Role does not have permission to delete user password."
            raise ex
        elif ex.response['Error']['Code'] == 'NoSuchEntity':
            # user has no password
            pass
            logger.info(f"{user_name} does not have password")
        else:
            ex.response['Error']['Message'] = "InternalError"
            ex.response['Error']['Code'] = "InternalError"
            raise ex
    else:
        logger.info(f"Deleted password for {user_name}")
    
    # Deactivate access keys
    try:
        response = client.list_access_keys(
            UserName=user_name
        )
    except ClientError as ex:
        if 'AccessDenied' in ex.response['Error']['Code']:
            ex.response['Error']['Message'] = "Lambda Execution Role does not have permission to list access keys."
            raise ex
        elif ex.response['Error']['Code'] == 'NoSuchEntity':
            # user has no access keys
            pass
            logger.info(f"{user_name} does not have access keys")
        else:
            ex.response['Error']['Message'] = "InternalError"
            ex.response['Error']['Code'] = "InternalError"
            raise ex
    else:
        if len(response['AccessKeyMetadata']):
            for key in response['AccessKeyMetadata']:
                response = client.update_access_key(
                    UserName=user_name,
                    AccessKeyId=key['AccessKeyId'],
                    Status='Inactive'
                )
                logger.info(f"Deactivated {key['AccessKeyId']} for {user_name}")

# Form an evaluation as a dictionary. Suited to report on scheduled rules.  More info here:
# https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/config.html#ConfigService.Client.put_evaluations
def build_evaluation(resource_id, compliance_type, notification_creation_time, resource_type=DEFAULT_RESOURCE_TYPE, annotation=None):
    evaluation = {}
    if annotation:
        evaluation['Annotation'] = annotation
    evaluation['ComplianceResourceType'] = resource_type
    evaluation['ComplianceResourceId'] = resource_id
    evaluation['ComplianceType'] = compliance_type
    evaluation['OrderingTimestamp'] = notification_creation_time
    return evaluation

# Determine if any users were used to make an AWS request
def determine_last_used(client, user_name, user_pw_last_used, min_age_in_days, max_age_in_days, notification_creation_time):

    last_used_date = user_pw_last_used

    days_unused = (datetime.datetime.now() - last_used_date.replace(tzinfo=None)).days

    if min_age_in_days < days_unused < max_age_in_days:
        compliance_result = NON_COMPLIANT
        reason = f"Was used {days_unused} days ago"
        logger.info(f"To Quarantine: {user_name} has not been used for {days_unused} days")
        quarantine_inactive_user(client, user_name)
            
        return build_evaluation(user_name, compliance_result, notification_creation_time, resource_type=DEFAULT_RESOURCE_TYPE, annotation=reason)
    
    elif days_unused > max_age_in_days:
        compliance_result = NON_COMPLIANT
        reason = f"Was used {days_unused} days ago"
        logger.info(f"To Delete: {user_name} has not been used for {days_unused} days")
        delete_user(client, user_name)
            
        return build_evaluation(user_name, compliance_result, notification_creation_time, resource_type=DEFAULT_RESOURCE_TYPE, annotation=reason)

    compliance_result = COMPLIANT
    reason = f"Was used {days_unused} days ag"
    logger.info(f"COMPLIANT: {user_name} used {days_unused} days ago")
    return build_evaluation(user_name, compliance_result, notification_creation_time, resource_type=DEFAULT_RESOURCE_TYPE, annotation=reason)


# Returns a list of docts, each of which has authorization details of each user.  More info here:
#   https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/iam.html#IAM.Client.get_account_authorization_details
def get_user_details(iam_client):

    users_details = []
    users_list = iam_client.list_users()

    while True:
        users_details += users_list['Users']
        if 'Marker' in users_list:
            users_list = iam_client.list_users(Marker=users_list['Marker'])
        else:
            break

    return users_details


# Check the compliance of each user by determining if user last used is > than max_days_for_last_used
def evaluate_compliance(event, context):

    # Initialize our AWS clients
    iam_client = get_client('iam', event["executionRoleArn"])
    config_client = get_client('config', event["executionRoleArn"])

    # List of resource evaluations to return back to AWS Config
    evaluations = []

    # List of dicts of each user's authorization details as returned by boto3
    all_users = get_user_details(iam_client)

    # Timestamp of when AWS Config triggered this evaluation
    notification_creation_time = str(json.loads(event['invokingEvent'])['notificationCreationTime'])

    # ruleParameters is received from AWS Config's user-defined parameters
    rule_parameters = json.loads(event["ruleParameters"])
    
    # Minimum allowed days that a user can be inactive before it is quarantined
    min_days_for_last_used = int(os.environ.get('min_days_for_last_used', '90'))
    if 'min_days_for_last_used' in rule_parameters:
        min_days_for_last_used = int(rule_parameters['min_days_for_last_used'])

    # Maximum allowed days that a user can be inactive before it is deleted
    max_days_for_last_used = int(os.environ.get('max_days_for_last_used', '180'))
    if 'max_days_for_last_used' in rule_parameters:
        max_days_for_last_used = int(rule_parameters['max_days_for_last_used'])

    whitelisted_user_pattern_list = []
    if 'user_whitelist' in rule_parameters:
        whitelisted_user_pattern_list = validate_whitelist(rule_parameters['user_whitelist'])

    # Iterate over all our users.  If the password last used date of a user is < min_days_for_last_used, it is compliant
    for user in all_users:
        user_name = user['UserName']
        
        if user_name.startswith('spn'):
            compliance_result = COMPLIANT
            reason = "User is a service account"
            evaluations.append(
                build_evaluation(user_name, compliance_result, notification_creation_time, resource_type=DEFAULT_RESOURCE_TYPE, annotation=reason))
            logger.info(f"COMPLIANT: {user_name} is a service account")
        elif 'PasswordLastUsed' not in user:
            # PasswordLastUsed would be none if IAM user is a person 
            # who has never signed into the console before
            compliance_result = NON_COMPLIANT
            reason = "No record of usage"
            evaluations.append(
                build_evaluation(user_name, compliance_result, notification_creation_time, resource_type=DEFAULT_RESOURCE_TYPE, annotation=reason))
            logger.info(f"To Delete: {user_name} has never signed into the console")
            delete_user(iam_client, user_name)
        else:
            # User name does not start with 'spn' means user is a human, not an application
            # And 'PasswordLastUsed' is not None so user has signed into the console at least once
            user_path = user['Path']
            user_creation_date = user['CreateDate']
            user_pw_last_used = user['PasswordLastUsed']
            user_age_in_days = (datetime.datetime.now() - user_pw_last_used.replace(tzinfo=None)).days
            
            if is_whitelisted_user(user_name, whitelisted_user_pattern_list):
                compliance_result = COMPLIANT
                reason = "User is whitelisted"
                evaluations.append(
                    build_evaluation(user_name, compliance_result, notification_creation_time, resource_type=DEFAULT_RESOURCE_TYPE, annotation=reason))
                logger.info(f"COMPLIANT: {user_name} is whitelisted")
                continue
    
            if user_age_in_days <= min_days_for_last_used:
                compliance_result = COMPLIANT
                reason = f"User last signed in {user_age_in_days} days ago"
                evaluations.append(
                    build_evaluation(user_name, compliance_result, notification_creation_time, resource_type=DEFAULT_RESOURCE_TYPE, annotation=reason))
                logger.info(f"COMPLIANT: {user_name} - {user_age_in_days} is newer than {min_days_for_last_used} days")
                continue
    
            evaluation_result = determine_last_used(iam_client, user_name, user_pw_last_used, min_days_for_last_used, max_days_for_last_used, notification_creation_time)
            evaluations.append(evaluation_result)

    # Iterate over our evaluations 100 at a time, as put_evaluations only accepts a max of 100 evals.
    evaluations_copy = evaluations[:]
    while evaluations_copy:
        config_client.put_evaluations(Evaluations=evaluations_copy[:100], ResultToken=event['resultToken'])
        del evaluations_copy[:100]