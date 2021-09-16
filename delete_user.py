import boto3
from botocore.exceptions import ClientError

def delete_user(client=None, user_name=None):

  '''
  There are a number of things to delete before a user can be deleted. Refer
  to https://docs.aws.amazon.com/cli/latest/reference/client/delete-user.html 
  for more details. 
  '''
  ## Delete User Password ( DeleteLoginProfile )
  try:
    client.get_login_profile(UserName=user_name)
  except ClientError as e:
    if e.response['Error']['Code'] == 'NoSuchEntity':
      ## User has no password
      pass
    else:
      raise e
  else:
    client.delete_login_profile(UserName=user_name)


  # Delete User Access keys ( DeleteAccessKey )
  try:
    access_key = client.list_access_keys(UserName=user_name)
  except ClientError as e:
    raise e
  else:
    if (len(access_key['AccessKeyMetadata']) == 0):
      ## User has no access keys
      pass
    else:
      for key in access_key['AccessKeyMetadata']:
        client.delete_access_key(UserName=user_name, AccessKeyId=key['AccessKeyId'])


  # Delete User MFA device ( DeactivateMFADevice , DeleteVirtualMFADevice )
  try:
    mfa_device = client.list_mfa_devices(UserName=user_name)
  except ClientError as e:
    raise e
  else:
    if (len(mfa_device['MFADevices']) == 0):
      ## User has no MFA device
      pass
    else:
      for device in mfa_device['MFADevices']:
        client.deactivate_mfa_device(UserName=user_name, SerialNumber=device['SerialNumber'])
        client.delete_virtual_mfa_device(SerialNumber=device['SerialNumber'])


  # Delete User inline policies ( DeleteUserPolicy )
  try:
    paginator = client.get_paginator('list_user_policies')
    page_iterator = paginator.paginate(UserName=user_name)
  except ClientError as e:
    raise e
  else:
    for page in page_iterator:
      inline_policies = page['PolicyNames']
      if (len(inline_policies) == 0):
        ## User has no inline policies
        pass
      else:
        for policy in inline_policies:
          client.delete_user_policy(UserName=user_name, PolicyName=policy)

  # Detach User managed policies ( DetachUserPolicy )
  try:
    paginator = client.get_paginator('list_attached_user_policies')
    page_iterator = paginator.paginate(UserName=user_name)
  except ClientError as e:
    raise e
  else:
    for page in page_iterator:
      managed_policies = page['AttachedPolicies']
      if (len(managed_policies) == 0):
        ## User has no managed policies
        pass
      else:
        for policy in managed_policies:
          client.detach_user_policy(UserName=user_name, PolicyArn=policy['PolicyArn'])
  
  # Detach User Permissions Boundary ( DeleteUserPermissionsBoundary )
  try:
    iam_pb = client.delete_user_permissions_boundary(UserName=user_name)
  except ClientError as e:
    if e.response['Error']['Code'] == 'NoSuchEntity':
      ## User has no permissions boundary
      pass
    else:
      raise e
  
  # Delete User group memberships ( RemoveUserFromGroup )
  try:
    paginator = client.get_paginator('list_groups_for_user')
    page_iterator = paginator.paginate(UserName=user_name)
  except ClientError as e:
    raise e
  else:
    for page in page_iterator:
      user_groups = page['Groups']
      if (len(user_groups) == 0):
        ## User is not in any groups
        pass
      else:
        for group in user_groups:
          client.remove_user_from_group(GroupName=group['GroupName'], UserName=user_name)

  # Delete user
  try:
    client.delete_user(UserName=user_name)
  except ClientError as e:
    raise e
  else:
    print(f'Deleted {user_name}')