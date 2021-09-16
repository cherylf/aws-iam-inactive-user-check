# AWS IAM Inactive User Check
Identify inactive/unused AWS IAM users and take actions accordingly

This solution is adapted from AWS blog post called "Continuously monitor unused IAM roles with AWS Config" and checks for inactive/unused IAM users, instead of roles. 

## Overview
The solution takes action according to how long the user has been inactive/unused.

A user who has been inactive for more than 90 days but less than 180 days will be quarantined i.e., delete access keys and console password. AWS Config will also mark the user as non-compliant. 

If a user has been inactive for more than or equals to 180 days, the user will be deleted immediately. 

The values of 90 days/180 days can be changed in the iam-user-last-used.yml file. Likewise, the actions to take against inactive users can be changed in the quarantine_user function and delete_user function, respectively. 

**Note**: The number of days that a user has been inactive is calculated by the following formula:
```
last_used_date = user_pw_last_used
days_unused = (datetime.datetime.now() - last_used_date.replace(tzinfo=None)).days
```
The last used date takes the value of `PasswordLastUsed` from the `list-users` AWS IAM CLI command output because `PasswordLastUsed` shows when the user last used his/her password to sign into AWS management console. 

## Exempt certain users
This solution exempt users with name starting with "spn" e.g. spn-test-user would be exempted.

Also, any users passed into the iam-user-last-used.yml CloudFormation template under the `UserPatternWhitelist` will be exempted too. 

## Deployment
1. Create Lambda Layer according to the steps given in [AWS premium support knowledge center article](https://aws.amazon.com/premiumsupport/knowledge-center/lambda-python-runtime-errors/). Make a note of the Lambda layer ARN in the output as you will need it in Step 3.
2. Package the CloudFormation template. 
```
aws cloudformation package --region <YOUR REGION> --template-file iam-user-last-used.yml \
--s3-bucket <YOUR S3 BUCKET> \
--output-template-file iam-user-last-used-transformed.yml
```
3. Launch the CloudFormation stack.
```
aws cloudformation deploy --region <YOUR REGION> --template-file iam-user-last-used-transformed.yml \
--stack-name iam-user-last-used \
--parameter-overrides NameOfSolution='iam-user-last-used' \
MaxDaysForLastUsed=270 \
RolePatternWhitelist='test-user1|test-user2' \
LambdaLayerArn='<YOUR LAMBDA LAYER ARN>' \
--capabilities CAPABILITY_NAMED_IAM
```
If you change anything in the iam-user-last-used.yml, repeat steps 1 to 3 to update your deployed CloudFormation stack. 

**Note**: If you only need to update the Lambda function code after the first deployment, you can do the following. This will update the function but not the CloudFormation stack. 
```
zip lambda_function.zip lambda_function.py delete_user.py
```
```
aws lambda update-function-code --function-name iam-user-last-used --zip-file fileb://lambda_function.zip
```
