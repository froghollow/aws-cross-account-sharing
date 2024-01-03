""" Module to support Cross Account Roles and Policies between a Shared Account and a Trusted Account  """

import boto3
import json
import logging

class AwsAccount:
    '''
    Class that represents an IAM Account with methods to manage Roles and Policies

    # adapted from https://github.com/awsdocs/aws-doc-sdk-examples/blob/main/python/example_code/iam
    # Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
    # SPDX-License-Identifier: Apache-2.0
    '''

    def __init__( self, partition, region,account_id, profile_name):
        self.partition = partition,
        self.region = region,
        self.account_id = account_id
        self.profile_name = profile_name

        self.session = boto3.Session( 
            profile_name = profile_name,
            region_name  = region ) # ToDo Support SSM, Secrets
        
        self.iam_client = self.session.client('iam')
        self.iam_resource = self.session.resource('iam')

        self.logger = logging.getLogger(__name__)

    def create_role(self, role_name, allowed_services):
        """
        Creates a role that lets a list of specified services assume the role.

        :param role_name: The name of the role.
        :param allowed_services: The services that can assume the role.
        :return: The newly created role.
        """
        trust_policy = {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Allow",
                    "Principal": {"Service": service},
                    "Action": "sts:AssumeRole",
                }
                for service in allowed_services
            ],
        }
        try:
            role = self.iam_client.create_role(
                RoleName=role_name, AssumeRolePolicyDocument=json.dumps(trust_policy)
            )
            self.logger.info("Created role %s.", role.name)
        except ClientError:
            self.logger.exception("Couldn't create role %s.", role_name)
            raise
        else:
            return role

    def create_policy(self, name, description, policy_doc):
        """
        Creates a policy based on a JSON doc.

        :param name: The name of the policy to create.
        :param description: The description of the policy.
        :param policy_doc: JSON Policy Document that defines what actions are allowed on which resources
        :return: The newly created policy.
        """

        try:
            policy = self.iam_resource.create_policy(
                PolicyName=name,
                Description=description,
                PolicyDocument=json.dumps(policy_doc),
            )
            self.logger.info("Created policy %s.", policy.arn)
        except ClientError:
            self.logger.exception("Couldn't create policy %s.", name)
            raise
        else:
            return policy

    def attach_policy(self, role_name, policy_arn):
        """
        Attaches a managed policy to a role.

        :param role_name: The name of the role. **Note** this is the name, not the ARN.
        :param policy_arn: The ARN of the policy.

        """
        try:
            self.iam_resource.Role(role_name).attach_policy(PolicyArn=policy_arn)
            self.logger.info("Attached policy %s to role %s.", policy_arn, role_name)
        except ClientError:
            self.logger.exception("Couldn't attach policy %s to role %s.", policy_arn, role_name)
            raise
  
    def query_role_and_policy_config (self, role_name  ):
        """ 
        Query IAM Role with Attached and Inline Policies into a JSON doc

        :param role_name: The name of the role. **Note** this is the name, not the ARN.

        """
        role = self.iam_resource.Role(role_name)

        config = {
            "RoleName" : role.name,
            "RoleArn" : role.arn,
            "RoleDescription" : role.description,
            "RoleTrustPolicyDoc" : role.assume_role_policy_document,
            "AttachedPolicies" : [],
            "InlinePolicies" : []
        }
        for iam_policy in role.attached_policies.all():
            #print(iam_policy)
            config["AttachedPolicies"].append ( {
                "PolicyName" : iam_policy.policy_name,
                "PolicyArn" : iam_policy.arn,
                "Description" : iam_policy.description,
                "DefaultVersion" : iam_policy.default_version.version_id,
                "PolicyDoc" : iam_policy.default_version.document
            })
    
        for inline_policy in role.policies.all():
            config["InlinePolicies"].append ( {
                "PolicyName" : inline_policy.policy_name,
                "PolicyDoc" : inline_policy.policy_document
            }) 

        return config # json
    '''
    e.g.,
    role_name = 'ram-lab-CrossAccountLandingPadRole'
    trusted_config = trusted_acct.query_role_and_policy_config ( role_name )
    '''

    def put_managed_policy (self, policy_arn, description, policy_doc ):
        ''' Create or Update IAM Managed Policy from JSON Policy Doc '''
        try:
            response = self.iam_client.get_policy(
                PolicyArn=policy_arn
            )
            policy = response['Policy']

            response = self.iam_client.get_policy_version(
                PolicyArn=policy_arn,
                VersionId=policy['DefaultVersionId']
            )
            if response['PolicyVersion']['Document'] != policy_doc:
                response = self.iam_client.create_policy_version(
                    PolicyArn=policy_arn,
                    PolicyDocument=json.dumps(policy_doc),
                    SetAsDefault=True
                )    
            policy['DefaultVersionId'] = response['PolicyVersion']['VersionId']
            print ( f"Existing Managed Policy: {policy['Arn']}, Doc Version:, {policy['DefaultVersionId']}" )

        except self.iam_client.exceptions.NoSuchEntityException:
            policy_name = policy_arn.split('/')[-1]

            response = self.iam_client.create_policy(
                PolicyName=policy_name,
                PolicyDocument=json.dumps(policy_doc),
                Description=description
            )
            policy = response['Policy']
            print ( f"Created Managed Policy: {policy['Arn']}, Doc Version:, {policy['DefaultVersionId']}" )

            return policy
        
        '''
        e.g.,
        for iam_policy_config in shared_config['AttachedPolicies']:
            put_managed_policy( iam_policy_config['PolicyArn'], iam_policy_config['Description'], iam_policy_config['PolicyDoc'])
        '''
        
    def put_role_and_policy_config (self, config_doc ):
        ''' 
        Put IAM Role with Attached and/or Inline Policies from a JSON doc in the format produced
        by query_role_and_policy_config()
        '''
        role = self.iam_resource.create_role(
            RoleName = config_doc['RoleName'],
            AssumeRolePolicyDocument=json.dumps(config_doc['RoleTrustPolicyDoc']),
            Description = config_doc['RoleDescription']
        )
        self.logger.info(f"Created role {role.name}.")
        # ToDo -- if role it already exists ...

        for iam_policy_config in config_doc['AttachedPolicies']:
            # create policy or new verison
            policy = self.put_managed_policy( 
                iam_policy_config['PolicyArn'],
                iam_policy_config['Description'], 
                iam_policy_config['PolicyDoc'] 
            )  
            self.iam_resource.attach_policy( 
                role.name,
                policy['PolicyArn']
            )
        
        for inline_policy in config_doc['InlinePolicies']:
            self.put_role_policy( 
                RoleName=role.name,
                PolicyName=inline_policy['PolicyName'],
                PolicyDocument= json.dumps(inline_policy['PolicyDoc'])
            )

