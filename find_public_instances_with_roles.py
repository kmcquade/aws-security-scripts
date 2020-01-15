#!/usr/bin/env python
"""
find_public_instances_with_roles.py: Finds public EC2 instances with instance profiles and stores the results in files.
"""

import click
from policy_sentry.util.arns import get_resource_path_from_arn
import json
import os
from pathlib import Path
from common.awsinfo import get_list_of_aws_profiles, get_aws_account_id, get_all_regions, is_aws_managed_policy
from common.login import login
from botocore.exceptions import ClientError

HOME = str(Path.home())


@click.command(
    short_help='find all Ec2 instances that are exposed to the internet and have IAM roles attached.'
)
@click.option(
    '--credentials-file',
    required=False,
    default=HOME + '/.aws/credentials',
    type=click.Path(exists=True),
    help='AWS shared credentials file. Defaults to ~/.aws/credentials'
)
@click.option(
    '--recursive',
    required=False,
    default=False,
    is_flag=True,
    help='Use this flag to download from **all** accounts listed in the credentials file. Defaults to false.'
)
@click.option(
    '--profile',
    required=False,
    type=str,
    default='default',
    help='To authenticate to AWS and scan just one profile.'
)
@click.option(
    '--all-regions',
    required=False,
    default=False,
    is_flag=True,
    help='Audit all regions, not just US regions. This will be VERY slow if you are scanning a lot of accounts.'
)
@click.option(
    '--output',
    type=click.Path(exists=True),
    default=os.getcwd() + '/reports/accounts/',
    help='The directory where you will store the report output. Defaults to ./reports/accounts/'
)
def find_public_instances_with_roles(credentials_file, recursive, profile, output, all_regions):
    if recursive:
        initial_profiles = get_list_of_aws_profiles(credentials_file)
        profiles = list(dict.fromkeys(initial_profiles))  # remove duplicates
        for profile in profiles:
            create_public_privileged_instances_report(profile, output, all_regions)
    else:
        create_public_privileged_instances_report(profile, output, all_regions)


def create_public_privileged_instances_report(profile, output_dir, audit_all_regions):
    ec2_findings = EC2Findings()
    sts_session = login(profile, 'sts', 'us-east-1')
    account_alias = profile.replace(' ', '')
    try:
        account_id = get_aws_account_id(sts_session)
        ec2_findings.add_account(account_id)
        all_regions = get_all_regions(audit_all_regions)
        print("Looking for Public EC2 Instances with Instance Profiles...")
        print(f"Account: {account_id}")
        for region in all_regions:
            print(f"Region: {region}")
            find_public_instances_with_iam_profiles(profile, account_id, region, ec2_findings)
        with open(output_dir + '/' + account_alias + '.json', 'w') as json_file:
            all_findings = ec2_findings.get_all_accounts()
            json.dump(all_findings, json_file, indent=2)
        print(f"Report for Account ID {account_id} saved to {output_dir}/{account_alias}.json")
    except AttributeError as a_e:
        print(a_e)


def find_public_instances_with_iam_profiles(profile_name, account_id, region, ec2_findings):
    """
    Run ec2:DescribeInstances, and if there is an IamInstanceProfile and PublicIpAddress attached,
    add the associated metadata to the findings.
    """
    all_recorded_accounts = ec2_findings.get_all_accounts()
    if account_id not in all_recorded_accounts:
        ec2_findings.add_account(account_id)

    ec2_client = login(profile_name, 'ec2', region)
    iam_client = login(profile_name, 'iam', region)
    response = ec2_client.describe_instances()
    if response['Reservations']:
        for r in response['Reservations']:
            if r['Instances']:
                for i in r['Instances']:
                    if 'IamInstanceProfile' in i.keys() and 'PublicIpAddress' in i.keys():
                        instance_profile_name = get_resource_path_from_arn(i['IamInstanceProfile']['Arn'])
                        instance_id = i['InstanceId']
                        public_ip_address = i['PublicIpAddress']
                        try:
                            instance_profile_response = iam_client.get_instance_profile(
                                InstanceProfileName=instance_profile_name
                            )
                            try:
                                security_groups = []
                                role_name = instance_profile_response['InstanceProfile']['Roles'][0]['RoleName']
                                assume_role_policy_document = \
                                    instance_profile_response['InstanceProfile']['Roles'][0]['AssumeRolePolicyDocument']

                                ec2_instance = {
                                    'instance_id': i['InstanceId'],
                                    'public_ip_address': i['PublicIpAddress']
                                }
                                # Get the security groups
                                for sg in i['SecurityGroups']:
                                    try:
                                        response = ec2_client.describe_security_groups(GroupIds=[sg['GroupId']])
                                        ingress_rules = []
                                        egress_rules = []
                                        for grp in response['SecurityGroups']:
                                            if 'IpPermissions' in grp:
                                                if len(grp['IpPermissions']) > 0:
                                                    ingress_rules.append(grp['IpPermissions'])
                                            if 'IpPermissionsEgress' in grp:
                                                if len(grp['IpPermissionsEgress']) > 0:
                                                    egress_rules.append(grp['IpPermissionsEgress'])
                                        this_security_group = {
                                            'security_group_id': sg['GroupId'],
                                            'security_group_name': sg['GroupName'],
                                            'ingress_rules': ingress_rules,
                                            'egress_rules': egress_rules
                                        }
                                        security_groups.append(this_security_group)
                                    except ClientError as e:
                                        print(e)

                                    # print()

                                policies = get_managed_policy_documents_for_iam_role(role_name, iam_client)
                                ec2_findings.add_privileged_instance_finding(account_id, region, role_name, policies,
                                                                             assume_role_policy_document, ec2_instance,
                                                                             security_groups)
                                print(f"FOUND! Instance: {instance_id}, Public IP: {public_ip_address}, "
                                      f"Role: {role_name}")
                            except IndexError as i_e:
                                print(i_e)
                        except iam_client.exceptions.NoSuchEntityException as ns_ee:
                            print(ns_ee)


def get_managed_policy_documents_for_iam_role(iam_role_name, iam_client_session, path_prefix='/'):
    """
    https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/iam.html#IAM.Client.list_attached_role_policies
    Given an IAM Role name, return a list of IAM policies and the associated metadata

    Example data:
    [
        {
            'policy_name': policy_name,
            'policy_arn': policy_arn,
            'default_version_id': default_version_id,
            'aws_managed': True | False,
            'policy_document': policy_document
        }
    ]
    """
    policy_arn_list = []
    policy_list = []
    response = iam_client_session.list_attached_role_policies(
        RoleName=iam_role_name,
        PathPrefix=path_prefix,
    )
    for attached_policy in response['AttachedPolicies']:
        policy_arn_list.append(attached_policy['PolicyArn'])

    for policy_arn in policy_arn_list:
        response = iam_client_session.get_policy(
            PolicyArn=policy_arn
        )
        policy_name = response['Policy']['PolicyName']
        # policy_id = response['Policy']['PolicyId']
        policy_arn = response['Policy']['Arn']
        default_version_id = response['Policy']['DefaultVersionId']

        # Get the policy contents
        policy_version_response = iam_client_session.get_policy_version(
            PolicyArn=policy_arn,
            VersionId=default_version_id
        )
        policy_document = policy_version_response['PolicyVersion']['Document']

        aws_managed = is_aws_managed_policy(policy_arn)

        policy_list.append({
            'policy_name': policy_name,
            'policy_arn': policy_arn,
            'default_version_id': default_version_id,
            'aws_managed': aws_managed,
            'policy_document': policy_document
        })

    return policy_list


def get_inline_policy_documents_for_iam_role(iam_role_name, iam_client_session):
    """
    list_role_policies()
    https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/iam.html#IAM.Client.list_role_policies
    """

    response = iam_client_session.list_role_policies(
        RoleName=iam_role_name,
    )
    inline_policy_name_list = []
    for policy_name in response:
        inline_policy_name_list.append(policy_name)
    return inline_policy_name_list


class EC2Findings:
    """
    {
        "012345678901": {
            "us-east-1": {
                "arn:aws:iam::012345678901:instance-profile/my_instance_profile": {
                    "instances": [
                        { 'instance_id': 'i-01234567e89012ea2', 'public_ip_address': '104.83.225.8' }
                        { 'instance_id': 'i-01234567e89012ea3', 'public_ip_address': '104.83.225.8' }
                    ]
                }
            },
        }
    }
    """
    accounts = {}

    def __init__(self):
        self.accounts = {}

    def add_account(self, account_id):
        # Set it to empty
        if account_id not in self.accounts.keys():
            account = {account_id: {}}
            self.accounts.update(account)

    def add_region(self, account_id, region):
        if account_id not in self.accounts.keys():
            self.add_account(account_id)
        if region not in self.accounts[account_id].keys():
            self.accounts[account_id][region] = []

    def add_privileged_instance_finding(self, account_id, region, role_name, policies, assume_role_policy_document,
                                        instances, security_groups):
        # AssumeRole contents?
        self.add_account(account_id)
        self.add_region(account_id, region)
        role_entry = {
            'role_name': role_name,
            'instances': [instances],
            'policies': policies,
            'security_groups': security_groups
        }
        # roles_in_region means "Instance profiles active in region"
        roles_in_region = self.get_role_names_per_region(account_id, region)

        if roles_in_region is None or role_name not in roles_in_region:
            self.accounts[account_id][region].append(role_entry)
        else:
            # Just add the instances
            for entry in self.accounts[account_id][region]:
                if entry['role_name'] == role_name:
                    entry['instances'].append(instances)

    def get_all_accounts(self):
        return self.accounts

    def get_role_names_per_region(self, account_id, region):
        role_names = []
        try:
            for entry in self.accounts[account_id][region]:
                role_names.append(entry['role_name'])
                return role_names
        except KeyError as k_e:
            print(k_e)


if __name__ == '__main__':
    find_public_instances_with_roles()
