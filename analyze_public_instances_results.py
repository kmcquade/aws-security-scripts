#!/usr/bin/env python
"""
analyze_public_instances_results.py: Analyzes the results files from the `find_public_instances.py` report. It generates report summaries in `results.csv` and `results.json` files.
"""
import csv
import json
import os
import click
from os.path import isfile, isdir
from pathlib import Path
from policy_sentry.util.actions import get_service_from_action
from policy_sentry.analysis.analyze import analyze_by_access_level
from policy_sentry.shared.constants import DATABASE_FILE_PATH
from policy_sentry.shared.database import connect_db
from policy_sentry.util.file import list_files_in_directory
from policy_sentry.command.initialize import initialize
from common.awsinfo import is_aws_managed_policy

HOME = str(Path.home())
if isfile(HOME + '/.policy_sentry/aws.sqlite3'):
    print("Policy Sentry database found. Continuing...")
else:
    print("NOTE: Policy Sentry database not found. Initializing...")
    initialize()
db_session = connect_db(DATABASE_FILE_PATH)


@click.command(
    short_help='analyze the JSON formatted results of the find_public_instances_with_roles script.'
)
@click.option(
    '--input-file',
    type=click.Path(exists=True),
    help='Path to the JSON file you want to analyze, or a directory of those files. '
         'Defaults to the directory "./reports/accounts/"',
    default=os.getcwd() + '/reports/accounts/'
)
@click.option(
    '--output',
    # required=False,
    type=click.Path(exists=True),
    default=os.getcwd() + '/reports/',
    help='Directory to store the reports. Defaults to "/reports/"'
)
def analyze_public_instances_results(input_file, output):
    all_results = []
    if isfile(input_file):
        account_alias, account_id, results = analyze_file(input_file)
        print(json.dumps(results, indent=2))
    elif isdir(input_file):
        file_list = list_files_in_directory(input_file)
        for file in file_list:
            if file.endswith(".json"):
                account_alias, account_id, results = analyze_file(input_file + file)
                this_result = {
                    'account_id': account_id,
                    'account_alias': account_alias,
                    'results': results
                }
                all_results.append(this_result)
    if isfile(output):
        with open(output, 'w') as results_file:
            json.dump(all_results, results_file, indent=4)
        write_csv_report(all_results, output + 'results.csv')
    elif isdir(output):
        with open(output + 'results.json', 'w') as results_file:
            json.dump(all_results, results_file, indent=4)
        write_csv_report(all_results, output + 'results.csv')


def analyze_file(input):
    with open(input, 'r') as json_file:
        datastore = json.load(json_file)
    base_name = os.path.basename(input)
    base_name_no_extension = os.path.splitext(os.path.basename(base_name))[0]
    account_id, roles_with_public_access = get_list_of_roles_in_account_with_public_access(base_name_no_extension,
                                                                                           datastore)
    account_alias = base_name_no_extension
    return account_alias, account_id, roles_with_public_access


def get_list_of_roles_in_account_with_public_access(account_id, json_data):
    """
    Example results:
    [
        {
            "role_name": "SomeRole",
            "public_ips": 3,
            "policies_count": 3,
            "aws_managed_policies_count": 3,
            "aws_managed_policies": [
                "arn:aws:iam::aws:policy/AmazonEKSWorkerNodePolicy",
                "arn:aws:iam::aws:policy/AmazonEC2ContainerRegistryReadOnly",
                "arn:aws:iam::aws:policy/AmazonEKS_CNI_Policy",
                "arn:aws:iam::aws:policy/AmazonS3FullAccess"
            ],
            "custom_policies": [
                "arn:aws:iam::012345678901:policy/Tupac-Is",
                "arn:aws:iam::012345678901:policy/StillAlive"
            ]
        },
        {
            "role_name": "SomeRole2",
            "public_ips": 4,
            "policies_count": 1,
            "aws_managed_policies_count": 1,
            "aws_managed_policies": [
                "arn:aws:iam::aws:policy/AmazonS3FullAccess"
            ],
            "customer_managed_policies": [
                "arn:aws:iam::0123456789012:policy/JEpstein",
                "arn:aws:iam::012345678901:policy/DidntHangHimself"
            ]
        }
    ]
    """
    roles = []
    aws_managed_policies = []
    customer_managed_policies = []
    list_of_account_ids = json_data.keys()  # should only be one item; lazy messy quick fix
    for account_id in list_of_account_ids:
        for region in json_data[account_id]:
            for role in json_data[account_id][region]:
                services_role_can_modify = []
                aws_managed_policies_count = 0
                role_permissions_management_abilities = []
                role_write_abilities = []
                for policy in role['policies']:
                    if is_aws_managed_policy(policy['policy_arn']) and policy['policy_arn'] not in aws_managed_policies:
                        aws_managed_policies_count += 1
                        aws_managed_policies.append(policy['policy_arn'])
                        permissions_management_abilities = has_permissions_management_access(policy['policy_document'])
                        if permissions_management_abilities:
                            role_permissions_management_abilities.extend(permissions_management_abilities)
                        write_abilities = has_write_access(policy['policy_document'])
                        if write_abilities:
                            role_write_abilities.extend(write_abilities)
                        services_role_can_modify = get_service_prefixes_role_can_modify(policy['policy_document'])
                    elif not is_aws_managed_policy(policy['policy_arn']) and policy['policy_arn'] not in \
                            customer_managed_policies:
                        customer_managed_policies.append(policy['policy_arn'])
                        permissions_management_abilities = has_permissions_management_access(policy['policy_document'])
                        if permissions_management_abilities:
                            role_permissions_management_abilities.extend(permissions_management_abilities)
                        write_abilities = has_write_access(policy['policy_document'])
                        if write_abilities:
                            role_write_abilities.extend(write_abilities)
                        services_role_can_modify = get_service_prefixes_role_can_modify(policy['policy_document'])
                    # else:
                    #     pass
                aws_managed_policies.sort()
                customer_managed_policies.sort()
                services_role_can_modify.sort()
                role_permissions_management_abilities.sort()
                role_write_abilities.sort()
                this_role = {
                    'role_name': role['role_name'],
                    'public_ips': len(role['instances']),  # The number of public IP addresses with that role
                    'policies_count': len(role['policies']),
                    'aws_managed_policies_count': aws_managed_policies_count,
                    'aws_managed_policies': aws_managed_policies,
                    'customer_managed_policies': customer_managed_policies,
                    'services_role_can_modify': services_role_can_modify,
                    'write_abilities': role_write_abilities,
                    'permissions_management_abilities': role_permissions_management_abilities
                }
                roles.append(this_role)
    return account_id, roles


def write_csv_report(data, results_summary_file):
    with open(results_summary_file, 'w') as csvfile:
        fieldnames = ['account_id', 'account_alias', 'role_name', 'aws_managed_policies_count', 'public_ip_count',
                      'policies_count', 'permissions_management_abilities_count', 'write_abilities_count',
                      'services_role_can_modify_count', 'aws_managed_policies', 'customer_managed_policies',
                      'services_role_can_modify', 'write_abilities', 'permissions_management_abilities']
        writer = csv.DictWriter(csvfile, fieldnames=fieldnames, dialect='excel')

        writer.writeheader()

        for account in data:
            account_id = account['account_id']
            account_alias = account['account_alias']
            for role in account['results']:
                role_name = role['role_name']
                public_ip_count = role['public_ips']
                aws_managed_policies_count = role['aws_managed_policies_count']
                policies_count = role['policies_count']
                write_abilities_count = str(len(role['write_abilities']))
                permissions_management_abilities_count = str(len(role['permissions_management_abilities']))
                services_role_can_modify_count = str(len(role['services_role_can_modify']))
                aws_managed_policies = role['aws_managed_policies']
                customer_managed_policies = role['customer_managed_policies']
                services_role_can_modify = role['services_role_can_modify']
                write_abilities = role['write_abilities']
                permissions_management_abilities = role['permissions_management_abilities']
                aws_managed_policies_result = '; '
                customer_managed_policies_result = '; '
                services_role_can_modify_result = '; '
                write_abilities_result = '; '
                permissions_management_abilities_result = '; '

                writer.writerow({
                    'account_id': account_id,
                    'account_alias': account_alias,
                    'role_name': role_name,
                    'aws_managed_policies_count': aws_managed_policies_count,
                    'public_ip_count': public_ip_count,
                    'policies_count': policies_count,
                    'permissions_management_abilities_count': permissions_management_abilities_count,
                    'write_abilities_count': write_abilities_count,
                    'services_role_can_modify_count': services_role_can_modify_count,
                    'aws_managed_policies': aws_managed_policies_result.join(aws_managed_policies),
                    'customer_managed_policies': customer_managed_policies_result.join(customer_managed_policies),
                    'services_role_can_modify': services_role_can_modify_result.join(services_role_can_modify),
                    'write_abilities': write_abilities_result.join(write_abilities),
                    'permissions_management_abilities': permissions_management_abilities_result.join(permissions_management_abilities)
                })
            print(f"Finished writing data for account {account_id}")


def has_permissions_management_access(policy):
    """
    Given a policy as a dictionary, determine if the policy grants Permissions management access.
    If so, return a list of IAM Actions that grant Permissions management access level. If not, return false.
    """

    permissions_management_actions = analyze_by_access_level(policy, db_session, "permissions-management") # TODO: Test this.
    if len(permissions_management_actions) > 0:
        return permissions_management_actions
    else:
        return []


def has_write_access(policy):
    """
    Given a policy as a dictionary, determine if the policy grants Permissions management access.
    If so, return a list of IAM Actions that grant Permissions management access level. If not, return false.
    """

    permissions_management_actions = analyze_by_access_level(policy, db_session, "permissions-management")
    if len(permissions_management_actions) > 0:
        return permissions_management_actions
    else:
        return []


def get_service_prefixes_role_can_modify(policy):
    """
    Given a policy as a dictionary, determine what AWS services the policy grants at the write
    or permissions management access levels.
    """
    service_prefixes_with_write_access = []
    service_prefixes_with_permissions_management_access = []
    write_access_actions = has_write_access(policy) # TODO: Verify the accuracy of this.
    permissions_management_actions = has_permissions_management_access(policy)
    if write_access_actions:
        for action in write_access_actions:
            service_name = get_service_from_action(action)
            if service_name not in service_prefixes_with_write_access:
                service_prefixes_with_write_access.append(service_name)
    if permissions_management_actions:
        for action in permissions_management_actions:
            service_name = get_service_from_action(action)
            if service_name not in service_prefixes_with_permissions_management_access:
                service_prefixes_with_permissions_management_access.append(service_name)
    all_modify_level_service_prefixes = service_prefixes_with_permissions_management_access + \
                                        service_prefixes_with_write_access
    # remove duplicates
    all_modify_level_service_prefixes = list(dict.fromkeys(all_modify_level_service_prefixes))
    return all_modify_level_service_prefixes


if __name__ == '__main__':
    analyze_public_instances_results()
