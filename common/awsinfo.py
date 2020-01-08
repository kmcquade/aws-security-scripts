import configparser
import json
import boto3
from botocore.exceptions import ClientError, ProfileNotFound
from common.login import login

def get_list_of_aws_profiles(credentials_file):
    """Get a list of profiles from the AWS Credentials file"""
    config = configparser.ConfigParser(strict=False)
    config.read(credentials_file)
    sections = config.sections()
    legitimate_sections = []
    print(f"Sections are: \n")
    # sections_to_print = sections.sort()
    sections_to_print = []
    for section in sections:
        sections_to_print.append(str(section))
    sections_to_print.sort()
    print(json.dumps(sections_to_print, indent=2))
    for section in sections_to_print:
        # https://github.com/broamski/aws-mfa#credentials-file-setup
        broamski_suffix = "-long-term"
        # pylint: disable=no-else-continue
        if section.endswith(broamski_suffix):
            # skip it if it's not a real profile we want to evaluate
            continue
        else:
            legitimate_sections.append(section)
    legitimate_sections = list(dict.fromkeys(legitimate_sections))  # remove duplicates
    return legitimate_sections


def get_aws_account_id(sts_session):
    """Test the login procedure with boto3 STS session."""
    try:
        result = sts_session.get_caller_identity()
        return result['Account']
    except ClientError as c_e:
        if "InvalidClientTokenId" in str(c_e):
            print(
                "ERROR: sts.get_caller_identity failed with InvalidClientTokenId. "
                "Likely cause is no AWS credentials are set.",
                flush=True,
            )
            exit(-1)
        else:
            print(
                "ERROR: Unknown exception when trying to call sts.get_caller_identity: {}".format(
                    c_e
                ),
                flush=True,
            )
            exit(-1)
    except ProfileNotFound as p_fe:
        print(p_fe)
        exit(-1)


def get_all_regions(audit_all_regions):
    """
    Get a list of AWS regions. By default, this just returns US regions. To return all regions,
    set the input parameter 'audit_all_regions' to True
    """
    if audit_all_regions:
        ec2 = boto3.client('ec2', 'us-east-1')

        # Retrieves all regions/endpoints that work with EC2
        response = ec2.describe_regions()
        all_regions = []
        for region in response['Regions']:
            all_regions.append(region['RegionName'])

        # print(json.dumps(regions, indent=2))
        return all_regions
    else:
        return ['us-east-1', 'us-east-2', 'us-west-1', 'us-west-2']


def is_aws_managed_policy(policy_arn):
    """
    Look for only the AWS Managed Policies (not policies you created) by looking for "iam::aws" in the ARN
    Got this trick from: https://gist.github.com/0xdabbad00/4ed4a7a56bbb93d70505a709de227414#file-grab-sh-L21
    """
    if 'iam::aws' in policy_arn:
        return True
    else:
        return False


def get_managed_policy(profile_name, policy_arn):
    """Given a valid policy ARN, get a customer managed policy or an AWS managed policy"""
    iam_client = login(profile_name, 'iam')

    response = iam_client.get_policy(
        PolicyArn=policy_arn
    )
    default_version_id = response['Policy']['DefaultVersionId']
    response = iam_client.get_policy_version(
        PolicyArn=policy_arn,
        VersionId=default_version_id
    )
    return response['PolicyVersion']['Document']