import os
import configparser
import boto3
from botocore.exceptions import ClientError, ProfileNotFound


def login(profile_name, service, region="us-east-1"):
    """Log in to AWS and return a boto3 session."""
    default_region = os.environ.get("AWS_REGION", region)
    session_data = {"region_name": default_region}
    if profile_name:
        session_data["profile_name"] = profile_name
    try:
        try:
            session = boto3.Session(**session_data)
            # Ensure we can make calls
            sts_session = session.client('sts')
            login_sts_test(sts_session)
            # Return the service requested by the function - either sts or iam
            if service:
                this_session = session.client(service)
            # By default return IAM
            else:
                this_session = session.client(service)
            return this_session
        except configparser.DuplicateSectionError as d_se:
            print(d_se)
    except ProfileNotFound as p_nf:
        print(p_nf)
        return p_nf


def login_sts_test(sts_session):
    """Test the login procedure with boto3 STS session."""
    try:
        sts_session.get_caller_identity()
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
