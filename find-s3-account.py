from datetime import datetime, timedelta
from time import sleep

from botocore.utils import IMDSFetcher
import http.client
import boto3
import json
import sys


class InstanceMetadata(IMDSFetcher):
    def retrieve(self, path):
        response = self._get_request(
            url_path=path,
            retry_func=self._default_retry,
            token=self._fetch_metadata_token(),
        )
        return response.text


role_name = "s3-find-account"
metadata = InstanceMetadata()
region = metadata.retrieve("latest/meta-data/placement/availability-zone")[:-1]
instance_id = metadata.retrieve("latest/meta-data/instance-id")
mac = metadata.retrieve("latest/meta-data/network/interfaces/macs/").split("\n")[0].strip("/")
vpc_id = metadata.retrieve(f"latest/meta-data/network/interfaces/macs/{mac}/vpc-id")
account_id = metadata.retrieve(f"latest/meta-data/network/interfaces/macs/{mac}/owner-id")

session = boto3.Session(region_name=region)
s3 = session.client("s3")
ec2 = session.client("ec2")
sts = session.client("sts")
cloudtrail = session.client("cloudtrail")
cloudtrail_events = cloudtrail.get_paginator("lookup_events")


def wildcard_string(digit_position, digit):
    # e.g. wildcard_string(2, 7) returns "??7?????????"
    return f"{digit_position * '?'}{digit}{'?' * (11 - digit_position)}"


def wildcards():
    return [
        wildcard_string(digit_position, digit)
        for digit_position in range(12)
        for digit in range(10)
    ]


def wildcard_to_session_name(wildcard):
    return wildcard.replace("?", "-")


def account_id_from_session_names(session_names_seen):
    bucket_account_id = ["?"] * 12

    for session_name in session_names_seen:
        for i, session_name_char in enumerate(session_name):
            if session_name_char.isdigit():
                bucket_account_id[i] = session_name_char

    return "".join(bucket_account_id)


def assert_region_matches(bucket_name):
    connection = http.client.HTTPSConnection(f"{bucket_name}.s3.amazonaws.com")
    connection.request("HEAD", "/")
    response = connection.getresponse()

    if response.headers["x-amz-bucket-region"] != region:
        raise RuntimeError(
            f"Bucket {bucket_name} is in region {response.headers['x-amz-bucket-region']}, not VPC region {region}")


def generate_wildcard_policy_statement(wildcard):
    # Allow access to s3 resources to a role session name of
    # e.g. "--2---------" if the bucket account id matches "??2?????????"
    return {
        "Effect": "Allow",
        "Action": ["s3:*"],
        "Resource": "*",
        "Principal": "*",
        "Condition": {
            "StringLike": {
                "aws:userid": f"*:{wildcard_to_session_name(wildcard)}",
                "s3:ResourceAccount": wildcard,
            }
        }
    }


def generate_policy(role_name):
    # Allow if not using role_name
    statements = [{
        "Action": "s3:*",
        "Effect": "Allow",
        "Resource": "*",
        "Principal": "*",
        "Condition": {
            "StringNotLikeIfExists": {
                "aws:PrincipalArn": f"*/{role_name}"
            }
        }
    }]

    for wildcard in wildcards():
        statements.append(generate_wildcard_policy_statement(wildcard))

    return json.dumps({
        "Version": "2012-10-17",
        "Statement": statements,
    }, separators=(',', ':'))


def configure_vpc_endpoint(policy):
    vpc_endpoints = ec2.describe_vpc_endpoints()
    for vpc_endpoint in vpc_endpoints["VpcEndpoints"]:
        if (
                vpc_endpoint["ServiceName"] == f"com.amazonaws.{region}.s3"
                and vpc_endpoint["VpcId"] == vpc_id
                and vpc_endpoint["VpcEndpointType"] == "Interface"
        ):
            vpc_endpoint_id = vpc_endpoint["VpcEndpointId"]

            if vpc_endpoint["PolicyDocument"] != policy:
                print(f"Modifying VPC endpoint {vpc_endpoint_id} policy...")
                ec2.modify_vpc_endpoint(
                    VpcEndpointId=vpc_endpoint["VpcEndpointId"],
                    PolicyDocument=policy
                )
                print("Modified VPC endpoint policy; waiting 5 minutes to propagate")
                sleep(300)

            else:
                print(f"VPC endpoint {vpc_endpoint_id} policy already configured")

            return vpc_endpoint["VpcEndpointId"]

    raise RuntimeError("VPC endpoint not found")


def make_s3_requests(role_name, bucket_name):
    role_arn = f"arn:aws:iam::{account_id}:role/{role_name}"

    for wildcard in wildcards():
        session_name = wildcard_to_session_name(wildcard)
        credentials = sts.assume_role(
            RoleArn=role_arn,
            RoleSessionName=session_name,
        )["Credentials"]

        wildcard_s3 = boto3.client("s3", region_name=region, aws_access_key_id=credentials["AccessKeyId"],
                                   aws_secret_access_key=credentials["SecretAccessKey"],
                                   aws_session_token=credentials["SessionToken"])

        print(f"Requesting {bucket_name} using session name {session_name}")
        try:
            wildcard_s3.get_bucket_acl(Bucket=bucket_name)
        except s3.exceptions.ClientError:
            pass


def find_session_names_in_cloudtrail(vpc_endpoint_id, start_time, bucket_name):
    print("Finding session names which passed the VPC endpoint in CloudTrail...")

    session_names = set()
    while len(session_names) < 12 and datetime.utcnow() < start_time + timedelta(minutes=10):
        for page in cloudtrail_events.paginate(
                LookupAttributes=[
                    {
                        "AttributeKey": "EventName",
                        "AttributeValue": "GetBucketAcl",
                    }
                ],
                StartTime=start_time - timedelta(minutes=1),
        ):
            for event in page["Events"]:
                body = json.loads(event["CloudTrailEvent"])
                if (
                        body.get("eventName") == "GetBucketAcl" and
                        body.get("requestParameters", {}).get("bucketName") == bucket_name and
                        body.get("userIdentity", {})
                                .get("sessionContext", {})
                                .get("sessionIssuer", {})
                                .get("userName") == role_name
                ):
                    if body.get("vpcEndpointId") != vpc_endpoint_id:
                        raise RuntimeError(
                            f"Traffic not going through VPC endpoint ({vpc_endpoint_id}), check configuration")

                    session_name = body["userIdentity"]["principalId"].split(":")[1]

                    if session_name not in session_names:
                        print(f"Found {session_name} for {bucket_name} in CloudTrail")
                        session_names.add(session_name)

        sleep(30)

    return session_names


def main():
    if len(sys.argv) != 2:
        print("Usage: python find-s3-account.py <bucket-name>")
        sys.exit(1)

    bucket_name = sys.argv[1]

    assert_region_matches(bucket_name)
    vpc_endpoint_policy = generate_policy(role_name)
    vpc_endpoint_id = configure_vpc_endpoint(vpc_endpoint_policy)

    start_time = datetime.utcnow()
    make_s3_requests(role_name, bucket_name)
    session_names = find_session_names_in_cloudtrail(vpc_endpoint_id, start_time, bucket_name)
    account_id = account_id_from_session_names(session_names)
    print(f"Bucket {bucket_name}: {account_id}")


if __name__ == "__main__":
    main()
