# find-s3-account

Sample code to find the AWS account ID of an S3 bucket using the technique described in https://tracebit.com/blog/2024/02/finding-aws-account-id-of-any-s3-bucket/

See the blog post for the supporting infrastructure you'll need. This code expects to be able to assume a role "s3-find-account".

*Do not run this code in anything other than a VPC that you've explicitly created for this purpose as it *will* break
existing connectivity to S3 within the VPC in which you run it.*