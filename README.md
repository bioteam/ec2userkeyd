# ec2userkeyd

## Introduction

Currently accepted security best practice for AWS EC2 instances is to
grant them *instance IAM roles*, which allows applications on those
instances to use AWS services without needing to hard-code IAM user
secret access keys. Unfortunately, this carries with it the
implication that all users on a given EC2 instance ought to have the
same permissions to AWS APIs, which is not always the case. For
example, a shared analytics instance may have multiple users who each
need to have access to different S3 buckets. Therefore, there is a
need, in certain circumstances, to grant different IAM credentials to
different users local to an instance.

The most obvious solution to this problem, currently, is to revert
back to the former practice of embedding IAM user secret access keys
on the instance. However, this means manually managing a fleet of
secret access keys and protecting those keys with file permissions.
Furthermore, the keys are likely not to be rotated on a defined
schedule, increasing the risk of compromise through the leak of a
long-lived credential.

This application provides another potential solution. By using NAT via
`iptables`, it intercepts HTTP requests destined to the EC2 metadata
service and responds with short-lived credentials that are specific to
the originating process's user ID. Multiple methods of translating
from UNIX usernames to AWS credentials are supported, depending on
your AWS IAM typical practices.

## Requirements

* Python 3.6+
* Linux
* Flask
* Click
* Requests
* Boto3

