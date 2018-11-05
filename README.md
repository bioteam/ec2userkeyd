# ec2userkeyd

Automatically provide EC2 users with personalized credentials via a
local daemon intercepting requests to the EC2 metadata service.

![Flow diagram](https://raw.githubusercontent.com/bioteam/ec2userkeyd/b58a67577ceeff6a824997396be59ce7af21035e/ec2userkeyd-diagram.png)

## Motivation

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

# Credential Methods

This daemon supports multiple different methods of translating from
UNIX users to AWS credentials. You can chain these methods, so that a
failure to retrieve credentials via the first method will fall back to
the second method in the list, and so on. You can also have different
chains for individual users or ranges of UIDs.

The currently supported methods are:

### UserRole

This method tries to AssumeRole to an IAM role that matches a pattern,
which defaults to `user-{username}`. This should be used if you can
easily maintain roles that correspond to your users, or if you are
trying to enable reduced privileges for a local service account.

The only instance role permissions required for this method are
`sts:AssumeRole`. Additionally, you should ensure that the role to be
assumed has an Assume Role Policy Document that grants access to the
instance role. The following policy grants access to a specific
instance role:

    {
        "Version": "2012-10-17",
        "Statement": [{
            "Action": "sts:AssumeRole",
            "Principal": "arn:aws:iam::123456789012:role/my-instance-role",
            "Effect": "Allow"
        }]
    }
    
Changing the Principal above to `arn:aws:iam::123456789012:role/*`
would allow any role in the account with `sts:AssumeRole` privileges
to use the role.

### CreateUserRole

This method behaves similarly to UserRole, except that it
automatically maintains user roles that parallel IAM users. It is able
to synchronize the policies attached to user roles with those defined
on the IAM users, and it can create new roles if necessary.

This method requires the following permissions to be granted to the
instance role:

* `sts:AssumeRole`
* `sts:GetCallerIdentity`
* `iam:CreateRole`
* `iam:List*`
* `iam:GetPolicy`
* `iam:GetPolicyVersion`
* `iam:GetRolePolicy`
* `iam:GetGroupPolicy`
* `iam:AttachRolePolicy`
* `iam:PutRolePolicy`

If the config option `instance_role_linked` inside
`method_CreateUserRole` is set to True, then only the role that
creates the user role can access it; otherwise, any role in the
account can access the created user role.

### RestrictedInstanceRole

This method attempts to AssumeRole to the current instance role, while
passing a set of additional restrictive policies that are derived from
the policies discovered from an IAM user. The resulting permissions
will be no greater than those given to the instance role. This method
is most suitable for users with small attached policies, since the
Policy parameter to AssumeRole is limited to 2KB, or smaller,
depending on the policy's packed size. 

Because of the tight policy size restrictions with this method, there
is an optional compression feature available that tries to reduce the
size of the policy parameter by eliminating unneeded statements, such
as overlapping Deny statements. This is controlled by the
`compress_user_policy` parameter within
`method_RestrictedInstanceRole`.

This method requires the following permissions to be granted to the
instance role:

* `sts:AssumeRole`
* `sts:GetCallerIdentity`
* `iam:GetPolicy`
* `iam:GetPolicyVersion`
* `iam:GetUserPolicy`
* `iam:GetGroupPolicy`
* `iam:ListUserPolicies`
* `iam:ListGroupsForUser`
* `iam:ListGroupPolicies`
* `iam:ListAttachedUserPolicies`
* `iam:ListAttachedGroupPolicies`

If `compress_user_policy` is enabled, then additional permissions are
required:

* `iam:GetRolePolicy`
* `iam:ListRolePolicies`
* `iam:ListAttachedRolePolicies`

### InstanceRole

This method passes through the instance role privileges, with optional
policy restrictions. It can be used, for example, as the last method
in a chain so that users (typically local service accounts) that don't
match earlier methods can get privileges as defined by the instance
role.

It is important to note that if this method is used as a fallback for
one of the preceding role-based methods, it may be possible for a user
to use instance role privileges to call AssumeRole, and therefore gain
access to another user's privileges. To avoid this, the method has an
option (default enabled) to deny AssumeRole access by generating new
credentials with a small attached policy. 

This additional restriction requires the following permissions to be
granted to the instance role:

* `sts:AssumeRole`
* `sts:GetCallerIdentity`

The instance role should also have an Assume Role Policy Document that
grants access to itself; see the discussion in UserRole for details.


# Getting Started

## Requirements

This app requires Python 3.6 or greater to run, which should be
available in your distribution's package repository. 

On Amazon Linux:

    $ sudo yum -y install python3 python3-pip

Only Linux is supported at this time.

## Installation

Install from PyPI via `pip`:

    $ sudo pip3 install ec2userkeyd
    
## Configuration

The application configuration defaults are shown in
`ec2userkeyd/config.py`. These settings can be overridden by creating
a config file (default location: `/etc/ec2userkeyd.conf`) in INI-style
format.

## Startup

To test run the app, call it with the `daemon` argument.

    $ sudo /usr/local/bin/ec2userkeyd daemon

It will run in the foreground until killed. 

To autostart, refer to your distribution's init system.
