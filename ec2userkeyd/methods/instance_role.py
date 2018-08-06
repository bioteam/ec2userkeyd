
import json
import requests

from ec2userkeyd import utils
from ec2userkeyd import clients
from ec2userkeyd.methods.base import BaseCredentialSource


class InstanceRole(BaseCredentialSource):
    """Retrieve credentials directly from the instance.
    """
    DENY_ASSUMEROLE = {'Action': 'sts:AssumeRole', 'Resource': '*',
                       'Effect': 'Deny'}

    DENY_SECRETSMANAGER = {'Action': 'secretsmanager:*', 'Resource': '*',
                           'Effect': 'Deny'}
    
    def get(self, username, role):
        statements = []
        if self.config.deny_assumerole:
            statements.append(self.DENY_ASSUMEROLE)

        if self.config.deny_secretsmanager:
            statements.append(self.DENY_SECRETSMANAGER)

        if statements:
            # We have a policy to try to attach. For this, we're going
            # to try to assume our current role but apply an inline
            # restrictive policy.
            try:
                response = clients.sts.assume_role(
                    RoleArn=clients.current_role_arn(),
                    RoleSessionName=username,
                    Policy=utils.make_iam_policy(statements))
                return utils.assume_role_response(response)
            except clients.sts.exceptions.ClientError as ex:
                if 'AccessDenied' not in str(ex):
                    raise ex
                if self.config.fail_safe:
                    return None
        
        return requests.get(
            ('http://169.254.169.254/latest/meta-data/iam'
             '/security-credentials/' + role)).json()
