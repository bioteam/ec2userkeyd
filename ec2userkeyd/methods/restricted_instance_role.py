import logging
logger = logging.getLogger(__name__)

from ec2userkeyd import clients, utils, iam_policy
from ec2userkeyd.methods.base import BaseCredentialSource


class RestrictedInstanceRole(BaseCredentialSource):
    """AssumeRole to this instance's role, restricted by the IAM user's
    permissions.
    """

    def get(self, username, instance_role_name):
        # Try to find the corresponding IAM user policies
        try:
            logger.debug(f'{username}: IAM user ' +
                         self.config.iam_name_pattern.format(username=username))
            
            statements = clients.get_iam_user_policy_statements(
                self.config.iam_name_pattern.format(username=username))
            if not statements:
                logger.debug(f'{username}: no IAM user policy statements')
                return None
        
            if self.config.compress_user_policy:
                statements = self.compress_statements(statements)
                if not statements:
                    logger.debug(f'{username}: no statements after compression')
                    return None
            
            response = clients.cached_assume_role(
                RoleArn=clients.current_role_arn(),
                RoleSessionName=username,
                Policy=utils.make_iam_policy(statements))
            return utils.assume_role_response(response)
        except clients.sts.exceptions.ClientError as ex:
            if 'AccessDenied' not in str(ex):
                raise ex
            logger.debug(str(ex))
            return None

    def compress_statements(self, statements):
        # The effective policy of the user will be the permissions
        # granted by the role, unioned by the permissions granted by
        # these statements.
        role_statements = clients.get_iam_role_policy_statements(
            clients.current_role_arn())
        policy = iam_policy.Policy(role_statements)

        retval = []
        for s in statements:
            if s['Effect'] == 'Allow' and s in policy:
                retval.append(s)
                    
            if s['Effect'] == 'Deny' and s not in policy:
                retval.append(s)

        return retval
