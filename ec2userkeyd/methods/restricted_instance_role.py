from ec2userkeyd import clients, utils, iam_policy
from ec2userkeyd.methods.base import BaseCredentialSource


# It's possible that we may want some way to stop the default
# fall-through behavior. For example, if we have
# RestrictedInstanceRole before InstanceRole, it may be intentional
# that when RestrictedInstanceRole fails (because the local user
# doesn't have a corresponding IAM user) then InstanceRole gives full
# permissions. However, RestrictedInstanceRole could also fail for a
# number of other reasons, including that the packed policy is too
# large. The fall-through to InstanceRole may therefore grant too much
# permission to the user.
#
# I'm going to suggest that at the general level, the config allows
# for a map between username or UID range and method list. That way,
# you could have different lists of methods for your normal users
# versus your service accounts.

class RestrictedInstanceRole(BaseCredentialSource):
    """AssumeRole to this instance's role, restricted by the IAM user's
    permissions.
    """

    def get(self, username, instance_role_name):
        # Try to find the corresponding IAM user policies
        try:
            statements = clients.get_iam_user_policy_statements(
                self.config.iam_name_pattern.format(username=username))
            if not statements:
                return None
        
            if self.config.compress_user_policy:
                statements = self.compress_statements(statements)
                if not statements:
                    return None
            
            response = clients.sts.assume_role(
                RoleArn=clients.current_role_arn(),
                RoleSessionName=username,
                Policy=utils.make_iam_policy(statements))
            return utils.assume_role_response(response)
        except clients.sts.exceptions.ClientError as ex:
            if 'AccessDenied' not in str(ex):
                raise ex
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
