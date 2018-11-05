import json
import logging
logger = logging.getLogger(__name__)

from ec2userkeyd import utils, clients
from ec2userkeyd.methods.user_role import UserRole


class CreateUserRole(UserRole):
    """AssumeRole to a user-oriented role, creating it first if it doesn't
    yet exist, and synchronizing policies if it does exist.
    """

    def get(self, username, instance_role_name):
        try:
            result = self.synchronize(username)
            if result == 'role-does-not-exist':
                self.create_new_role(username)
                result = self.synchronize(username)

            if result == 'user-does-not-exist':
                return None

            return super().get(username, instance_role_name)
        except clients.sts.exceptions.ClientError as ex:
            if 'AccessDenied' not in str(ex):
                raise ex
            logger.debug(str(ex))
            return None

    def create_new_role(self, username):
        iam_user_name = self.config.iam_name_pattern.format(username=username)
        iam_role_name = self.config.role_name_pattern.format(username=username)
        logger.warning(f'Creating new role {iam_role_name} to track user'
                       f' {iam_user_name}')
        
        if self.config.instance_role_linked:
            assume_role_policy_document = utils.make_iam_policy([{
                'Action': 'sts:AssumeRole',
                'Principal': {'AWS': clients.current_role_arn()},
                'Effect': 'Allow'
            }])
        else:
            account_id = clients.current_role_arn().split(':')[4]
            assume_role_policy_document = utils.make_iam_policy([{
                'Action': 'sts:AssumeRole',
                'Principal': {'AWS': f'arn:aws:iam::{account_id}:role/*'},
                'Effect': 'Allow'
            }])
        
        clients.iam.create_role(
            RoleName=iam_role_name,
            AssumeRolePolicyDocument=assume_role_policy_document,
            Description=f'Role tracking user {iam_user_name}'
        )

    def synchronize(self, username):
        iam_user_name = self.config.iam_name_pattern.format(username=username)
        iam_role_name = self.config.role_name_pattern.format(username=username)

        inline_policies = {}
        attached_policies = set()
        try:
            user = clients.iam_resource.User(iam_user_name)

            for group in user.groups.all():
                for policy in group.policies.all():
                    inline_policies[policy.name] = policy
                for policy in group.attached_policies.all():
                    attached_policies.add(policy.arn)
            
            for policy in user.policies.all():
                inline_policies[policy.name] = policy
            for policy in user.attached_policies.all():
                attached_policies.add(policy.arn)
                
        except clients.iam.exceptions.NoSuchEntityException:
            logger.info(f'IAM user {iam_user_name} does not exist')
            return 'user-does-not-exist'

        try:
            role = clients.iam_resource.Role(iam_role_name)

            # check attached policies
            role_attached_policies = {p.arn
                                      for p in role.attached_policies.all()}
            for policy in role_attached_policies.difference(attached_policies):
                role.detach_policy(PolicyArn=policy)
            for policy in attached_policies.difference(role_attached_policies):
                role.attach_policy(PolicyArn=policy)

            # check inline policies
            role_policies = {p.name:p for p in role.policies.all()}
            user_inline_policy_names = set(inline_policies.keys())
            role_inline_policy_names = set(role_policies.keys())
            for name in role_inline_policy_names.difference(
                    user_inline_policy_names):
                clients.iam.delete_role_policy(
                    RoleName=iam_role_name,
                    PolicyName=name)
            for name in user_inline_policy_names:
                if (name in role_policies
                    and role_policies[name].policy_document == \
                        inline_policies[name].policy_document):
                    continue
                clients.iam.put_role_policy(
                    RoleName=iam_role_name,
                    PolicyName=name,
                    PolicyDocument=json.dumps(
                        inline_policies[name].policy_document))
            
        except clients.iam.exceptions.NoSuchEntityException:
            return 'role-does-not-exist'
        
        
