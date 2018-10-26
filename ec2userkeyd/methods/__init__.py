
from ec2userkeyd.methods.user_role import UserRole
from ec2userkeyd.methods.restricted_instance_role import RestrictedInstanceRole
from ec2userkeyd.methods.instance_role import InstanceRole

from ec2userkeyd import config


def sequence_for(username, uid):
    sequence = (config.general.user_credential_methods(username)
                or config.general.uid_credential_methods(uid)
                or config.general.credential_methods)
    return [globals()[m]() for m in sequence]
