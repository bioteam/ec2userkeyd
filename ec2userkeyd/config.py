import os
import re
import logging
import configparser


logger = logging.getLogger(__name__)


class general:
    daemon_port = 808

    iptables = '/sbin/iptables'

    # Supported methods:
    # - UserRole
    # - CreateUserRole
    # - RestrictedInstanceRole
    # - InstanceRole
    credential_methods = ['UserRole', 'RestrictedInstanceRole', 'InstanceRole']

    per_user_credential_methods = {}
    per_uid_credential_methods = {}
    
    log_level = logging.ERROR
    log_console = False
    log_syslog = True

    @classmethod
    def user_credential_methods(cls, username):
        """Parse per_user_credential_methods.

        >>> general.per_user_credential_methods = {'joe': 'one, two'}
        >>> general.user_credential_methods('joe')
        ['one', 'two']
        >>> general.user_credential_methods('jane')
        []

        """
        if username not in cls.per_user_credential_methods:
            return []
        return [i.strip()
                for i in cls.per_user_credential_methods[username].split(',')]

    @classmethod
    def uid_credential_methods(cls, uid):
        """Parse per_uid_credential_methods.

        >>> general.per_uid_credential_methods = {'0-499': 'three, four'}
        >>> general.uid_credential_methods(250)
        ['three', 'four']
        >>> general.uid_credential_methods(500)
        []

        """
        seq = None
        for k in cls.per_uid_credential_methods:
            if '-' in k:
                s, e = k.split('-')
                if int(s) <= uid <= int(e):
                    seq = cls.per_uid_credential_methods[k]
            elif int(k) == uid:
                seq = cls.per_uid_credential_methods[k]
        if seq:
            return [i.strip() for i in seq.split(',')]
        return []
        

class method_UserRole:
    # This method tries to find a role in the system matching the name
    # pattern below; if found, attempts to AssumeRole to that role.
    role_name_pattern = "user-{username}"


class method_CreateUserRole:
    # This method assumes there's an IAM user matching the IAM name
    # pattern below. If found, the instance role is used to create a
    # new role with all policies copied over from the IAM user, and
    # returns the AssumeRole to the new role. If the role already
    # exists, then the policies are synchronized before assuming.
    iam_name_pattern = "{username}"
    role_name_pattern = "user-{username}"

    
class method_RestrictedInstanceRole:
    # This method assumes there's an IAM user matching the IAM name
    # pattern below. If found, the user's policies are extracted and
    # passed to AssumeRole as a restriction on top of the current
    # instance role.
    iam_name_pattern = "{username}"
    
    # If True, this method tries to reduce the size of the user policy
    # by removing Deny statements that overlap with the instance
    # role's Deny statements.
    compress_user_policy = False


class method_InstanceRole:
    # This method returns the current instance role credentials, with
    # an optional attached policy denying access to sensitive APIs.
    
    # In order to activate an attached policy (if enabled below), the
    # instance role must have sts:AssumeRole privileges on its own
    # role. If this is not present and a deny is enabled, when
    # fail_safe is set to True, this method will not emit any
    # credentials. Otherwise, if False, this method will emit the
    # current instance role credentials.
    fail_safe = False
    
    # If True, the credentials will have an attached policy that
    # prevents further calls to AssumeRole. This is recommended if any
    # of the role-based policies are in use.
    deny_assumerole = True

    # If True, the credentials will have an attached policy that
    # prevents any calls to AWS Secrets Manager. This is recommended
    # if UserKeysSecretsManager is in use.
    deny_secretsmanager = True


class method_UserKeysSecretsManager:
    # This method stores user API keys in AWS Secrets Manager. The
    # instance role must have access to the secretsmanager API.
    pass


###
### Helper functions

def update(filename):
    logger.info(f'Reading config from {filename}')
    config = configparser.ConfigParser()
    config.read([filename])
    for section in config.sections():
        if section not in [k for k, v in globals().items() if type(v) == type]:
            raise Exception(f'malformed config file: invalid section'
                            f' {section}')
        klass = globals()[section]
        for option in config.options(section):
            if hasattr(klass, option):
                attr = getattr(klass, option)
                logger.debug(f'update {klass}.{option} to '
                             f'{config.get(section, option)}')
                try:
                    if type(attr) == str:
                        setattr(klass, option, config.get(section, option))
                    elif type(attr) == int:
                        setattr(klass, option, config.getint(section, option))
                    elif type(attr) == bool:
                        setattr(klass, option,
                                config.getboolean(section, option))
                    elif type(attr) == list:
                        config_val = config.get(section, option)
                        parsed_val = [i.strip() for i in config_val.split(',')]
                        if all(type(v) == int for v in attr):
                            parsed_val = [int(i) for i in parsed_val]
                        setattr(klass, option, parsed_val)
                    elif type(attr) == dict:
                        config_val = config.get(section, option)
                        kvs = [i.strip()
                               for i in re.split(r'(?:,\s+)?(\S+):', config_val)
                               if i]
                        iter_kvs = iter(kvs)
                        parsed_val = {k:v for k, v in zip(iter_kvs, iter_kvs)}
                        setattr(klass, option, parsed_val)
                except ValueError:
                    raise ValueError(
                        f'invalid value for {option} in config section'
                        f' {section}: {config.get(section, option)}')
            else:
                raise Exception(f'malformed config file: invalid option'
                                f' {option} in section {section}')
        
