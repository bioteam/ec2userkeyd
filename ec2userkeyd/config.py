# Configuration settings

class general:
    daemon_port = 808

    # Supported methods:
    # - UserRole
    # - CreateUserRole
    # - RestrictedInstanceRole
    # - InstanceRole
    # - UserKeysSecretsManager
    credential_methods = ['UserRole', 'RestrictedInstanceRole', 'InstanceRole']


class method_UserRole:
    role_name_pattern = "user-{username}"


class method_CreateUserRole:
    iam_name_pattern = "{username}"
    role_name_pattern = "user-{username}"

    
class method_RestrictedInstanceRole:
    iam_name_pattern = "{username}"
    
    # If True, this method tries to consolidate the user policy by
    # removing Deny statements that overlap with the instance role's
    # Deny statements.
    compress_user_policy = False


class method_InstanceRole:
    # If True, the credentials will have a custom attached policy that
    # prevents further calls to AssumeRole. This is recommended if any
    # of the role-based policies are in use.
    deny_assumerole = True

    # If True, the credentials will have a custom attached policy that
    # prevents any calls to AWS Secrets Manager. This is recommended
    # if UserKeysSecretsManager is in use.
    deny_secretsmanager = True


class method_UserKeysSecretsManager:
    # This method stores user API keys in AWS Secrets Manager. The
    # instance role must have access to the secretsmanager API.
