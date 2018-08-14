
from ec2userkeyd import iam_policy


def test_contains_1():
    p = iam_policy.Policy([
        {'Effect': 'Allow', 'Resource': '*', 'Action': 'iam:*'},
        {'Effect': 'Allow', 'Resource': ['arn:aws:s3:::foobucket',
                                         'arn:aws:s3:::foobucket/*'],
         'Action': 's3:*'},
    ])
    assert {'Effect': 'Allow', 'Resource': '*', 'Action': 'iam:*'} in p
    assert {'Effect': 'Allow', 'Resource': '*', 'Action': 'iam:GetUser'} in p
    assert {'Effect': 'Allow', 'Resource': '*', 'Action': 'iam:Get*'} in p
    assert {'Effect': 'Allow', 'Resource': '*', 'Action': 'sqs:*'} not in p
    assert {'Effect': 'Allow', 'Resource': '*', 'Action': '*'} not in p
    assert {'Effect': 'Deny', 'Resource': '*', 'Action': 's3:*'} not in p
    assert {'Effect': 'Allow', 'Resource': 'arn:aws:s3:::foobucket',
            'Action': 's3:GetObject'} in p
    assert {'Effect': 'Allow', 'Resource': 'arn:aws:s3:::barbucket',
            'Action': 's3:*'} not in p


def test_contains_2():
    # Conditions are only supported if exactly equivalent to a
    # statement in the policy.
    p = iam_policy.Policy([
        {'Effect': 'Allow', 'Resource': '*', 'Action': 's3:*',
         'Condition': {
             'DateGreaterThan': {'aws:CurrentTime': '2013-12-15T12:00:00Z'}}}
    ])
    assert {'Effect': 'Allow', 'Resource': '*', 'Action': 's3:*'} not in p
    assert {'Effect': 'Allow', 'Resource': '*', 'Action': 's3:*',
            'Condition': {
                'DateGreaterThan': {
                    'aws:CurrentTime': '2013-12-15T12:00:00Z'}}} in p


def test_contains_3():
    # This policy is plausible; it allows the user to do anything to
    # foobucket but no other actions (even if otherwise granted).
    p = iam_policy.Policy([
        {'Effect': 'Allow', 'Resource': '*', 'Action': 's3:*'},
        {'Effect': 'Deny', 'NotResource': ['arn:aws:s3:::foobucket',
                                           'arn:aws:s3:::foobucket/*'],
         'Action': 's3:*'},
        {'Effect': 'Deny', 'Resource': '*', 'NotAction': 's3:*'}
    ])
    assert {'Effect': 'Allow', 'Resource': 'arn:aws:s3:::foobucket',
            'Action': 's3:*'} in p
    assert {'Effect': 'Deny', 'Resource': '*', 'NotAction': 's3:*'} in p
    assert {'Effect': 'Deny', 'Resource': '*', 'Action': 'iam:*'} in p
    assert {'Effect': 'Deny', 'Resource': 'arn:aws:s3:::barbucket',
            'Action': 's3:ListBucket'} in p
    assert {'Effect': 'Allow', 'Resource': '*', 'Action': 'iam:*'} not in p


def test_all_input_forms():
    p = iam_policy.Policy(
        '{"Version": "2012-10-17", "Statement": ['
        '    {"Effect": "Allow", "Resource": "*", "Action": "*"}]}')
    assert p.statements == [
        {'Effect': 'Allow', 'Resource': ['*'], 'Action': ['*']}]

    q = iam_policy.Policy(
        {"Version": "2012-10-17", "Statement": [
            {"Effect": "Allow", "Resource": "*", "Action": "*"}]})
    assert q.statements == [
        {'Effect': 'Allow', 'Resource': ['*'], 'Action': ['*']}]

    r = iam_policy.Policy([
        {"Effect": "Allow", "Resource": "*", "Action": "*"}])
    assert r.statements == [
        {'Effect': 'Allow', 'Resource': ['*'], 'Action': ['*']}]
    
    s = iam_policy.Policy([
        '{"Effect": "Allow", "Resource": "*", "Action": "*"}'])
    assert s.statements == [
        {'Effect': 'Allow', 'Resource': ['*'], 'Action': ['*']}]
    
