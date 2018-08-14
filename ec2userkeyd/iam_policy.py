import copy
import json
from fnmatch import fnmatchcase


def normalize(statement):
    """Make all IAM statements consistent.

    >>> s = normalize({'Effect': 'allow', 'Resource': '*', 'Action': 's3:*'})
    >>> s['Effect']
    'Allow'
    >>> s['Resource']
    ['*']
    >>> s['Action']
    ['s3:*']

    """
    if isinstance(statement, str):
        statement = json.loads(statement)
    else:
        statement = copy.deepcopy(statement)
        
    if 'Principal' in statement:
        raise Exception('Principal statements not supported')

    statement['Effect'] = statement['Effect'].title()
    for k in ['Action', 'NotAction', 'Resource', 'NotResource']:
        if k in statement and isinstance(statement[k], str):
            statement[k] = [statement[k]]

    return statement


def wildcard_compare(a, b):
    """Compare two lists, with wildcard matching from the first to the second.

    >>> wildcard_compare(['a', 'b*'], ['bb'])
    True

    """
    return all(any(fnmatchcase(i, j) for j in a) for i in b)
    

class Policy:
    def __init__(self, document):
        self.statements = []
        if isinstance(document, dict):
            self.statements = [normalize(s) for s in document['Statement']]
        elif isinstance(document, list):
            self.statements = [normalize(s) for s in document]
        elif isinstance(document, str):
            doc = json.loads(document)
            self.statements = [normalize(s) for s in doc['Statement']]

    def __str__(self):
        return json.dumps(
            {'Version': '2012-10-17', 'Statement': self.statements})

    def __contains__(self, statement):
        """Returns True if all of the permissions granted by the provided
        statement are granted in this policy, or if all the
        permissions denied by the provided statement are denied by
        this policy.
        """
        statement = normalize(statement)
        
        # First, let's do an exact search.
        if statement in self.statements:
            return True

        # Filter on effect
        effect_hits = [s for s in self.statements
                       if statement['Effect'] == s['Effect']]
        if not effect_hits:
            return False

        # Filter on condition
        condition_hits = [s for s in effect_hits
                          if statement.get('Condition') == s.get('Condition')]
        if not condition_hits:
            return False
        
        # Filter on action
        action_hits = []
        for s in condition_hits:
            i = statement.get('Action') or statement.get('NotAction', [])
            j = s.get('Action') or s.get('NotAction', [])
            inverted = (('Action' in statement and 'NotAction' in s)
                        or ('NotAction' in statement and 'Action' in s))
            if wildcard_compare(j, i) ^ inverted:
                action_hits.append(s)
        if not action_hits:
            return False

        # Filter on resource
        resource_hits = []
        for s in action_hits:
            i = statement.get('Resource') or statement.get('NotResource', [])
            j = s.get('Resource') or s.get('NotResource', [])
            inverted = (('Resource' in statement and 'NotResource' in s)
                        or ('NotResource' in statement and 'Resource' in s))
            if wildcard_compare(j, i) ^ inverted:
                resource_hits.append(s)
        
        return bool(resource_hits)
