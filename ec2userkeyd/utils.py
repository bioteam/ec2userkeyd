import re
import pwd
import json
import time
import datetime
import platform
import functools
import subprocess


def get_user_from_port(port):
    """Given a TCP source port number, returns the name of the user who
    currently has that port open.

    >>> import socket, getpass
    >>> c = socket.create_connection(('google.com', 80))
    >>> port = c.getsockname()[1]
    >>> username = get_user_from_port(port)
    >>> username == getpass.getuser()
    True

    """
    username = None
    if platform.system() == 'Linux':
        ss_out = subprocess.check_output(
            ['ss', '-atne', 'sport = :{}'.format(port)])
        uid_match = re.search(" uid:([0-9]+) ", ss_out.decode('utf-8'))

        if uid_match:
            uid = int(uid_match.group(1))
            try:
                username = pwd.getpwuid(uid).pw_name
            except KeyError:
                pass

    elif platform.system() == 'Darwin':
        lsof_out = subprocess.check_output(
            ['lsof', '-n', '-i4TCP:{}'.format(port)])
        # extract the third space-separated field of the line that
        # contains :{port}->
        user_match = re.search("^\S+\s+\S+\s+(\S+).*:{}->.*$".format(port),
                               lsof_out.decode('utf-8'),
                               flags=re.MULTILINE)

        if user_match:
            username = user_match.group(1)

    else:
        raise NotImplementedError('Platform {} is not supported'.format(
            platform.system()))
        
    return username


def now():
    """Returns the current time in ISO8501 format.
    """
    return datetime.datetime.now().isoformat()


def assume_role_response(response):
    """Turn the result from an AssumeRole call into a credential response.
    """
    creds = response['Credentials']
    return {
        'Code': 'Success',
        'LastUpdated': now(),
        'Type': 'AWS-HMAC',
        'AccessKeyId': creds['AccessKeyId'],
        'SecretAccessKey': creds['SecretAccessKey'],
        'Token': creds['SessionToken'],
        'Expiration': creds['Expiration'].isoformat()
    }


def make_iam_policy(statements):
    """Turn a list of statements into an IAM policy.
    """
    return json.dumps({'Version': '2012-10-17', 'Statement': list(statements)})


def timed_memoize(timeout=60.0):
    """Memoizer decorator with a dictionary-based cache and a fixed timeout.

    >>> @timed_memoize(0.1)
    ... def circle_area(radius):
    ...     print("computing", radius)
    ...     return 3.14159 * (radius ** 2)
    >>> circle_area(1.0)
    computing 1.0
    3.14159
    >>> circle_area.cache
    {(1.0,): 3.14159}
    >>> circle_area(1.0)
    3.14159
    >>> import time; time.sleep(0.15) # wait a bit
    >>> circle_area(1.0)
    computing 1.0
    3.14159

    Only positional arguments are used as keys for the cache. All
    cache arguments must be hashable, so this will not work to
    decorate a function that takes lists or dictionaries as inputs
    (for example).

    >>> @timed_memoize(0.1)
    ... def circle_areas(radii):
    ...     print("computing", radii)
    ...     return [3.14159 * (r**2) for r in radii]
    >>> circle_areas([1.0, 2.0])
    Traceback (most recent call last):
      ...
    TypeError: unhashable type: 'list'

    If you need to use this decorator for a use case like this,
    convert the unhashable arguments to hashable variants first.

    >>> circle_areas(tuple([1.0, 2.0]))
    computing (1.0, 2.0)
    [3.14159, 12.56636]
    """
    def memoize(obj):
        """Define the cache and expiration structures on the function"""
        obj.cache = {}
        obj.expire = {}
        
        @functools.wraps(obj)
        def memoizer(*args, **kwargs):
            """Determine whether or not to wrap the function, and cache
            the results"""
            if args in obj.expire:
                if time.time() >= obj.expire[args]:
                    del(obj.cache[args])
            if args not in obj.cache:
                obj.cache[args] = obj(*args, **kwargs)
                obj.expire[args] = time.time() + timeout
            return obj.cache[args]
        return memoizer
    return memoize
