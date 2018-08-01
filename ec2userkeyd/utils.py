import re
import pwd
import subprocess


def get_user_from_port(port):
    ss_out = subprocess.check_output(
        ['ss', '-atne', 'sport = :{}'.format(port)])
    uid_match = re.search(" uid:([0-9]+) ", ss_out.decode('utf-8'))

    if uid_match:
        uid = int(uid_match.group(1))
        try:
            username = pwd.getpwuid(uid).pw_name
            return username
        except KeyError:
            return None
    else:
        return None

