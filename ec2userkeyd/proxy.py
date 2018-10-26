import os
import atexit
import datetime
import subprocess

import logging
logger = logging.getLogger(__name__)

import requests
from flask import Flask, jsonify, request, abort

from ec2userkeyd import utils, config, methods


app = Flask('ec2userkeyd')


###
### Flask routes

@app.route('/<rev>/meta-data/iam/security-credentials/<role>')
def role_data(rev, role):
    remote_port = request.environ.get('REMOTE_PORT')
    username, uid = utils.get_user_from_port(remote_port)

    for method in methods.sequence_for(username, uid):
        try:
            credentials = method.get(username, role)
        except:
            logger.exception(f'Exception from {method}')
            abort(500)
        
        if credentials:
            logger.info(f'issued {method} {username}'
                        f' {credentials["AccessKeyId"]}')
            return jsonify(credentials)
        else:
            logger.debug(f'failed {method} {username}')

    # No credentials were found...
    abort(404)


@app.route('/', defaults={'path': ''})
@app.route('/<path:path>')
def catch_all(path):
    if not path:
        logger.debug('catch_all retrieved root')
    return requests.get('http://169.254.169.254/' + path).text


###
### iptables

class Iptables:
    RULE_BASE = 'OUTPUT -d 169.254.169.254 -p tcp --dport 80'
    RULES = [
        # Immediately pass through any request coming from root
        RULE_BASE + ' -m owner --uid-owner 0 -j ACCEPT',
        # Send all other requests to us
        RULE_BASE + ' -j DNAT --to 127.0.0.1:{port}'
    ]

    def __init__(self, flask_port):
        self.rules = [r.format(port=flask_port).split() for r in self.RULES]

    def activate(self):
        if os.getuid() != 0:
            return

        for rule in self.rules:
            subprocess.check_call([config.general.iptables, '-t', 'nat',
                                   '-A'] + rule)

        atexit.register(self.deactivate)

    def deactivate(self):
        if os.getuid() != 0:
            return

        for rule in self.rules:
            subprocess.check_call([config.general.iptables, '-t', 'nat',
                                   '-D'] + rule)
