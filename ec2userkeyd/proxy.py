import os
import atexit
import datetime
import subprocess

import requests
from flask import Flask, jsonify, request, abort

from ec2userkeyd import utils


app = Flask('ec2userkeyd')

# This will be overridden when the app starts up.
credential_methods = []

###
### Flask routes

@app.route('/<rev>/meta-data/iam/security-credentials/<role>')
def role_data(rev, role):
    remote_port = request.environ.get('REMOTE_PORT')
    username = utils.get_user_from_port(remote_port)

    for method in credential_methods:
        credentials = method.get(username, role)
        if credentials:
            return jsonify(credentials)

    # No credentials were found...
    abort(404)


@app.route('/', defaults={'path': ''})
@app.route('/<path:path>')
def catch_all(path):
    return requests.get('http://169.254.169.254/' + path).text
    #return requests.get('http://127.0.0.1/' + path).text
    #return 'hello'


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
            subprocess.check_call(['iptables', '-t', 'nat', '-A'] + rule)

        atexit.register(self.deactivate)

    def deactivate(self):
        if os.getuid() != 0:
            return

        for rule in self.rules:
            subprocess.check_call(['iptables', '-t', 'nat', '-D'] + rule)
