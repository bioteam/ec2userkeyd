# Functions related to command-line use

from ec2userkeyd import proxy, methods

def cli(cfgfile):
    config.update(cfgfile)

def daemon():
    # Instantiate credential methods
    proxy.credential_methods = [
        getattr(methods, method_name)()
        for method_name in config.general.credential_methods
    ]
    # Set up iptables rules. Note that there is a brief race here
    # where credential requests may be rejected until the Flask app
    # starts up. There doesn't seem to be a good way to get this to
    # run after Flask starts...
    proxy.Iptables(config.general.daemon_port).activate()
    # Start the daemon
    proxy.app.run()
