#!/usr/bin/env python3
import core.app
import core.helper.pklogging
from subprocess import check_output, CalledProcessError
from os import geteuid, environ, execlpe
from sys import executable, argv
from getpass import getuser

def setupLigoloNgInterface():
    noLigoloNgInterface = False
    command = ['/usr/bin/ip a | grep "ligolo"']
    try:
        output = check_output(command, shell=True).decode().strip()
    except CalledProcessError as error:
        noLigoloNgInterface = True

    currentUsername = getuser()
    if noLigoloNgInterface:
        command = [f'/usr/bin/ip tuntap add user {currentUsername} mode tun ligolo']
        check_output(command, shell=True)
        command = ['/usr/bin/ip link set ligolo up']
        check_output(command, shell=True)
    else:
        if 'UP' not in output:
            command = ['/usr/bin/ip link set ligolo up']
            check_output(command, shell=True)

if __name__ == '__main__':
    isRunningAsRoot = True if geteuid() == 0 else False
    if not isRunningAsRoot:
        # core.helper.pklogging.info('The Powerkatz Flask web application must be running as the root user! Re-running the script as the root user...')
        print('[INFO] The Powerkatz Flask web application must be running as the root user! Re-running the script as the root user...')
        # from https://stackoverflow.com/questions/5222333/authentication-in-python-script-to-run-as-root
        args = ['sudo', executable] + argv + [environ]
        execlpe('sudo', *args)

    setupLigoloNgInterface()

    # isInDevelopment = True
    isInDevelopment = False
    ALL_INTERFACES = '0.0.0.0'
    HTTPS_PORT_NUMBER = 443
    SSL_PRIVATE_KEY_FILE = './src/core/ssl_cert/priv_key.pem'
    SSL_CERTIFICATE_FILE = './src/core/ssl_cert/cert.pem'

    try:
        core.app.cleanup()
        if isInDevelopment:
            core.app.app.run(host=ALL_INTERFACES, port=HTTPS_PORT_NUMBER, debug=True, ssl_context=(SSL_CERTIFICATE_FILE, SSL_PRIVATE_KEY_FILE))
        else:
            core.app.app.run(host=ALL_INTERFACES, port=HTTPS_PORT_NUMBER, ssl_context=(SSL_CERTIFICATE_FILE, SSL_PRIVATE_KEY_FILE))

            # TODO: use Gunicorn and gevent to serve the web app
            # from gevent import monkey
            # monkey.patch_all()
            # from gevent.pywsgi import WSGIServer

            # print('[INFO] Starting the Powerkatz Flask web application...')
            # http_server = WSGIServer((ALL_INTERFACES, HTTPS_PORT_NUMBER), app.app, keyfile=SSL_PRIVATE_KEY_FILE, certfile=SSL_CERTIFICATE_FILE)
            # http_server.serve_forever()
    except KeyboardInterrupt:
        core.app.cleanup()