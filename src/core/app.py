from flask import Flask, render_template, request, current_app, redirect, url_for
from core.api import api, getWordlistFullPath, powerkatzAgent
from functools import wraps
from re import search
from ipaddress import ip_network
import os
import netifaces
import core.helper.pkhistory
import core.helper.pkencryptor

app = Flask(__name__)
app.register_blueprint(api)

def cleanup():
    CLEANUP_PATHS = (
        './src/core/static/transferFiles/payloadExecutables/',
        './src/core/cracking_files/',
    )
    for path in CLEANUP_PATHS:
        for filename in os.listdir(path):
            # don't delete the README file
            if filename == 'README.md':
                continue

            filePath = os.path.join(path, filename)
            try:
                if os.path.isfile(filePath):
                    os.unlink(filePath)
            except Exception as error:
                print(f'[ERROR] Failed to delete file contents at {filePath}. Error: {error}')

def getAttackerIpAddress():
    interfaces = netifaces.interfaces()

    # get the first valid interface
    for interface in interfaces:
        if interface == 'lo' or interface == 'ligolo':
            continue

        addresses = netifaces.ifaddresses(interface)
        if netifaces.AF_INET in addresses:
            ipv4Addresses = addresses[netifaces.AF_INET]
            for address in ipv4Addresses:
                ip = address['addr']
                return interface, ip

def getAllIpInterfacesDetail():
    ipInterfaces = dict()
    interfaces = netifaces.interfaces()
    for interface in interfaces:
        # exclude local loopback and ligolo interface
        if interface == 'lo' or interface == 'ligolo':
            continue

        addresses = netifaces.ifaddresses(interface)
        if netifaces.AF_INET in addresses:
            ipInterfaces[interface] = dict()
            ipv4Addresses = addresses[netifaces.AF_INET]
            for address in ipv4Addresses:
                ip = address['addr']
                netmask = address['netmask']
                network = str(ip_network(f'{ip}/{netmask}', strict=False))

                ipInterfaces[interface]['network'] = network

    return ipInterfaces

# global variables
app.config['settings'] = dict()
app.config['settings']['generalSettings'] = dict()
app.config['settings']['otherGeneralSettings'] = dict()
app.config['settings']['targetComputer'] = dict()
app.config['settings']['targetDomain'] = dict()
app.config['settings']['executor'] = dict()

DEFAULT_WORDLIST = 'rockyou.txt'
app.config['settings']['otherGeneralSettings']['passwordCrackingWordlist'] = getWordlistFullPath(DEFAULT_WORDLIST)
app.config['settings']['otherGeneralSettings']['isRegistered'] = False

attackerNetworkInterface, attackerIpAddress = getAttackerIpAddress()
app.config['settings']['otherGeneralSettings']['attackerNetworkInterface'] = attackerNetworkInterface
app.config['settings']['otherGeneralSettings']['attackerIpAddress'] = attackerIpAddress
app.config['settings']['otherGeneralSettings']['interfacesDetail'] = getAllIpInterfacesDetail()

app.config['powerkatzHistoryObject'] = core.helper.pkhistory.PowerkatzHistory()
app.config['AESEncryptorObject'] = core.helper.pkencryptor.AESEncryptor()

def checkIsRegistered(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        isRegistered = current_app.config['settings']['otherGeneralSettings']['isRegistered']
        if not isRegistered:
            return redirect(url_for('initialSetup'))
        return f(*args, **kwargs)
    return decorated_function

@app.route('/', methods=('GET',))
@checkIsRegistered
def index():
    title = 'Dashboard'

    allAgents = powerkatzAgent.getAllAgentsInformation()

    return render_template('dashboard.html', currentAppConfig=current_app.config, agentsInformation=allAgents, title=title, splitInHalf=True)

@app.route('/powerkatz-server-listener', methods=('GET',))
@checkIsRegistered
def powershellServerListenerPage():
    title = 'Powerkatz Server Listener'

    return render_template('powerkatz-server-listener.html', currentAppConfig=current_app.config, title=title, splitInHalf=False)

@app.route('/history', methods=('GET',))
@checkIsRegistered
def historyPage():
    title = 'History'
    issuedCommands = current_app.config['powerkatzHistoryObject'].getIssuedCommands()
    issuedCommandsDomain = current_app.config['powerkatzHistoryObject'].getIssuedCommandsDomain()

    return render_template('history.html', currentAppConfig=current_app.config, issuedCommands=issuedCommands, issuedCommandsDomain=issuedCommandsDomain, title=title, splitInHalf=False)

@app.route('/settings', methods=('GET',))
@checkIsRegistered
def settings():
    title = 'Settings'

    return render_template('settings.html', title=title, currentAppConfig=current_app.config, splitInHalf=False)

@app.route('/executor', methods=('GET',))
@checkIsRegistered
def executor():
    title = 'Executor'

    return render_template('executor.html', title=title, currentAppConfig=current_app.config, splitInHalf=False)

@app.route('/automate-executor', methods=('GET',))
@checkIsRegistered
def automateExecutor():
    title = 'Automate Executor'

    return render_template('automate-executor.html', title=title, currentAppConfig=current_app.config)

@app.route('/initial-setup', methods=('GET',))
def initialSetup():
    title = 'Initial Setup'
    isRegistered = current_app.config['settings']['otherGeneralSettings']['isRegistered']
    if isRegistered:
        return redirect(url_for('index'))

    return render_template('initial-setup.html', title=title, currentAppConfig=current_app.config)