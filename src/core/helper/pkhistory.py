from flask import current_app
from datetime import datetime
from json import dumps

class PowerkatzHistory:
    def __init__(self):
        self.__issuedCommands = dict()
        self.id = 0

    def getIssuedCommands(self):
        return self.__issuedCommands

    def getIssuedCommandsById(self, id):
        return self.__issuedCommands[id]

    def getIssuedCommandsDomain(self):
        issuedCommandsDomain = set()
        for id in self.__issuedCommands:
            issuedCommandDomain = self.__issuedCommands[id]['domain']
            issuedCommandsDomain.add(issuedCommandDomain)

        return issuedCommandsDomain

    def setIssuedCommands(self, executedFunction, targetIpAddress, status, command, result, isFromImporting=False, currentTime=None, domain=None):
        if 'id' not in self.__issuedCommands:
            self.id += 1
            self.__issuedCommands[self.id] = dict()

        if isFromImporting:
            self.__issuedCommands[self.id]['timestamp'] = currentTime
        else:
            # get current time based on the machine's local timezone
            currentTime = datetime.now()
            localTimezone = datetime.now().astimezone().tzinfo
            formattedTime = currentTime.astimezone(localTimezone)
            utcOffset = formattedTime.strftime('%z')
            utcOffsetFormatted = f'{utcOffset[:-2]}:{utcOffset[-2:]}'
            timeString = formattedTime.strftime('%d/%m/%Y %H:%M:%S %Z') + f' (UTC{utcOffsetFormatted})'
            # expected output: 28/12/2023 13:13:00 HKT (UTC+08:00)

            self.__issuedCommands[self.id]['timestamp'] = timeString

        # try to find the target IP address's domain
        if not domain:
            domain = ''
            domains = current_app.config['settings']['targetDomain']
            if not domains:
                domain = '(N/A)'
            else:
                for eachDomain in current_app.config['settings']['targetDomain']:
                    for computer in current_app.config['settings']['targetDomain'][eachDomain]['computers']:
                        computerIpAddress = current_app.config['settings']['targetDomain'][eachDomain]['computers'][computer]['ipAddress']
                        isMatchToComputerIpAddress = True if targetIpAddress == computerIpAddress else False
                        if isMatchToComputerIpAddress:
                            domain = eachDomain
                            break

        self.__issuedCommands[self.id]['executedFunction'] = executedFunction
        self.__issuedCommands[self.id]['targetIpAddress'] = targetIpAddress
        self.__issuedCommands[self.id]['domain'] = domain

        self.__issuedCommands[self.id]['status'] = status
        self.__issuedCommands[self.id]['command'] = command
        self.__issuedCommands[self.id]['executedCommandResult'] = result

    def exportAllHistoryAsJson(self):
        return dumps(self.getIssuedCommands())

    def exportHistoryAsJsonById(self, id):
        output = dict()
        history = self.getIssuedCommandsById(id)
        output[id] = history
        return dumps(output)