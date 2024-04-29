from subprocess import Popen, PIPE
from threading import Thread
from base64 import b64decode
import core.kerberos.tgsrepcrack

class PowerkatzCracker:
    def __init__(self):
        self.__passwordHashFilename = './src/core/cracking_files/password_hash.txt'
        self.__crackingResult = dict()
        self.__keberoastingCrackingResult = dict()
        self.__kerberosTicketDirectory = './src/core/cracking_files/'

        # store all cracked results in this variable.
        # basically acts like a database
        PowerkatzCracker.__crackedResults = dict()

    @staticmethod
    def getCrackedResults():
        return PowerkatzCracker.__crackedResults

    def getCrackedCrackingResults(self):
        crackedResults = dict()
        for k, v in self.__crackingResult.items():
            if v['status'] != 'Cracked':
                continue

            crackedResults[k] = v

        if len(crackedResults) == 0:
            return None

        return crackedResults

    def getFailedCrackingResults(self):
        failedResults = dict()
        for k, v in self.__crackingResult.items():
            if v['status'] != 'Failed':
                continue

            failedResults[k] = v

        if len(failedResults) == 0:
            return None

        return failedResults

    def getCrackingResult(self):
        crackedResults = self.getCrackedCrackingResults()
        failedResults = self.getFailedCrackingResults()

        return crackedResults, failedResults

    def writeHashesToDisk(self):
        ntlmHashes = list()
        for k, v in self.__crackingResult.items():
            ntlmHashes.append(v['ntlmHash'])

        with open(self.__passwordHashFilename, 'w') as fp:
            fp.write('\n'.join(ntlmHashes))

    def appendProcessResult(self, process):
        out, err = process.communicate()
        if out:
            filteredResult = list()
            result = out.decode().strip().split('\n')

            # filter unwanted result
            while('' in result):
                result.remove('')
            for resultOutput in result:
                for value in self.__crackingResult.values():
                    if f'{value["ntlmHash"]}:' not in resultOutput:
                        continue

                    filteredResult.append(resultOutput)

            for crackedHash in filteredResult:
                ntlmHash, clearTextPassword = crackedHash.split(':')

                for value in self.__crackingResult.values():
                    if ntlmHash != value['ntlmHash']:
                        continue

                    value['status'] = 'Cracked'
                    value['clearTextPassword'] = clearTextPassword

    def crackPasswordProcess(self, passwordWordlist):
        crackingProcess = Popen(['hashcat', '--quiet', '-m', '1000', '-a', '0', self.__passwordHashFilename, passwordWordlist], stdout=PIPE)
        self.appendProcessResult(crackingProcess)

    def startPasswordCrackingThread(self, accountsHash, passwordWordlist):
        # get a clean slate of the result
        self.__crackingResult = dict()

        formattedAccountsHash = dict()
        for k, v in accountsHash.items():
            username = k
            ntlmHash = dict(v)['ntlmHash']

            formattedAccountsHash[username] = {
                'status': 'Pending',
                'ntlmHash': ntlmHash,
                'clearTextPassword': ''
            }

        self.__crackingResult = formattedAccountsHash
        self.writeHashesToDisk()

        # check the hash(es) against the hashcat.potfile
        checkPastCrackedProcess = Popen(['hashcat', '-m', '1000', self.__passwordHashFilename, '--show'], stdout=PIPE)
        self.appendProcessResult(checkPastCrackedProcess)

        processThread = Thread(target=self.crackPasswordProcess, args=(passwordWordlist,))
        processThread.start()
        # wait for the prcoess is terminated
        processThread.join()

        for k, v in self.__crackingResult.items():
            # if the status is still "Pending" at this point,
            # the hash didn't cracked, thus mark the cracking status to "Failed"
            if v['status'] == 'Pending':
                self.__crackingResult[k]['status'] = 'Failed'
            # store all cracked results into the "database"
            elif v['status'] == 'Cracked':
                PowerkatzCracker.__crackedResults[k] = v

    def getKerberoastingCrackingResult(self):
        return self.__keberoastingCrackingResult

    def writeKerberosTicketToDisk(self, target, base64String):
        formattedTarget = target.replace('/', '-')
        filename = f'{self.__kerberosTicketDirectory}{formattedTarget}.kirbi'
        with open(filename, 'wb') as fp:
            fp.write(b64decode(base64String))

        return filename

    def appendKerberoastCrackingResult(self, status, crackedPassword, target):
        self.__keberoastingCrackingResult[target] = dict()
        self.__keberoastingCrackingResult[target]['status'] = status
        self.__keberoastingCrackingResult[target]['crackedPassword'] = crackedPassword

    def crackKerberosTicketProcess(self, passwordWordlist, kerberoastTicketFilename, target):
        status, crackedPassword = core.kerberos.tgsrepcrack.crack(kerberoastTicketFilename, passwordWordlist)
        self.appendKerberoastCrackingResult(status, crackedPassword, target)

    def startKeberoastingCrackingThread(self, target, base64String, passwordWordlist):
        # get a clean slate of the result
        self.__keberoastingCrackingResult = dict()

        kerberoastTicketFilename = self.writeKerberosTicketToDisk(target, base64String)

        processThread = Thread(target=self.crackKerberosTicketProcess, args=(passwordWordlist, kerberoastTicketFilename, target))
        processThread.start()
        # wait for the prcoess is terminated
        processThread.join()