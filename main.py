import socket
import random
import binascii
import sys
import time
import dnslib
import json
import csv
import getopt
from colorama import Fore, Style


HOST = '8.8.8.8'
PORT = 53

rootFile = open('./root-servers.json')
rootServers = json.load(rootFile)

recordTypes = json.load(open('./records.json'))

cacheFile = open('./dnsCache.json', 'r')
cache = json.load(cacheFile)

def UDPSocketConnection(host:str, port:int, message:str):
    '''
        Create a UDP socket connection to the specified
        host on given port
        Sends message
        Returns the result or exits if encountered error
    '''
    try:
        dnsSocket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)  
        dnsSocket.sendto(request, (host, port))
        return dnsSocket.recvfrom(4096)
    except Exception as e:
        print(f'An error occured:\n{e}')
        dnsSocket.close()
        sys.exit()

def constructMessage(domain:str, recordType: str, recursionDesired: bool):
    '''
        Constructs the HEADER and Question part of request based on recordType
        Returns Header, Question and binary reperesentation of constructed request
    '''
    randomID = random.getrandbits(16)
    ID = format(randomID, '04x') # Random generated ID
    print(f'Generated ID is:\t{randomID}')
    FLAGS = ''
    if recursionDesired:
        FLAGS = format(256, '04x') # Recursion desired
        print(f'Flags:\t{FLAGS}(Do query recursively)')
    else:
        FLAGS = format(0, '04x') # Set all Flags to zero(No recursion using iterative Queries)
        print(f'Flags:\t{FLAGS}(No recursion desired, do query by iteration)')
    QDCOUNT = format(1, '04x') # Number of questions
    print(f'Number of questions:\t{QDCOUNT}')
    ANCOUNT = format(0, '04x')
    NSCOUNT = format(0, '04x')
    ARCOUNT = format(0, '04x')
    HEADER = ''.join([ID, FLAGS, QDCOUNT, ANCOUNT, NSCOUNT,ARCOUNT])

    if recordType == 'PTR':
        domain += '.in-addr.arpa'

    QNAME = ''
    # Split domain name by . and encode each one as a label
    for label in domain.split('.'): 
        QNAME += format(len(label), '02x')
        for char in label:
            QNAME += format(ord(char), '02x')
    QNAME += '00' # Specify the end of QNAME section
    QTYPE = format(recordTypes[recordType] , '04x') # Specify record type 
    print(f'Asking for type {recordType} Record!\n')
    QCLASS = format(1 , '04x') # Specify class of request
    QUESTION = QNAME + QTYPE + QCLASS

    return HEADER, QUESTION, binascii.unhexlify(HEADER + QUESTION)

def deconstructFlags(flags:str):
    binaryFlag = bin(int(flags, 16)).zfill(16)[2:]
    AA = binaryFlag[5] # Is this an Authoritative answer
    RCODE = binaryFlag[12:] # 4-bit status of the response 0000 for no error

    return AA, RCODE

def sendRequest(message, record):
    for root in rootServers:
        data, _ = UDPSocketConnection(root['ipv4'], 53, message)
        rootAnswer = dnslib.DNSRecord.parse(data)
        if rootAnswer.header.rcode == 0 and record == 'PTR':
            return rootAnswer
        for tld in rootAnswer.ar:
            if tld.rtype == 1:
                tldData, _ = UDPSocketConnection(str(tld.rdata), 53, message)
                tldAnswer = dnslib.DNSRecord.parse(tldData)
                for ns in tldAnswer.ar:
                    if ns.rtype == 1:
                        auth, _ = UDPSocketConnection(str(ns.rdata), 53, message)
                        authAnswer = dnslib.DNSRecord.parse(auth)
                        if authAnswer.header.aa == 1:
                            return authAnswer

def parseAnswer(result):
    RESPONSEFLAGS , ANSWER = result[4:8], result[len(QUESTION+HEADER):]

    AA, RCODE = deconstructFlags(RESPONSEFLAGS)
    if RCODE == '0000': # No Errors
        TYPE = int(ANSWER[4:8], 16)
        TTL = int(ANSWER[12:20], 16)
        RDLENGTH = int(ANSWER[20:24], 16)
        RDDATA = ANSWER[-RDLENGTH*2:]
        IP = '.'.join(list(str(int(RDDATA[i:i+2], 16)) for i in range(0, len(RDDATA), 2)))
        print('No Errors Encountered.')
        print(f'Requested Domain:\t{domainName}')
        print(f'TTL(Time To Live):\t{TTL} seconds')
        print(f'Asked {HOST} for IP')
        print(f'The IP is:\t{IP}')

    else:
        print(RCODE)

def parseArgs():
    args = sys.argv[1:]

    options = {}

    try:
        allOpt, allArgs = getopt.getopt(args, "hd:i:o:r:R:", ["help", "domain_name=", "input=", "output=", "record=", "Recur"])
        for opt, value in allOpt:
            if opt in ['-h', '--help']:
                printHelp()
                sys.exit()
            elif opt in ['-d', '--domain_name']:
                options['domain'] = value
            elif opt in ['-i', '--input']:
                options['input'] = value
            elif opt in ['-o', '--output']:
                options['output'] = value
            elif opt in ['-r', '--record']:
                if value not in recordTypes.keys():
                    print(Fore.RED , 'Record type not supported!')
                    sys.exit(2)
                options['record'] = value
            elif opt in ['-R', '--Recur']:
                options['recursion'] = True
        
        optionsKeys = options.keys()
        if 'domain' not in optionsKeys and ('input' not in optionsKeys or 'output' not in optionsKeys):
            print(Fore.RED + 'Please provide domain name or use an input file!!!')
            sys.exit(2)
        if 'record' not in optionsKeys:
            options['record'] = 'A' #Default look for A records
        if 'recursion' not in optionsKeys:
            options['recursion'] = False #Default do query by iteration
    except:
        sys.exit(2)

    return options

def readInputDomains(options):
    if 'domain' in options:
        domainName = options['domain']
        return True, domainName
    else:
        try:
            inputCSV = csv.reader(open(options['input']), delimiter=',')
            return False, inputCSV
        except Exception as error:
            print(Fore.RED + str(error))
            sys.exit(2)

def hasAnswerInCache(typeRecord:str ,domainName:str):
    if typeRecord in cache:
        if domainName in cache[typeRecord]:
            cache[typeRecord][domainName]['count'] += 1
            if cache[typeRecord][domainName]['count'] >= 3:
                return cache[typeRecord][domainName]['data']
            else:
                return False
        else:
            cache[typeRecord][domainName] = {'count': 1}
            return False
    else:
        cache[typeRecord] = {domainName: {'count': 1}}
        return False

def writeToCache(typeRecord:str ,domainName:str, datas):
    cache[typeRecord][domainName]['data'] = datas

def printCache(domainName, typeRec, cacheAnswer):
    print(Fore.GREEN, 20*'-', 'Answer Section', 20*'-')
    print(f'Name {domainName} of type {typeRec} is used more than 3 times. Got results from cache!\n')
    print('RName\t\tRType\tTTL\tRData')
    for ans in cacheAnswer:
        print(f"{ans['rname']}\t{ans['rtype']}\t{ans['ttl']}\t{ans['rdata']}\n")

def printHelp():
    print(Fore.WHITE+'This is a dns lookup tool written for Computer Networks course.\n')
    print('Syntax: python3 main.py [-h|r|R] [-d|io]')
    print('options:')
    print('h|help\t\t\tShow this help menu and exit')
    print('d|domain_name\t\tGive domain name you are seeking for its IP')
    print('i|input\t\t\tThe input path of csv file with domainName and recordType')
    print('o|output\t\tThe path of output.csv')
    print(Fore.RED,'--note: Either -d or -io option should be specified.')
    print(Fore.WHITE+'r|record\t\tOne of the [A, NS, CNAME, SOA, PTR, MX, TXT, AAAA] record types(default is A)')
    print('R|Recur\t\t\tAsk to do the query recursively(default is iterative)')


options = parseArgs()
isSingleDomain, domainName = readInputDomains(options)

if isSingleDomain:
    try:
        print(Fore.YELLOW, 20*'-', 'Question Section', 20*'-')
        HEADER, QUESTION, request = constructMessage(domainName, options['record'], options['recursion'])

        cacheAnswer = hasAnswerInCache(options['record'], domainName)
        if cacheAnswer:
            printCache(domainName, options['record'],cacheAnswer)
        else:        
            startTime = time.time()
            answer = sendRequest(request, options['record'])
            endTime = time.time()
            print(Fore.WHITE, f'\nGot results in {endTime - startTime} seconds\n')

            print(Fore.GREEN, 20*'-', 'Answer Section', 20*'-')
            print(answer)
            print(Style.RESET_ALL)
            writeToCache(options['record'], domainName, [{'rname': str(rr.rname), 'rtype': int(rr.rtype), 'ttl': int(rr.ttl), 'rdata': str(rr.rdata)} for rr in answer.rr])
    except Exception as error:
        print(Fore.RED, error)
        sys.exit(2)
else:
    try:
        csvOutput = csv.writer(open(options['output'], 'w'), delimiter=',')
        csvOutput.writerow(['rname', 'rtype', 'ttl', 'rdata'])
        for name, record in domainName:
            if record not in recordTypes:
                print(Fore.RED , 'Record type not supported!')
                sys.exit(2)
            print(Fore.YELLOW, 20*'-', 'Question Section', 20*'-')
            HEADER, QUESTION, request = constructMessage(name, record.strip(), options['recursion'])
            if cacheAnswer:
                printCache(domainName, options['record'],cacheAnswer)
            else:
                startTime = time.time()
                answer = sendRequest(request, record.strip())
                endTime = time.time()
                print(Fore.WHITE, f'\nGot results in {endTime - startTime} seconds\n')

                for rr in answer.rr:
                    csvOutput.writerow([rr.rname, str(rr.rtype), rr.ttl, rr.rdata])
                for ar in answer.ar:
                    csvOutput.writerow([ar.rname, str(ar.rtype), ar.ttl, ar.rdata])
                print(Fore.GREEN, 20*'-', 'Saved in csv!', 20*'-')
                print(Style.RESET_ALL)
                writeToCache(options['record'], domainName, [{'rname': str(rr.rname), 'rtype': int(rr.rtype), 'ttl': int(rr.ttl), 'rdata': str(rr.rdata)} for rr in answer.rr])
    except Exception as error:
        print(Fore.RED, error)
        sys.exit(2)
    
cacheFile = open('./dnsCache.json', 'w')
json.dump(cache, cacheFile)


