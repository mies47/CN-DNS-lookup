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

rootFile = open('./root-servers.json')
rootServers = json.load(rootFile)

recordTypes = json.load(open('./records.json'))

testcsvf = open('./test.csv')
csvtest = csv.reader(testcsvf, delimiter=',')

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
    ID = format(random.getrandbits(16), '04x') # Random generated ID
    print(f'Generated ID is:\t{ID}')
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
        print(rootAnswer)
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
                print('help')
                sys.exit()
            elif opt in ['-d', '--domain_name']:
                options['domain'] = value
            elif opt in ['-i', '--input']:
                options['input'] = value
            elif opt in ['-o', '--output']:
                options['output'] = value
            elif opt in ['-r', '--record']:
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

HOST = '1.1.1.1'
PORT = 53
options = parseArgs()
isSingleDomain, domainName = readInputDomains(options)

if isSingleDomain:
    try:
        print(Fore.GREEN, 20*'-', 'Question Section', 20*'-')
        HEADER, QUESTION, request = constructMessage(domainName, options['record'], options['recursion'])

        startTime = time.time()
        print(Fore.YELLOW, 20*'-', 'Whats Going On', 20*'-')
        answer = sendRequest(request, options['record'])
        endTime = time.time()
        print(Fore.WHITE, f'\nGot results in {endTime - startTime} seconds\n')

        print(Fore.GREEN, 20*'-', 'Answer Section', 20*'-')
        print(answer)
        print(Style.RESET_ALL)
    except Exception as error:
        print(Fore.RED, error)
        sys.exit(2)
else:
    print('hi')


