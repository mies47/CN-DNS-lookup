import socket
import random
import struct
import binascii
import sys
import time
import dnslib
import json

f = open('./root-servers.json')
rootServers = json.load(f)

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


# HOST = '198.41.0.4'
HOST = '127.0.0.1'
PORT = 53

def constructMessage(domain:str):
    '''
        Constructs the HEADER and Question part of request
        Returns Header, Question and binary reperesentation of constructed request
    '''
    ID = format(random.getrandbits(16), '04x') # Random generated ID
    print(f'Generated ID is:\t{ID}')
    FLAGS = format(0, '04x') # Set all Flags to zero(No recursion using iterative Queries)
    print(f'Flags:\t{FLAGS}(No recursion desired, do query by iteration)')
    QDCOUNT = format(1, '04x') # Number of questions
    print(f'Number of questions:\t{QDCOUNT}')
    ANCOUNT = format(0, '04x')
    NSCOUNT = format(0, '04x')
    ARCOUNT = format(0, '04x')
    HEADER = ''.join([ID, FLAGS, QDCOUNT, ANCOUNT, NSCOUNT,ARCOUNT])

    QNAME = ''
    # Split domain name by . and encode each one as a label
    for label in domain.split('.'): 
        QNAME += format(len(label), '02x')
        for char in label:
            QNAME += format(ord(char), '02x')
    QNAME += '00' # Specify the end of QNAME section
    QTYPE = format(1 , '04x') # Specify record type 1 for A records
    print(f'Asking for type A Record!')
    QCLASS = format(1 , '04x') # Specify class of request
    QUESTION = QNAME + QTYPE + QCLASS

    return HEADER, QUESTION, binascii.unhexlify(HEADER + QUESTION)

def deconstructFlags(flags:str):
    binaryFlag = bin(int(flags, 16)).zfill(16)[2:]
    AA = binaryFlag[5] # Is this an Authoritative answer
    RCODE = binaryFlag[12:] # 4-bit status of the response 0000 for no error

    return AA, RCODE

def parseAnswer(result):
    packet = binascii.unhexlify(result)
    x = dnslib.DNSRecord.parse(packet)
    # print(x.ar)
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

# if len(sys.argv) < 2:
#     print('Please provide required args!!')
#     sys.exit()

# domainName = sys.argv[-1:][0]
domainName = input()
print(20*'-', 'Question Section', 20*'-')
HEADER, QUESTION, request = constructMessage(domainName)

startTime = time.time()
data, _ = UDPSocketConnection(HOST, 53, request)
endTime = time.time()
print(f'\nGot results in {endTime - startTime} seconds\n')
result = binascii.hexlify(data)

print(20*'-', 'Answer Section', 20*'-')
parseAnswer(result)

