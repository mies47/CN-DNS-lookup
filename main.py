import socket
import random
import struct
import binascii
import sys

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


HOST = '1.1.1.1'
PORT = 53

def constructMessage(domain:str):
    '''
        Constructs the HEADER and Question part of request
        Returns Header, Question and binary reperesentation of constructed request
    '''
    ID = format(random.getrandbits(16), '04x')
    FLAGS = format(0, '04x')
    QDCOUNT = format(1, '04x')
    ANCOUNT = format(0, '04x')
    NSCOUNT = format(0, '04x')
    ARCOUNT = format(0, '04x')
    HEADER = ''.join([ID, FLAGS, QDCOUNT, ANCOUNT, NSCOUNT,ARCOUNT])

    QNAME = ''
    for label in domain.split('.'):
        QNAME += format(len(label), '02x')
        for char in label:
            QNAME += format(ord(char), '02x')
    QNAME += '00'
    QTYPE = format(1 , '04x')
    QCLASS = format(1 , '04x')
    QUESTION = QNAME + QTYPE + QCLASS

    return HEADER, QUESTION, binascii.unhexlify(HEADER + QUESTION)

HEADER, QUESTION, request = constructMessage('www.facebook.com')

data, _ = UDPSocketConnection(HOST, 53, request)
result = binascii.hexlify(data)

print(data)
RESPONSEFLAGS , ANSWER = result[4:8], result[len(QUESTION+HEADER):] 

# print(TTL)
print(result)
print(binascii.unhexlify(RESPONSEFLAGS))
RDDATA = ANSWER[-8:]
IP = '.'.join(list(str(int(RDDATA[i:i+2], 16)) for i in range(0, len(RDDATA), 2)))
print(IP)

