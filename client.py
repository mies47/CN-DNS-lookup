import socket

def UDPSocketConnection(host:str, port:int, message:str):
    '''
        Create a UDP socket connection to the specified
        host on given port
        Sends message
        Returns the result or exits if encountered error
    '''
    try:
        dnsSocket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        dnsSocket.sendto(str.encode(message), (host, port))
        return dnsSocket.recvfrom(4096)
    except Exception as e:
        print(f'An error occured:\n{e}')
        dnsSocket.close()
        sys.exit()

data, _ = UDPSocketConnection('127.0.0.1', 53, 'Test Message To Server!')

print(f'Server Respose:{data.decode(encoding="utf-8")}')