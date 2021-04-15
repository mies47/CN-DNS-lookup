import socket

localIP     = "127.0.0.1"
localPort   = 53
bufferSize  = 1024
 

# Create a datagram socket
UDPServerSocket = socket.socket(family=socket.AF_INET, type=socket.SOCK_DGRAM)

# Bind to address and ip
UDPServerSocket.bind((localIP, localPort))

print("UDP server up and listening...")

# Listen for incoming datagrams

while(True):

    message, address = UDPServerSocket.recvfrom(bufferSize)

    clientMsg = "Message from Client:{}".format(message.decode(encoding='utf-8'))
    clientIP  = "Client IP Address:{}".format(address)
    
    print(clientMsg)
    print(clientIP)

    UDPServerSocket.sendto(str.encode('Message Recieved!'), address)
 