import socket
from time import sleep

UDP_BASE = "10.0.0."
UDP_REL_PORT = 0
UDP_REL_IP   = 0
MESSAGE = "Hello, World!"

print "message:", MESSAGE

sock = socket.socket(socket.AF_INET, # Internet
                     socket.SOCK_DGRAM) # UDP
sock.bind(('10.0.0.1',0))
while(1):
	UDP_REL_PORT = (UDP_REL_PORT + 1)%10
	UDP_REL_IP   = (UDP_REL_IP + 1)%8
	print UDP_REL_PORT, UDP_REL_IP
	sock.sendto(MESSAGE, (UDP_BASE + str(UDP_REL_IP + 2), UDP_REL_PORT + 5000))
