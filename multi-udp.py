import socket
from time import sleep

UDP_IP = "10.0.0.2"
UDP_REL_PORT = 1
MESSAGE = "Hello, World!"

print "UDP target IP:", UDP_IP
print "UDP target port:", UDP_REL_PORT
print "message:", MESSAGE

sock = socket.socket(socket.AF_INET, # Internet
                     socket.SOCK_DGRAM) # UDP
sock.bind(('10.0.0.1',0))
while(1):
	sleep(1)
	UDP_REL_PORT = UDP_REL_PORT + 1
	print UDP_REL_PORT
	sock.sendto(MESSAGE, (UDP_IP, 5000 + (UDP_REL_PORT + 1)%10000))
