import socket
from time import sleep

UDP_IP = "172.16.16.182"
UDP_PORT = 2023
DISCOVER_MESSAGE = b"discover"

print("UDP target IP: %s" % UDP_IP)
print("UDP target port: %s" % UDP_PORT)
print("message: %s" % DISCOVER_MESSAGE)

# sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)  # UDP
# sock.sendto(DISCOVER_MESSAGE, (UDP_IP, UDP_PORT))

sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
#sock.bind(("0.0.0.0", 2023))

while True:

        sock.sendto(bytes("discover", "utf-8"), ("255.255.255.255", 2023))
        print("sent")
        data, addr = sock.recvfrom(1024)
        sleep(1)