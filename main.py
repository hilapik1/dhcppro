import socket
from time import sleep

UDP_IP = "172.16.16.182"
UDP_PORT = 2023
#DISCOVER_MESSAGE = b"discover"
DISCOVER_MESSAGE="discover"
OFFER_MESSAGE="offer"
REQUEST_MESSAGE="request"
ACKNOWLEDGE_MESSSAGE="acknowledge"


print("UDP target IP: %s" % UDP_IP)
print("UDP target port: %s" % UDP_PORT)
print("message: %s" % DISCOVER_MESSAGE)

# sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)  # UDP
# sock.sendto(DISCOVER_MESSAGE, (UDP_IP, UDP_PORT))

sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
#sock.bind(("0.0.0.0", 2023))

while True:

        sock.sendto(bytes(DISCOVER_MESSAGE, "utf-8"), ("255.255.255.255", 2023))
        print("sent discover")
        data, addr = sock.recvfrom(1024)  # expecting to recieve an offer msg
        sleep(1)
        if data.startswith() == OFFER_MESSAGE:
                msg=data.split(" ")  #["offer",ip adr]
                ip_adr=msg[1]
                REQUEST_MESSAGE=REQUEST_MESSAGE+" "+ip_adr
                sock.sendto(bytes(REQUEST_MESSAGE, "utf-8"), ("255.255.255.255", 2023))
                print("sent request")
                data, addr = sock.recvfrom(1024)  # expecting to recieve an acknowledge msg
                sleep(1)
                if data == ACKNOWLEDGE_MESSSAGE:
                        print("it works")
                else:
                        print("error")
        else:
                print("error")