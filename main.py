import socket
from time import sleep
from scapy.all import *
from scapy.layers.inet import UDP
import scapy.all as scapy

UDP_IP = "172.16.20.211"
UDP_PORT = 2024
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
sock.bind(("0.0.0.0", 2024))

def filter(packet):
    if UDP in packet:
        if packet[UDP].dport == 2024:
            return True
    return False

while True:
        discover_msg="discover"
        #i = sock.sendto(bytes(DISCOVER_MESSAGE, "utf-8"), ("255.255.255.255", 2023))
        result = scapy.sr(scapy.Ether(dst="ff:ff:ff:ff:ff:ff")/scapy.IP(dst="255.255.255.255",src="0.0.0.0")/scapy.UDP(sport=2024, dport=2023)/scapy.Raw(discover_msg), verbose=0, timeout=3)
        #scapy.sendp(result,count=2,verbose=False)
        #scapy.sr(scapy.Ether(dst="ff:ff:ff:ff:ff:ff")/scapy.IP(dst="255.255.255.255", src="0.0.0.0")/scapy.UDP(sport=2024, dport=2023)/scapy.Raw("discover"), verbose=0, timeout=3)
        #print("sent discover")
        print("sent %s" % discover_msg)
        #data, addr = sock.recvfrom(1024)  # expecting to recieve an offer msg
        pa = sniff(lfilter=filter, iface="Software Loopback Interface 1")
        for packet in pa:
            msg = pa[raw]
            if msg.startswith(OFFER_MESSAGE.encode()):
                 tuple = msg.split(" ") # ["offer",ip adr]
                 ip_adr = msg[1]
                 REQUEST_MESSAGE = REQUEST_MESSAGE + " " + ip_adr
                 result1 = scapy.sr(scapy.Ether(dst="ff:ff:ff:ff:ff:ff") / scapy.IP(dst="255.255.255.255", src="0.0.0.0") / scapy.UDP(sport=2024, dport=2023) / scapy.Raw(REQUEST_MESSAGE), verbose=0, timeout=3)
                 print("sent request")
                 pa = sniff(lfilter=filter, iface="Software Loopback Interface 1")
                 for packet in pa:
                         msg = pa[raw]
                         if msg== ACKNOWLEDGE_MESSSAGE:
                                 print("it works")
                         else:
                                 print("error")

        sleep(1)
        #print("fgdfd")
        #print(data)
        #if data.startswith(OFFER_MESSAGE.encode()):
                #msg=data.split(" ")  #["offer",ip adr]
                #ip_adr=msg[1]
                #REQUEST_MESSAGE=REQUEST_MESSAGE+" "+ip_adr
                #sock.sendto(bytes(REQUEST_MESSAGE, "utf-8"), ("255.255.255.255", 2023))
                #print("sent request")
                #data, addr = sock.recvfrom(1024)  # expecting to recieve an acknowledge msg
                #sleep(1)
                #if data == ACKNOWLEDGE_MESSSAGE:
                #        print("it works")
                #else:
                #        print("error")
        #else:
        #        print("error")