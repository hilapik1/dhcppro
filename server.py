import select
import socket
import time
from datetime import datetime
from datetime import date
from scapy.all import *
from scapy.layers.inet import UDP
import scapy.all as scapy

MAX_MSG_LENGTH = 1024
UDP_IP = "172.16.20.211"
UDP_PORT = 2023
#server_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)# UDP
DISCOVER_MESSAGE = "discover"
OFFER_MESSAGE = "offer"
REQUEST_MESSAGE = "request"
ACKNOWLEDGE_MESSSAGE = "acknowledge"
allip = ["172.16.20.212"] #"255.255.255.0"
list_users = [] #id, MAC address, ip
MAX_COUNT = 40
LAST_NUM = 213
IP_FIRST_PART = "172.16.20."
Index = 0

server_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)  # UDP
server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
server_socket.bind((UDP_IP, UDP_PORT))
#server_socket.listen()

def create_ips(LAST_NUM):
    # this for create the ip
    for i in range(MAX_COUNT):
        CREATE_IP = IP_FIRST_PART + str(LAST_NUM)  # "172.16.16.213"
        print(type(CREATE_IP))
        LAST_NUM += 1
        allip.append(CREATE_IP)
        str_index=str(i+1)
        print(type(str_index))
        print("ID: %s" % str_index + " IP address: %s" % str(CREATE_IP))

def filter(packet):
    if UDP in packet:
        if packet[UDP].dport == 2023:
            return True
    return False


while True:
    create_ips(LAST_NUM)
    print("enter to loop")
    try:
        print("enter to try")
        # sock.sendto(bytes("hello", "utf-8"), ip_co)
        p=sniff()
        #data, addr = server_socket.recvfrom(1024) #expecting to recieve discover msg
        pa = sniff(lfilter=filter, iface="Software Loopback Interface 1")
        for packet in pa:
            msg = pa[raw]
            if msg=="discover":
                OFFER_MESSAGE = OFFER_MESSAGE + " " + allip[Index]
                Index += 1
                result = scapy.sr(scapy.Ether(dst="ff:ff:ff:ff:ff:ff") / scapy.IP(dst="255.255.255.255", src="172.16.20.211") / scapy.UDP(sport=2023, dport=2024) / scapy.Raw( OFFER_MESSAGE), verbose=0, timeout=3)
                print("offer msg" + OFFER_MESSAGE)
                pa = sniff(lfilter=filter, iface="Software Loopback Interface 1")
                for packet in pa:
                    msg = pa[raw]
                    message=msg = msg.split(" ")  # ["request",ip adr]
                    ip_adr = message[1]
                    if message.startswith() == REQUEST_MESSAGE:
                        user = "id " + addr + " " + ip_adr
                        list_users.append(user)  # a new user added to the list
                        result2 = scapy.sr(scapy.Ether(dst="ff:ff:ff:ff:ff:ff") / scapy.IP(dst="255.255.255.255",src="172.16.20.211") / scapy.UDP(sport=2023, dport=2024) / scapy.Raw(ACKNOWLEDGE_MESSSAGE), verbose=0, timeout=3)
                    else:
                        print("error")
        #while data != DISCOVER_MESSAGE:
        #    data, addr = server_socket.recvfrom(1024)  # expecting to recieve discover msg
        #    print(data)
        #print(data)
        #print(addr)
        #if data == DISCOVER_MESSAGE:
        #OFFER_MESSAGE = OFFER_MESSAGE + " " +allip[Index]
        #print("offer msg"+ OFFER_MESSAGE)
        #Index += 1
        #server_socket.sendto(bytes(OFFER_MESSAGE, "utf-8"), ("255.255.255.255", 2023))
        #data, addr = server_socket.recvfrom(1024) #expecting to recieve request msg
        #msg = data.split(" ")  # ["request",ip adr]
        #ip_adr = msg[1]

        #if data.startswith() == REQUEST_MESSAGE:
        #    user="id "+addr+" "+ip_adr
        #    list_users.append(user)  # a new user added to the list
        #    server_socket.sendto(bytes(ACKNOWLEDGE_MESSSAGE, "utf-8"), ("255.255.255.255", 2023))
        #else:
            #print("error")
        #else:
            #print("error")
    except:
        print("error")
        continue
print("jjjjj")


def main():
    print("hi")


if __name__ == "__main__":
    main()


