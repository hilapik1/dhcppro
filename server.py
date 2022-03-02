import select
import socket
import time
from datetime import datetime
from datetime import date

MAX_MSG_LENGTH = 1024
UDP_IP = "172.16.16.182"
UDP_PORT = 2023
#server_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)# UDP
DISCOVER_MESSAGE = "discover"
OFFER_MESSAGE = "offer"
REQUEST_MESSAGE = "request"
ACKNOWLEDGE_MESSSAGE = "acknowledge"
allip = ["172.16.16.183"] #"255.255.255.0"
list_users = [] #id, MAC address, ip
MAX_COUNT = 70
LAST_NUM = 184
IP_FIRST_PART = "172.16.16."
Index=0

server_socket= socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)  # UDP
server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
server_socket.bind((UDP_IP, UDP_PORT))
#server_socket.listen()

# this for create the ip
for i in range (MAX_COUNT):
    CREATE_IP = IP_FIRST_PART + str(LAST_NUM)  # "172.16.16.184"
    LAST_NUM += 1
    allip.append(CREATE_IP)



while True:

    try:
        # sock.sendto(bytes("hello", "utf-8"), ip_co)
        data, addr = server_socket.recvfrom(1024) #expecting to recieve discover msg
        print(data)
        print(addr)
        if data == DISCOVER_MESSAGE:
            OFFER_MESSAGE=OFFER_MESSAGE+" "+allip[Index]
            Index+=1
            server_socket.sendto(bytes(OFFER_MESSAGE, "utf-8"), ("255.255.255.255", 2023))
            data, addr = server_socket.recvfrom(1024) #expecting to recieve request msg
            msg = data.split(" ")  # ["request",ip adr]
            ip_adr = msg[1]
            print(data)
            print(addr)
            if data.startswith() == REQUEST_MESSAGE:
                user="id "+addr+" "+ip_adr
                list_users.append(user)  # a new user added to the list
                server_socket.sendto(bytes(ACKNOWLEDGE_MESSSAGE, "utf-8"), ("255.255.255.255", 2023))
            else:
                print("error")
        else:
            print("error")
    except:
        continue


def main():
    print("hi")


if __name__ == "__main__":
    main()


