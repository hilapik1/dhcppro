import select
import socket
import time
from datetime import datetime
from datetime import date

MAX_MSG_LENGTH = 1024
UDP_IP = "172.16.16.182"
UDP_PORT = 2023
MIN_NUM=0
MAX_NUM=10000
#server_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)# UDP


server_socket= socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)  # UDP
server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
server_socket.bind((UDP_IP, UDP_PORT))
#server_socket.listen()

while True:

    try:
        # sock.sendto(bytes("hello", "utf-8"), ip_co)
        data, addr = server_socket.recvfrom(1024)
        print(data)
        print(addr)
        server_socket.sendto(bytes("offer", "utf-8"), ("255.255.255.255", 2023))
    except:
        continue


def main():
    print("hi")


if __name__ == "__main__":
    main()


