import ipaddress

net4 = ipaddress.ip_network("192.168.10.10/24")
for x in net4.hosts():
    print(f"base ip {x}")