import ipaddress

net4 = ipaddress.ip_network('192.0.2.0/26')
ip="192.168.1.3"
for x in net4.hosts():
    print(x)
print(net4.netmask)
# 128 + 64 + 32 + 16 + 8