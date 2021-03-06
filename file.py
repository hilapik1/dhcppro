class Constants:
    ATTACK_THRESHOLD =7
    client_port = 68 #src
    server_port = 67
    iface= '\u200F\u200FEthernet'
    MASK_PART = 0
    IP_PART = 1
    STATIC_MASK_PART = "255"
    IP_SAPARATOR ="."
    SUBNET_MASK="255.255.255.0"
    DISCOVER =1#1
    OFFER = 2
    REQUEST = 3
    DECLINE=4
    ACK = 5
    NAK=6
    LEASE_TIME = 20

    MAC_ADDRESS_LENGTH = 17

    OP2CMD = {DISCOVER: "Discover", OFFER: "Offer", REQUEST:  "Request", ACK: "Ack", DECLINE:"Decline"}
    CMD2OP = {"Discover": DISCOVER, "Offer": OFFER, "Request": REQUEST, "Ack": ACK, "Decline":DECLINE}

    def _init_(self):
        pass
