class MacConverter:

    def str_to_bytes(self, mac_addr: str) -> bytes:
        """ Converts a MAC address string to bytes.
        """
        s = mac_addr.replace(":", "")
        int_s = int(s, 16)
        bytes_s = int_s.to_bytes(6, "big")
        return bytes_s
        #return int(mac_addr.replace(":", ""), 16).to_bytes(6, "big")

    def bytes_to_str(self, mac_addr: bytes) -> str:
        mac_s = mac_addr[:6].hex()
        mac_addr = mac_s[:2]
        for i in range(2, len(mac_s), 2):
            mac_addr += ":"
            mac_addr += mac_s[i:i+2]

        return mac_s


        """ Converts a MAC address bytes to string.
        """


    #    return int(mac_addr.replace(":", ""), 16).to_bytes(6, "big")


def main():
    obj = MacConverter()
    obj.bytes_to_str(obj.str_to_bytes("aa:bb:cc:dd:ee:ff"))



if __name__ == "__main__":
    main()