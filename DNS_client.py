from socket import *
import logging
import configparser
import struct
import random
import query_builder


config = configparser.ConfigParser()
config.read("config.ini")


# DNS Query Structure: https://learn.microsoft.com/en-us/windows-server/networking/dns/message-formats
# Flags (16 bits):
#   Request / Response: 1-bit field set to 0 for a request / 1 for a response.
#   Operation code: 4-bit field representing the name server operation of the packet, 0x0 is a query
#   Authoritative answer: 1-bit field indicating the responder is authoritative for the queried domain name. 
#   Truncation: 1-bit field set to 1 if the total number of response exceeded the UDP datagram size. Unless UDP datagrams larger than 512 bytes of EDNS0 are enabled, only the first 512 bytes of the UDP reply are returned. 
#   Recursion desired: 1-bit field set to 1 for a recursive query and 0 for iterative queries. If set to 0, the DNS server returns a list of other DNS servers from local cache data. 
#   Recursion available: 1-bit field set by a DNS server to 1 if it can handle recursive queries. If recursion is disabled, the server sets the field appropraitely. 
#   Reserved: 3-bit field that is reserved and set to 0. 
#   Return code: 4 bit field holding the return code:
#       0: Successful response (query answer is in the response)
#       0x3: Name error, indicating that an authoritative DNS server responded that the domain name does not exist.

# building query, we only need flag for request and recursion desired. 
def buildingQuery():
    question_type = {
        "A": 0x01,
        "NS": 0x02,
        "CNAME": 0x05,
        "PTR": 0x0C,
        "MX": 0x0F,
        "SRV": 0x21,
        "IXFR": 0xFB,
        "AXFR": 0xFC,
        "All records": 0xFF,
    }
    def buildingHeader():
        transactionID = random.randbyte(2) #creating two bytes for transaction ID
    pass

def main():
    client_serverPort = config["client"]["client_serverPort"]
    client_IPAddress = config["client"]["client_IPAddress"]
    
    domain = input("what is the URL? ")
    RR = input("what is the RR? ")

    #AF_INET, SOCK_DGRAM - socket is of IPv4 using UDP protocol
    clientSocket = socket(AF_INET, SOCK_DGRAM)
    clientSocket.bind((client_serverPort, client_IPAddress))

    print(f"domain: {domain}\nRR: {RR}")

    while True:
        pass

if __name__ == "__main__":
    main()