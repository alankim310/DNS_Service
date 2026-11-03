import logging
from socket import *

_SERVER_PORT = 10000
_IP_ADDRESS = "127.0.0.1"

def main():
    domain = input("what is the URL? ")
    RR = input("what is the RR? ")

    #AF_INET, SOCK_DGRAM - socket is of IPv4 using UDP protocol
    clientSocket = socket(AF_INET, SOCK_DGRAM)
    clientSocket.bind((_IP_ADDRESS, _SERVER_PORT))

    print(f"domain: {domain}\nRR: {RR}")

if __name__ == "__main__":
    main()