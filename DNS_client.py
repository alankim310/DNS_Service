from socket import *
import logging
import configparser
import struct
from DNS_question_query import *
from DNS_parser import *


config = configparser.ConfigParser()
config.read("config.ini")

def main():
    client_serverPort = config["client"]["client_serverPort"]
    client_IPAddress = config["client"]["client_IPAddress"]
    resolver_serverPort = config["local_resolver"]["resolver_serverPort"]
    resolver_IPAddress = config["local_resolver"]["resolver_IPAddress"]


    #AF_INET, SOCK_DGRAM - socket is of IPv4 using UDP protocol
    clientSocket = socket(AF_INET, SOCK_DGRAM)
    clientSocket.bind((client_IPAddress, int(client_serverPort)))
    
    questionName = input("what is the question name? ")
    questionType = input("what is the question type? ").upper()

    requestQueryInterface = questionQuery(questionName= questionName, 
                                 questionType= questionType)

    requestQuery = requestQueryInterface.buildingQuery()

    clientSocket.sendto(requestQuery, (resolver_IPAddress, int(resolver_serverPort)))

    modifiedMessage, serverAddress = clientSocket.recvfrom(2048)
    print(f"From Server: message {modifiedMessage}")

    parsedJSON = DNSParser(modifiedMessage).parsedJson

    print(parsedJSON)




    clientSocket.close()


if __name__ == "__main__":
    main()