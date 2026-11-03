from socket import *
import logging
import select
import time

_SERVER_PORT = 1053
_IP_ADDRESS = "127.0.0.1"
_DEFAULT_UPSTREAM_RESOLVER = "8.8.8.8"
_DEFAULT_DNS_SERVER_PORT = 53
# dict that maps a dict to serverSocket so when receiving response from DNS server, it knows what client to send the response to. 
# value dict includes clientAddress, clientPort, query, time at which we requested to DNS server (requestTime), number of attempt (attempt) (max 3), dns server address (dns_server), and dns server port number (dns_server_port)
pending_sockets = {}


# logging configuration
logging.basicConfig(
    filename="DNS_Response.txt",
    level=logging.INFO,
    format="%(asctime)s - %(message)s"
)
logger = logging.getLogger(__name__)

# forwarding_DNS_qeury:
# takes in query, clientaddress, clientport, DNS server (string IP address, defaulted to 8.8.8.8), dns server port (defaulted to 53)
# Create a new DNSSocket object and add to pending_socket, in which when we get response, main will get clientAddress and clientPort to send the response back to the client in the main function.
def forwarding_DNS_query(query, clientAddress, clientPort, dns_server = _DEFAULT_UPSTREAM_RESOLVER, dns_server_port = _DEFAULT_DNS_SERVER_PORT):
    # You cannot use local host to connect to an IP address outside of your computer. Therefore creating a new socket. 
    DNSSocket = socket(AF_INET, SOCK_DGRAM)
    DNSSocket.setblocking(False)
    DNSSocket.sendto(query, (dns_server, dns_server_port)) #forward DNS query to upstream resolver
    #response, dns_serverAddress = Socket.recvfrom(2048)
    pending_sockets[DNSSocket] = {
        "clientAddress": clientAddress,
        "clientPort": clientPort,
        "query": query,
        "requestTime": time.time(),
        "attempt": 1,
        "dns_server": dns_server,
        "dns_server_port": dns_server_port,
    }

    return None


# logging_response
# Takes in DNS response. 
# Parse and extract query names / types and response sizes then log into logging/DNS_Response.txt
def logging_response(response):

    #DNS response structure https://learn.microsoft.com/en-us/windows-server/networking/dns/message-formats
    # Header (12 bytes) - Transaction ID, Flags, Question Resource Record count, Answer Resource Record count, Authority Resource Record count, Additional Resource Record count
    
    # DNS query question entries (variable size) 
        # one  byte field indicating the length of the label (e.g. microsoft.com is 0x09microsoft0x03com0x00)
        # Question Type (2 bytes)
            # 0x01 - A
            # 0x02 - NS
            # 0x05 - CNAME
            # 0x0C - PTR
            # 0x1C - AAAA
            # 0x0F - MX
            # 0x21 - SRV
            # 0xFB - IXFR
            # 0xFC - AXFR
            # 0xFF - All records
    
    #extract query name, then return the query name and the first byte of query type. 
    def extracting_query_name():
        domain_name_list_string = [] # list of domain strings in str format
        domain_name_list_byte = [] #list of domain strings in byte
        query_name_size = response[12]
        next_character = 13
        while query_name_size != 0x00:
            domain_name_list_byte.append(response[next_character:next_character+query_name_size])
            next_length_index = next_character + query_name_size
            next_character = next_length_index + 1
            query_name_size = response[next_length_index]

        for i in range(len(domain_name_list_byte)):
            string_format_domain_name = domain_name_list_byte[i].decode("utf-8")
            domain_name_list_string.append(string_format_domain_name)
        #next_character returns the first byte of the two bytes for query type
        return (".".join(domain_name_list_string), next_character)


    def extracting_query_type(first_byte):
        byte_to_query_type = {
            0x01: "A",
            0x02: "NS",
            0x05: "CNAME",
            0x0C: "PTR",
            0x0F: "MX",
            0x21: "SRV",
            0xFB: "IXFR",
            0xFC: "AXFR",
            0xFF: "All records",
            0x1C: "AAAA",
        }

        query_type_bytes = (response[first_byte] << 8) | (response[first_byte + 1])
        return byte_to_query_type.get(query_type_bytes, "Unknown")

    domain_name, first_byte = extracting_query_name()
    query_type = extracting_query_type(first_byte)
    response_size = len(response)
    logger.info(f"Domain Name: {domain_name}, Query Type: {query_type}, Response Size {response_size}")

    return None

#retries: 
# checks all pending_sockets and see if any of them didn't get a response for more than 2 seconds. If so, retry up to three attempt. 
def retries():
    pending_sockets_copy = pending_sockets.copy()
    for pending_socket in pending_sockets_copy.keys():
        value_dict = pending_sockets[pending_socket]
        attempt, requestTime = value_dict.get("attempt"), value_dict.get("requestTime")

        if time.time() - requestTime > 2 and attempt < 3: #it has been more than 2 seconds since query request
            #print(f"Failed to get DNS response. Retrying the query. Attempt {attempt} Time: {requestTime - time.time()}")
            logger.info(f"Retrying the query. Attempt: {attempt + 1}, Time: {time.time() - requestTime} seconds")
            query, dns_server, dns_server_port = value_dict.get("query"), value_dict.get("dns_server"), value_dict.get("dns_server_port")
            pending_socket.sendto(query, (dns_server, dns_server_port)) #forward DNS query to upstream resolver
            value_dict["requestTime"] = time.time()
            value_dict["attempt"] = attempt + 1
        elif time.time() - requestTime > 2: #max attempt has been reached. 
            pending_socket.close()
            del pending_sockets[pending_socket]
    return

def main():
    #This is a socket that communicates between client and local host (receiving queries from client and forwarding response back to client)
    #We only need one client Socket because it can take queries from clients and the operating system can buffer incoming queries
    clientSocket = socket(AF_INET, SOCK_DGRAM)
    clientSocket.bind((_IP_ADDRESS, _SERVER_PORT))
    clientSocket.setblocking(False) #Configurated to False so that clientSocket.recvfrom doesn't block our code. 
    #print("The server is ready to receive")

    #This code follows a template from lecture slide - 06-TransportLayer-UDP page 8
    while True:
        #query is dig @127.0.0.1 -p 1053 example.com A
        #print(pending_sockets.keys())
        incoming_sockets, _,_ = select.select(
            [clientSocket] + list(pending_sockets.keys()), #monitor for sockets that has incoming data
            [], # monitor for sockets that writes data
            [], # monitor for sockets that have exception
            1.0 # one second timeout
        )

        for pending_socket in incoming_sockets:
            if pending_socket is clientSocket: #clientSocket received query from a client
                #print("received query from client")
                query, (clientAddress, clientPort) = clientSocket.recvfrom(2048)
                forwarding_DNS_query(query, clientAddress, clientPort)
            else: #pending_socket has response from DNS query
                #print("received response from DNS server")
                DNSResponse, _ = pending_socket.recvfrom(2048)
                value_dict = pending_sockets.get(pending_socket)
                #print(value_dict)
                clientAddress, clientPort = value_dict.get("clientAddress"), value_dict.get("clientPort")
                clientSocket.sendto(DNSResponse, (clientAddress, clientPort))
                logging_response(DNSResponse)
                pending_socket.close()
                del pending_sockets[pending_socket]

        retries()
        #print("still running")

if __name__ == "__main__":
    main()
