Written by Alan Kim

- - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - 

DNS forwarder:

How to Run:
In order to run, you must run the following in the CLI: python3 DNS_forwarder.py. 
Although there is no dependency required, if you want to use different upstream resolver or dns server port, 
you need to change the values of _DEFAULT_DNS_SERVER_PORT and _DEFAULT_UPSTREAM_RESOLVER accordingly. 
Query names, types, and response size will be logged into DNS_Response.txt file (which will be created when you run the script). 
This text file also log retries when a DNS response does not arrive within 2 seconds after forwarding the query upto 3 attempts. 
Then in a different terminal, you can request query using command, such as "dig @127.0.0.1 -p 1053 example.com A".

Do not change value of _SERVER_PORT or _IP_ADDRESS. 

Design: 
We have one socket dedicated to receiving DNS queries from clients, called clientSocket. 
We use the select library to handle multiple concurrent queries without blocking on individual socket operation. 
The main function runs in a continuous loop, and select monitors sockets for incoming data. 

When clientSocket receives a query, select returns it in the incoming_sockets list. 
It then creates a separate UDP socket to forward the query to the upstream DNS resolver (currently defaulted to 8.8.8.8). 
Each upstream socket is stored in a dictionary called pending_sockets, along with the client’s address, port, original query, and retry information. 

When an upstream socket receives a DNS response, select identifies it, and the proxy uses pending_sockets to forward the response to the corresponding client. 
The socket is then closed and removed from the dictionary. 

The code also checks for timeouts and retries any queries that did not get a response from the upstream resolver after 2 seconds up to 3 attempts. 
It logs the domain name, query type, and response size in DNS_Response.txt and also log of retries if necessary. 
