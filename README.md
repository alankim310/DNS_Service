# DNS Service

## Introduction

This Python project implements an interactive DNS client and a local UDP DNS
forwarder. The client builds DNS queries, sends them to the forwarder, and
displays the responses as formatted JSON. The forwarder passes requests to
Google DNS at `8.8.8.8` and returns the responses to the requesting clients.
The project also includes reusable modules for building queries, parsing DNS
messages, and validating parser inputs.

I am working on implementing a local DNS resolver as well, but it is currently
not implemented, so I am relying on Google DNS service.

## How to Run

Run the client from the project directory:

```sh
python3 DNS_client.py
```

The client needs a running DNS resolver. To use the included forwarder,
start it first in a separate terminal:

```sh
python3 DNS_forwarder.py
```

Then run the client and enter a domain name (for example, example.com) and
a question type (for example, A or AAAA) when prompted. The client prints
the raw response bytes and a formatted JSON representation of the response.

Requirements: Python 3 and access to the upstream DNS server. All Python
imports use the standard library; no additional packages are required.
Run from the project directory so the client can read config.ini.

## Configuration

config.ini sets the client's address and port (localhost:10000) and the
resolver's address and port (localhost:1053). These defaults match the
included forwarder's listening address, 127.0.0.1:1053.

DNS_forwarder.py uses its own constants rather than config.ini:

- `_IP_ADDRESS` and `_SERVER_PORT` control the listening address and port.
- `_DEFAULT_UPSTREAM_RESOLVER` and `_DEFAULT_DNS_SERVER_PORT` control the
  upstream DNS server, which defaults to `8.8.8.8:53`.

If you change the forwarder's listening address or port, update the
`[local_resolver]` section in config.ini to match.

You can also query the running forwarder directly with dig:

```sh
dig @127.0.0.1 -p 1053 example.com A
```

## Python Files and Design

### `DNS_client.py`

**Purpose:** Provides the interactive command-line DNS client.

**Design:** Reads addresses and ports from config.ini, binds an IPv4 UDP
socket, and prompts for a domain name and question type. It uses
questionQuery to build one request, sends it to the configured resolver,
waits for a response, and uses DNSParser to display the decoded result.
It closes the socket after handling that response.

### `DNS_forwarder.py`

**Purpose:** Forwards DNS requests from local clients to an upstream resolver
and returns each response to the client that requested it.

**Design:** Uses one nonblocking UDP socket for incoming client requests and
a separate nonblocking UDP socket for each pending upstream query.
select.select monitors these sockets in a single event loop. The
pending_sockets dictionary tracks each query's client address, request
bytes, upstream destination, timestamp, and attempt count. Requests are
retried after two seconds without a response, up to three total attempts;
unanswered requests are then removed and their sockets closed. Responses
are relayed to clients before their upstream sockets are closed.
Domain names, question types, response sizes, and retry events are logged
to DNS_Response.txt in the working directory.

### `DNS_question_query.py`

**Purpose:** Builds a standard DNS question request for the client.

**Design:** Defines questionQuery as a subclass of Query from query_builder.py.
It combines a header with one question, zero answer/authority/additional
records, and the recursion-desired flag enabled. The question class
defaults to IN (Internet). buildingQuery() delegates byte serialization
to the parent class.

### `query_builder.py`

**Purpose:** Supplies reusable classes for constructing DNS request bytes.

**Design:** Query combines a Header and a Question. Header generates a random
16-bit transaction ID and packs it with Flag and Counts into a 12-byte
header. Flag validates and combines the individual flag fields using bit
shifts. Counts validates the section counts. Question encodes the domain
as length-prefixed ASCII labels, followed by the numeric type and class.
Numeric fields use network byte order. Supported question types are A,
AAAA, NS, CNAME, PTR, MX, SRV, IXFR, AXFR, and ALL.

### `DNS_parser.py`

**Purpose:** Decodes raw DNS message bytes into readable JSON.

**Design:** DNSParser coordinates smaller parsers for the transaction ID,
section counts, names, types, classes, questions, and resource records.
It uses the counts and byte offsets to walk the question, answer,
authority, and additional sections. NameParser follows DNS compression
pointers recursively. AnswerParser extracts each record's metadata and
delegates its payload to ResourceData. The parsedJson attribute contains
the formatted JSON string. Resource-data decoding currently handles A,
AAAA, CNAME, NS, PTR, and SOA; other payload types raise ValueError even
when the query builder accepts that question type.

### `validation.py`

**Purpose:** Provides shared input-validation helpers used by the parser.

**Design:** Small functions check object types, minimum/maximum lengths,
exact lengths, and missing (None) values. Invalid inputs raise TypeError
or ValueError with the relevant variable name. This module is imported
by other code and does not need to be run separately.

Written by Alan Kim
