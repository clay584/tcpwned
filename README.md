# TCPwned

PoC toy code to exfiltrate data without ever making a TCP connection. This
will never show up in firewall logs, much less, actually be monitored
as there is never even a valid TCP session. This is pretty obscure, and requires
raw sockets on the victim, but if it is sensitive enough, this could be useful.
Network middleboxes will break this if they are full proxies, meaning there is a
connection from client to proxy, and a separate connection from proxy to server.

## Method

We are using the two-byte `window` field in the TCP header, and crafting packets
that place chunks of data into that field and send `SYN` packets out. The remote
side needs not run an actual service, and the server will actually send `RST` back
to the client, but none of that matters. We are merely shipping data one-way to
be reassembled. Considering there is no full handshake, this would be considered
connectionless, and has no guarantee of delivery or validity. Similar to UDP transport.

## Usage

### Victim

Run the `victim.py` script to pull a secret and send it.

### Attacker

Run the `attacker.py` script on a remote system. It will listen for 60 seconds
and receive anything it hears on port 4444. After receiving the data, it will
reassemble and print to screen.
