# TCP Syn Flood ( EDUCATIONAL PORPOSES )
> TCP Syn flood DDoS method.

## How it works?
TCP is a communication protocol used on the Internet for the reliable transmission of data between devices. It uses a three-way process (handshake) to establish a connection between the client and the server: SYN (synchronize), SYN-ACK (synchronize-acknowledge), and ACK (acknowledge).

Every time the TCP server receives a SYN flag, it allocates space and resources in a stack of waiting processes, sends the SYN + ACK flags to the client and waits for an ACK from the client to complete the "Handshake".

However, in this method, we do not send the rest of the flags to the server, so we send the SYN flag, the server allocates space for a waiting connection and sends the SYN+ACK to us, but we do not complete the "Handshake" so the The server will be waiting for a connection that will not happen and in the meantime, many other similar requests occur and fill the stack of waiting connections until the moment the server can no longer put connections on hold, completely stopping operation.

## Writer's note
This method already has some solutions, involving firewalls, IDS/IPS and mitigation services.

Of course, XDP will not leave the list, since we can analyze traffic and treat packets before reaching user space or deeper Kernel resources, it will depend on the nature and complexity of the attack, if you know how is done and know how to define standards. Rate limit is also not a bad idea, since we can set a time for the connection to be established, otherwise, we can cancel this waiting connection.