# Conan

## What does the program do?
Conan takes a pcap file as an input and starts reading the packets, it reassembles all the TCP connections in the file, and for each connection it looks for any ambiguities.
## What are the ambiguities it looks for?
Conan looks in each TCP connections for retransmitted packets, and investigates further in each of them, it checks if the retransmission was partially or fully retransmitted and checks if this retransmission holds new data or the same data ( the new data may be overlapped with the old one). It also checks for multiple MacAddresses and multiple time to live used in one connection. 
## How does it work?
* Multiple MacAddresses used in one connection.
    
    For each connection the program looks in the source and destination MacAddress of each side in each packet of the connection, if it finds a packet with a MacAddress different than the one used before by this side it flags this connection.
* Multiple time to live (TTL) used in one connection.

    For each connection the program looks in the TTL of each side in each packet of the connection, if it finds a packet with a TTL different than the one used before by this side it flags this connection.