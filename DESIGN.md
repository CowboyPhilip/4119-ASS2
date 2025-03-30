# CSEE 4119 Spring 2025, Assignment 2 Design File
## Feiyang Chen
## GitHub username: CowboyPhilip

*Please replace this text with your protocol design, which includes the types of messages, message type, and protocol elements to achieve reliable data transfer.*

## structure of packet

a json string with base64 encoded payload

e.g. 

pkt = {
    "type": ["syn","syn-ack","ack","fin","fin-ack","data"],
    "seq": int,
    "ack": int,
    "payload": "" or base64,
    "checksum": self.checksum("" or base64)
}

checksum is computed with hashlib.md5 to make sure that payload is correct.

## type of message
["syn","syn-ack","ack","fin","fin-ack","data"]

syn: try to open connection

syn-ack: recv syn and send back

ack: acknowledge the syn-ack or data

fin: try to close the connection

fin-ack: recv fin and send back

data: packet containing data payloads

## design against lossy network
### 1. server -> parse_packet()

check the packet is in JSON string format, contain all needed fields, and check the payload with checksum. return a python dict if the packet is good otherwise return None as dropping the packet

### 2. three handshakes during connection begin and connection end

when connection start,

[Server] <--- SYN <--- [Client]

[Server] ---> SYN-ACK ---> [Client]

[Server] <--- ACK <--- [Client]

this ensure the server and client both get ready for data transmit. 

If SYN/SYN-ACK is lost or corrupted, server and client will block and keep retransmitting.

If ACK is lost or corrupted, server will ignore it and deal with coming data packets normally.

when connection end, to ensure server recv all data and server/client will both end

[Server] ---> FIN ---> [Client]

[Server] <--- FIN-ACK <--- [Client]

[Server] ---> ACK ---> [Client]


