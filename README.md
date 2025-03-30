# CSEE 4119 Spring 2025, Assignment 2
## Feiyang Chen
## GitHub username: CowboyPhilip

*Please replace this text with information on how to run your code, description of each file in the directory, and any assumptions you have made for your code*

## How to Run the Code
platform: GCP Linux VM

in terminal 1, run "python3 network.py 51000 127.0.0.1 50000 127.0.0.1 60000 loss.txt"

in terminal 2, run "python app_server.py 60000 4096", 60000 is the port, and 4096 is the buffer size

in termianl 3, run "python3 app_client.py 50000 127.0.0.1 51000 1460", where 50000 is the client port and 51000 is the network simulator port. 1460 is the whole packet size upper bound.


## File Description

.
    ├── DESIGN.md
    ├── README.md
    ├── TESTING.md
    ├── app_client.py   simulate the client, call mrt_client
    ├── app_server.py   simulate the server, call mrt_server
    ├── data.txt        the data to be transmitted
    ├── log_50000.txt   sample log of client using port 50000
    ├── log_60000.txt   sample log of server using port 60000
    ├── loss.txt        specify the loss of network. Preset to be very lossy. Note the the bit error rate cannot be higher
    ├── mrt_client.py   
    ├── mrt_server.py
    └── network.py      network simulator, simulate lossy network with config in loss.txt

## Assumption
1.  The network can be lossy. Most of the packets can be corrupted and highly likely to be lost.
