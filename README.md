# RFID Supply Chain
Increasing traceability along the IC supply chain via RFID tags and a blockchain. The goal is to prevent
counterfeit or recycled ICs from entering the supply chain. This is accomplished by embedding an
RFID tag with the IC. This RFID tag contains a block chain that is updated by each distributor, 
ensuring traceability through the entire supply chain.

This project is based off the paper 
[*End-to-End Traceability of ICs in Component Supply Chain for Fighting Against Recycling*](https://ieeexplore.ieee.org/document/8760418).
Specifically, this project implements a central server that compliments the data stored on the RFID
tags. 

## Architecture
![Architecture](figures/arch.svg)

### Central Server
The central server maintains a database of all the distributors and their public keys. This allows
for anyone to verify the contents of an RFID tag. The central server also has its own blockchain
for each tracked IC.

### Distributor Server
A distributor may have many RFID readers in the form of dedicated readers or cell phones.
A central server is used to contain the distributor's private keys and to handle
block chain modifications. The distributor server is also in contact with the central
server. Readers send RFID data the distributor server which updates the blockchain and returns
the contents to program on the RFID tag.

