# Port scan detector
Small python script to check .pcap files on port scans.
# Types of scans supported:
Xmas

UDP

NULL

Half

ICMP

# Usage: 
```sh
py scan-detector.py file.pcap
```
# Requirements
Script requires python3 and scapy library to run:
```sh
pip install scapy
```
Some pcap's are not supported, because of the wrong magic number, to fix the magic you can open your file with WireShark and resave it as .pcap.

The heaviest part of program is loading pcap into the memory, very large files may take some time to process. On average on my PC it could only process about 4000 packets per second. 
