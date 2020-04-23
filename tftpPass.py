#!/bin/python3

import pyshark
file=pyshark.FileCapture(input("Enter your Wireshark file: "))
oFile=open(input("Enter your output file name: "),'w')
TFTPcount=0

for packet in file:
    if 'TFTP' in packet:
        try:
            oFile.write(bytearray.fromhex(packet['data'].data).decode())
        except:
            pass
        TFTPcount+=1

if TFTPcount==0:
    print ("No TFTP packet found in the file")

oFile.close()
