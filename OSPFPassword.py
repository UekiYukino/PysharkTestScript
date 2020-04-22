#!/bin/python3
#This is a script to find OSPFv2 plaintext password in a
#Wireshark captured file using pyshark
import pyshark

sFile=input("Enter your wireshark file name: ")
ospfPacket=0
for packet in pyshark.FileCapture(sFile):
    if 'OSPF' in packet:
        if packet.ospf.version=="3": #Detect OSPF version 3 packet
            print("Packet %s is an OSPF version 3 packet"%packet.frame_info.number)
        else:            
            if packet.ospf.auth_type == "0": #OPSFv2 packet without authentication
                print("No OSPF authentication for packet %s"%packet.frame_info.number)
            elif packet.ospf.auth_type == "1": #OSPFv2 packet with plaintext passsword
                print("OSPF plaintext password for packet %s is: %s"%(packet.frame_info.number,packet.ospf.auth_simple))
            elif packet.ospf.auth_type== "2": #OSPFv2 packet with encrypted password
                print("OSPF password for %s is encrypted"%packet.ospf.frame_info.number)
        ospfPacket+=1
print ("Total %s OSPF packet"%ospfPacket)
