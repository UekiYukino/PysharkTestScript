#!/bin/python3

##########################################################
#This is a script to find OSPFv2 plaintext password in a
#Wireshark captured file using pyshark
##########################################################

import pyshark

sFile= input ('Enter your wireshark file name: ')
OutFile= input("Enter your output file name: ")
FOut= open(OutFile,"w")

ospfPacket=0

for packet in pyshark.FileCapture(sFile):
    if 'OSPF' in packet:
        if packet['ospf'].version=="3": #Detect OSPF version 3 packet
            FOut.write("Packet %s is an OSPF version 3 packet\n"%packet.frame_info.number)
   
        else:            
            if packet['ospf'].auth_type == "0": #OPSFv2 packet without authentication
                FOut.write("No OSPF authentication for packet %s\n"%packet.frame_info.number)
            
            elif packet['ospf'].auth_type == "1": #OSPFv2 packet with plaintext passsword
                FOut.write("OSPF plaintext password for packet %s is: %s\n"%(packet.frame_info.number,packet['ospf'].auth_simple))
            
            elif packet['ospf'].auth_type== "2": #OSPFv2 packet with encrypted password
                FOut.write("OSPF password for %s is encrypted\n"%packet.frame_info.number)
        
        FOut.write("OSPF packet detail:\n%s\n\n\n"%packet)
        ospfPacket+=1

if ospfPacket==0:
    FOut.write("No OSPF packet found in the captured file\n")
else:    
    FOut.write("Total %s OSPF packet\n"%ospfPacket)

FOut.close()
