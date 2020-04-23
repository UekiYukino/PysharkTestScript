#!/bin/python3

##################################################
# This program read Wireshark captured packet 
# and extract plaintext FTP username and password
##################################################


import pyshark

#Receive file names
sfile= pyshark.FileCapture(input("Enter your wireshark file name: "))
pFile=open(input("Enter the name for the short file: "),"w")
dFile=open(input("Enter the name for your detail file: "),"w")

ftpCount=0

#Run loops for each packet
for packet in sfile:
    if "FTP" in packet:
        if "USER" in str(packet['FTP']):#Find username in FTP packet
            dFile.write ("Username detected in packet %s: %s\n"%(packet.frame_info.number,packet['FTP'].request_arg))
            dFile.write("Packet detail:\n%s\n\n"%packet)
            pFile.write("Username found: %s\n"%packet['FTP'].request_arg)
            ftpCount+=1
        elif "PASS" in str(packet['FTP']): #Find password in FTP packet
            dFile.write ("Password detected in packet %s: %s\n"%(packet.frame_info.number,packet['FTP'].request_arg))
            dFile.write("Packet detail:\n%s\n\n"%packet)
            pFile.write("Password found: %s\n\n"%packet['FTP'].request_arg)
            ftpCount+=1
        else:
            continue

pFile.close()
dFile.close()

if ftpCount == 0: #Print message if no username and password found
    print ("No username and password found")
    



