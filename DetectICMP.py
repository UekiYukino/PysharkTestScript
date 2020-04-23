#!/bin/python3

##############################################
# This program capture live packet and detect
# ICMP packets
##############################################
import pyshark
filename=input("Enter your output file name: ")
inface=input("Enter the interface to capture packet from: ")
host=input("Enter the host IP address: ")
capture= pyshark.LiveCapture(interface=inface)#Capture on the interface
newfile=open(filename,'w')

for packet in capture.sniff_continuously(packet_count=50):

	try:
		if packet['icmp'].Type=='0': #Capture icmp reply
			if packet['ip'].src == host: #Detect host icmp reply
				print ('Someone is trying to ping the server from',packet['ip'].dst)
				newfile.write("ALERT!!! SOMEONE IS TRYING TO PING FROM OUTSIDE\n")
				newfile.write("Packet coming from host: "+ str(packet['ip'].dst)+"\n")
				newfile.write(str(packet)+"\n\n")
			else: #Watch for reply from remote machine
				print('There is a reply from', packet['ip'].dst)
				newfile.write("This is a ping from the host\n")
				newfile.write(str(packet)+"\n\n")
		elif packet['icmp'].Type=='8': #Ignore icmp request packet
			continue


	except:
		pass
    
print('The End')
newfile.close()
exit()
