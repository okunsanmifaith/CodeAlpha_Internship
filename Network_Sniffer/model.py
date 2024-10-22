#!/usr/bin/python

from scapy.all import *
import socket
import datetime
import os
import time

def network_monitor(pak):
    time=datetime.datetime.now()

    if pak.haslayer(TCP):
        if socket.gethostbyname(socket.gethostname())==pak[IP].dst:
            print(str("[")+str(time)+str("]")+"  "+"TCP-IN:{}".format(len(pak[TCP]))+" Bytes"+"    "+"SRC-MAC:" +str(pak.src)+"    "+ "DST-MAC:"+str(pak.dst)+"    "+ "SRC-PORT:"+str(pak.sport)+"    "+"DST-PORT:"+str(pak.dport)+"    "+"SRC-IP:"+str(pak[IP].src)+"    "+"DST-IP:"+str(pak[IP].dst))

        if socket.gethostbyname(socket.gethostname())==pak[IP].src:
            print(str("[")+str(time)+str("]")+"  "+"TCP-OUT:{}".format(len(pak[TCP]))+" Bytes"+"    "+"SRC-MAC:" +str(pak.src)+"    "+ "DST-MAC:"+str(pak.dst)+"    "+ "SRC-PORT:"+str(pak.sport)+"    "+"DST-PORT:"+str(pak.dport)+"    "+"SRC-IP:"+str(pak[IP].src)+"    "+"DST-IP:"+str(pak[IP].dst))
        
        if socket.gethostbyname(socket.gethostname())==pak[IP].src:
            print(str("[")+str(time)+str("]")+"  "+"UDP-IN:{}".format(len(pak[TCP]))+" Bytes"+"    "+"SRC-MAC:" +str(pak.src)+"    "+ "DST-MAC:"+str(pak.dst)+"    "+ "SRC-PORT:"+str(pak.sport)+"    "+"DST-PORT:"+str(pak.dport)+"    "+"SRC-IP:"+str(pak[IP].src)+"    "+"DST-IP:"+str(pak[IP].dst))

        if socket.gethostbyname(socket.gethostname())==pak[IP].src:
            print(str("[")+str(time)+str("]")+"  "+"UDP-OUT:{}".format(len(pak[TCP]))+" Bytea"+"    "+"SRC-MAC:" +str(pak.src)+"    "+ "DST-MAC:"+str(pak.dst)+"    "+ "SRC-PORT:"+str(pak.sport)+"    "+"DST-PORT:"+str(pak.dport)+"    "+"SRC-IP:"+str(pak[IP].src)+"    "+"DST-IP:"+str(pak[IP].dst))
        
		if socket.gethostbyname(socket.gethostname())==pkt[IP].src:
			print(str("[")+str(time)+str("]")+"  "+"ICMP-OUT:{}".format(len(pkt[ICMP]))+" Bytes"+"    "+"IP-Version:"+str(pkt[IP].version) +"    "*1+" SRC-MAC:"+str(pkt.src)+"    "+"DST-MAC:"+str(pkt.dst)+"    "+"SRC-IP: "+str(pkt[IP].src)+ "    "+"DST-IP:  "+str(pkt[IP].dst))	
							 
		if socket.gethostbyname(socket.gethostname())==pkt[IP].dst:
			print(str("[")+str(time)+str("]")+"  "+"ICMP-IN:{}".format(len(pkt[ICMP]))+" Bytes"+"    "+"IP-Version:"+str(pkt[IP].version)+"    "*1+"	 SRC-MAC:"+str(pkt.src)+"    "+"DST-MAC:"+str(pkt.dst)+"    "+"SRC-IP: "+str(pkt[IP].src)+ "    "+"DST-IP:  "+str(pkt[IP].dst

if __name__ == '_main_':
    sniff(prn=network_monitor)
