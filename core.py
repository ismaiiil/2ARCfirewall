from scapy.contrib.igmp import IGMP
from scapy.layers.dns import DNS
from scapy.layers.inet import *
from scapy.all import *
from scapy.all import wrpcap

pcap = rdpcap(r'C:\Users\USER\Desktop\waza.pcapng')


def write(pkt):
    wrpcap('filtered.pcap', pkt, append=True)


for pkt in pcap:
    if not pkt.haslayer(TCP):  # filters out the has_layer
        write(pkt)  # sends the packet to be written if it meets criteria
    else:
        pass

input("press enter to clear fileterd.pcap")
open('filtered.pcap', 'w').close()
