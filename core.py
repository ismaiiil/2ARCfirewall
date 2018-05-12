from scapy.contrib.igmp import IGMP
from scapy.layers.dns import DNS
from scapy.layers.inet import *
from scapy.all import *
from scapy.all import wrpcap
import json

pcap = rdpcap(r'C:\Users\USER\Desktop\waza.pcapng') # user input path to cap file

tests = [
    {'UDPdport': 58373},
    {'dst_ip': "52.20.100.49"},
    {'UDPdport': 63630},
    {'src_ip': "52.20.100.49"},
    {'UDPdport': 65129}
    ]  # user input for rule

temp = []
alt = []


# protocol : TCP, UDP TODO:add more protocols
#   if it is TCP, filter out all TCP ports
#   and vice versa

# print(tests)

f = open("rules", 'w')
json.dump(tests, f)
f.close()

# save user input for rules to JSON file

g = open("rules")
Rules = json.load(g)
g.close()
print(Rules)
# load JSON file into THIS


def write(packet):
    wrpcap('filtered.pcap', packet, append=True)


print(pcap[100]['UDP'].dport)

print(pcap[100]['IP'].dst)

for i in range(0,len(Rules)):
    if "src_ip" in Rules[i]:
        if temp == []:
            for pkt in pcap:
                if pkt.haslayer(IP) and pkt['IP'].src != Rules[i]['src_ip']:  # filters out the has_layer
                    temp.append(pkt)  # sends the packet to be written if it meets criteria
                else:
                    pass
            alt = []
        else:
            for pkt in temp:
                if pkt.haslayer(IP) and pkt['IP'].src != Rules[i]['src_ip']:  # filters out the has_layer
                    alt.append(pkt)  # sends the packet to be written if it meets criteria
                else:
                    pass
            temp = alt
            alt = []

    elif "dst_ip" in Rules[i]:
        if temp == []:
            for pkt in pcap:
                if pkt.haslayer(IP) and pkt['IP'].dst != Rules[i]['dst_ip']:  # filters out the has_layer
                    temp.append(pkt)  # sends the packet to be written if it meets criteria
                else:
                    pass
            alt = []
        else:
            for pkt in temp:
                if pkt.haslayer(IP) and pkt['IP'].dst != Rules[i]['dst_ip']:  # filters out the has_layer
                    alt.append(pkt)  # sends the packet to be written if it meets criteria
                else:
                    pass
            temp = alt
            alt = []

    elif "UDPdport" in Rules[i]:
        if temp == []:
            for pkt in pcap:
                if pkt.haslayer(UDP) and (pkt["UDP"].dport != Rules[i]["UDPdport"]):
                    temp.append(pkt)
                elif not pkt.haslayer(UDP):
                    temp.append(pkt)
            alt = []
        else:
            for pkt in temp:
                if pkt.haslayer(UDP) and pkt["UDP"].dport != Rules[i]["UDPdport"]:
                    alt.append(pkt)
                elif not pkt.haslayer(UDP):
                    alt.append(pkt)
            temp = alt
            alt = []




for mod_pkt in temp:
    write(mod_pkt)

input("press enter to clear fileterd.pcap")
open('filtered.pcap', 'w').close()


# template = {'src_ip': "192.168.0.2",
#          'dst_ip': "197.224.119.2",
#          'protocol': "UDP",
#          'TCPsport': 58837, or UDPsport :80
#          'TCPdport': 56646, or UDPdport : 80
#          'dst_mac': "10:51:72:5f:34:5b",
#          'src_mac': "c8:ff:28:2c:71:d7"}


# dest 58373

# elif "protocol" in Rules[i]:
#     if Rules[i]["protocol"] == "UDP":
#         if temp == []:
#             for pkt in pcap:
#                 if not pkt.haslayer(UDP):
#                     temp.append(pkt)
#             alt = []
#         else:
#             for pkt in temp:
#                 if not pkt.haslayer(UDP):
#                     alt.append(pkt)
#             temp = alt
#             alt = []
#     elif Rules[i]["protocol"] == "TCP":
#         if temp == []:
#             for pkt in pcap:
#                 if not pkt.haslayer(TCP):
#                     temp.append(pkt)
#             alt = []
#         else:
#             for pkt in temp:
#                 if not pkt.haslayer(TCP):
#                     alt.append(pkt)
#             temp = alt
#             alt = []
#  #  will not be implemented because blocking all udp ports is not useful
# for pkt in pcap:
#     if pkt.haslayer(IP) and pkt['IP'].src != Rules['src_ip']:  # filters out the has_layer
#         temp.append(pkt)  # sends the packet to be written if it meets criteria
#     else:
#         pass
#
#
# for pkt in pcap:
#     if 'protocol' in Rules:
#         if not pkt.haslayer(UDP):
#             if pkt not in temp:
#                 temp.append(pkt)
#             else:
#                 pass
#         else:
#             pass