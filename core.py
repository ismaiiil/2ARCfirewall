from scapy.contrib.igmp import IGMP
from scapy.layers.dns import DNS
from scapy.layers.inet import *
from scapy.all import *
from scapy.all import wrpcap
import json
import argparse
import sys


parser = argparse.ArgumentParser(description='Assigns a keyword rule to a value')

my_dict = {}


class StoreDictKeyPair(argparse.Action):
    def __call__(self, parser, namespace, values, option_string=None):
        for kv in values.split(","):
            k, v = kv.split("=")
            my_dict[k] = v
        setattr(namespace, self.dest, my_dict)


h = "add a rule: src_ip,dst_ip,TCPsport,UDPsport,TCPdport,TCPdport,dst_MAC,src_MAC"

parser.add_argument("--ADD", help=h, dest="ADD", action=StoreDictKeyPair, metavar="add rule:")
parser.add_argument("--DELETE", type=int, help="delete rule")
parser.add_argument("--DISPLAY", help="display table of in_rules")
parser.add_argument("--FILTER", help="filters packet file to filtered.pcap")
parser.add_argument("-in", "--INBOUND", action='store_true')
parser.add_argument("-out", "--OUTBOUND", action='store_true')
parser.add_argument("--MAC", help="mac address of interface on which capture file was recorded")
args = parser.parse_args()
print(args)
if (args.DELETE is not None) and args.INBOUND:
    get_rules = open("in_rules")
    loadedRules = json.load(get_rules)
    get_rules.close()
    del loadedRules[args.DELETE]
    f = open("in_rules", 'w')
    json.dump(loadedRules, f)
    f.close()
if (args.ADD is not None) and args.INBOUND:
    get_rules = open("in_rules")
    loadedRules = json.load(get_rules)
    get_rules.close()
    loadedRules.append(my_dict)

    f = open("in_rules", 'w')
    json.dump(loadedRules, f)
    f.close()
if args.DISPLAY == "table" and args.INBOUND:
    get_rules = open("in_rules")
    loadedRules = json.load(get_rules)
    get_rules.close()

    for i in range(0, len(loadedRules)):
        print(str(i) + " " + str(loadedRules[i]))
if args.FILTER is not None:
    pcap = rdpcap(args.FILTER)  # user input path to cap file

    temp = []
    alt = []

    g = open("in_rules")
    InRules = json.load(g)
    g.close()

    # load JSON file into THIS

    def write(packet):
        wrpcap('filtered.pcap', packet, append=True)

    for i in range(0, len(InRules)):
        if "src_ip" in InRules[i]:
            if temp == []:
                for pkt in pcap:

                    if pkt.haslayer(IP) and pkt['IP'].src != InRules[i]['src_ip']:  # filters out the has_layer
                        temp.append(pkt)  # sends the packet to be written if it meets criteria
                    else:
                        pass
                alt = []
            else:
                for pkt in temp:
                    if pkt.haslayer(IP) and pkt['IP'].src != InRules[i]['src_ip']:  # filters out the has_layer
                        alt.append(pkt)  # sends the packet to be written if it meets criteria
                    else:
                        pass
                temp = alt
                alt = []
        elif "dst_ip" in InRules[i]:
            if temp == []:
                for pkt in pcap:
                    if pkt.haslayer(IP) and pkt['IP'].dst != InRules[i]['dst_ip']:  # filters out the has_layer
                        temp.append(pkt)  # sends the packet to be written if it meets criteria
                    else:
                        pass
                alt = []
            else:
                for pkt in temp:
                    if pkt.haslayer(IP) and pkt['IP'].dst != InRules[i]['dst_ip']:  # filters out the has_layer
                        alt.append(pkt)  # sends the packet to be written if it meets criteria
                    else:
                        pass
                temp = alt
                alt = []
        elif "UDPdport" in InRules[i]:
            if temp == []:
                for pkt in pcap:
                    if pkt.haslayer(UDP) and (pkt["UDP"].dport != InRules[i]["UDPdport"]):
                        temp.append(pkt)
                    elif not pkt.haslayer(UDP):
                        temp.append(pkt)
                alt = []
            else:
                for pkt in temp:
                    if pkt.haslayer(UDP) and pkt["UDP"].dport != InRules[i]["UDPdport"]:
                        alt.append(pkt)
                    elif not pkt.haslayer(UDP):
                        alt.append(pkt)
                temp = alt
                alt = []
        elif "UDPsport" in InRules[i]:
            if temp == []:
                for pkt in pcap:
                    if pkt.haslayer(UDP) and (pkt["UDP"].sport != InRules[i]["UDPsport"]):
                        temp.append(pkt)
                    elif not pkt.haslayer(UDP):
                        temp.append(pkt)
                alt = []
            else:
                for pkt in temp:
                    if pkt.haslayer(UDP) and pkt["UDP"].sport != InRules[i]["UDPsport"]:
                        alt.append(pkt)
                    elif not pkt.haslayer(UDP):
                        alt.append(pkt)
                temp = alt
                alt = []
        elif "TCPdport" in InRules[i]:
            if temp == []:
                for pkt in pcap:
                    if pkt.haslayer(TCP) and (pkt["TCP"].dport != InRules[i]["TCPdport"]):
                        temp.append(pkt)
                    elif not pkt.haslayer(TCP):
                        temp.append(pkt)
                alt = []
            else:
                for pkt in temp:
                    if pkt.haslayer(TCP) and pkt["TCP"].dport != InRules[i]["TCPdport"]:
                        alt.append(pkt)
                    elif not pkt.haslayer(TCP):
                        alt.append(pkt)
                temp = alt
                alt = []
        elif "TCPsport" in InRules[i]:
            if temp == []:
                for pkt in pcap:
                    if pkt.haslayer(TCP) and (pkt["TCP"].sport != InRules[i]["TCPsport"]):
                        temp.append(pkt)
                    elif not pkt.haslayer(TCP):
                        temp.append(pkt)
                alt = []
            else:
                for pkt in temp:
                    if pkt.haslayer(TCP) and pkt["TCP"].sport != InRules[i]["TCPsport"]:
                        alt.append(pkt)
                    elif not pkt.haslayer(TCP):
                        alt.append(pkt)
                temp = alt
                alt = []
        elif "src_MAC" in InRules[i]:
            if temp == []:
                for pkt in pcap:
                    if pkt['Ethernet'].src != InRules[i]['src_MAC']:  # filters out the has_layer
                        temp.append(pkt)  # sends the packet to be written if it meets criteria
                    else:
                        pass
                alt = []
            else:
                for pkt in temp:
                    if pkt['Ethernet'].src != InRules[i]['src_MAC']:  # filters out the has_layer
                        alt.append(pkt)  # sends the packet to be written if it meets criteria
                    else:
                        pass
                temp = alt
                alt = []
        elif "dst_MAC" in InRules[i]:
            if temp == []:
                for pkt in pcap:
                    if pkt['Ethernet'].dst != InRules[i]['dst_MAC']:  # filters out the has_layer
                        temp.append(pkt)  # sends the packet to be written if it meets criteria
                    else:
                        pass
                alt = []
            else:
                for pkt in temp:
                    if pkt['Ethernet'].dst != InRules[i]['dst_MAC']:  # filters out the has_layer
                        alt.append(pkt)  # sends the packet to be written if it meets criteria
                    else:
                        pass
                temp = alt
                alt = []
        elif "icmp" in InRules[i]:
            if temp == []:
                for pkt in pcap:
                    if pkt.haslayer(ICMP) and (pkt["ICMP"].code != InRules[i]["icmp"]):
                        temp.append(pkt)
                    elif not pkt.haslayer(ICMP):
                        temp.append(pkt)
                alt = []
            else:
                for pkt in temp:
                    if pkt.haslayer(ICMP) and pkt["ICMP"].code != InRules[i]["ICMP"]:
                        alt.append(pkt)
                    elif not pkt.haslayer(ICMP):
                        alt.append(pkt)
                temp = alt
                alt = []




    for mod_pkt in temp:
        write(mod_pkt)

    input("press enter to clear fileterd.pcap")
    open('filtered.pcap', 'w').close()

# slel='C:\Users\USER\Desktop\waza.pcapng'


# template = {'src_ip': "192.168.0.2",
#          'dst_ip': "197.224.119.2",
#          'protocol': "ICMP",
#          'TCPsport': 58837, or UDPsport :80
#          'TCPdport': 56646, or UDPdport : 80
#          'dst_MAC': "10:51:72:5f:34:5b",
#          'src_MAC': "c8:ff:28:2c:71:d7"}
