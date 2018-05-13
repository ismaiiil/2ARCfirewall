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
parser.add_argument("--DISPLAY", help="display table of rules")
parser.add_argument("--FILTER", help="filters packet file to filtered.pcap")
args = parser.parse_args()

if args.DELETE is not None:
    get_rules = open("rules")
    loadedRules = json.load(get_rules)
    get_rules.close()
    del loadedRules[args.DELETE]
    f = open("rules", 'w')
    json.dump(loadedRules, f)
    f.close()
if args.ADD is not None:
    get_rules = open("rules")
    loadedRules = json.load(get_rules)
    get_rules.close()
    loadedRules.append(my_dict)

    f = open("rules", 'w')
    json.dump(loadedRules, f)
    f.close()
if args.DISPLAY == "table":
    get_rules = open("rules")
    loadedRules = json.load(get_rules)
    get_rules.close()

    for i in range(0, len(loadedRules)):
        print(str(i) + " " + str(loadedRules[i]))
if args.FILTER is not None:
    pcap = rdpcap(args.FILTER)  # user input path to cap file

    temp = []
    alt = []

    g = open("rules")
    Rules = json.load(g)
    g.close()

    # load JSON file into THIS

    def write(packet):
        wrpcap('filtered.pcap', packet, append=True)

    for i in range(0, len(Rules)):
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
        elif "UDPsport" in Rules[i]:
            if temp == []:
                for pkt in pcap:
                    if pkt.haslayer(UDP) and (pkt["UDP"].sport != Rules[i]["UDPsport"]):
                        temp.append(pkt)
                    elif not pkt.haslayer(UDP):
                        temp.append(pkt)
                alt = []
            else:
                for pkt in temp:
                    if pkt.haslayer(UDP) and pkt["UDP"].sport != Rules[i]["UDPsport"]:
                        alt.append(pkt)
                    elif not pkt.haslayer(UDP):
                        alt.append(pkt)
                temp = alt
                alt = []
        elif "TCPdport" in Rules[i]:
            if temp == []:
                for pkt in pcap:
                    if pkt.haslayer(TCP) and (pkt["TCP"].dport != Rules[i]["TCPdport"]):
                        temp.append(pkt)
                    elif not pkt.haslayer(TCP):
                        temp.append(pkt)
                alt = []
            else:
                for pkt in temp:
                    if pkt.haslayer(TCP) and pkt["TCP"].dport != Rules[i]["TCPdport"]:
                        alt.append(pkt)
                    elif not pkt.haslayer(TCP):
                        alt.append(pkt)
                temp = alt
                alt = []
        elif "TCPsport" in Rules[i]:
            if temp == []:
                for pkt in pcap:
                    if pkt.haslayer(TCP) and (pkt["TCP"].sport != Rules[i]["TCPsport"]):
                        temp.append(pkt)
                    elif not pkt.haslayer(TCP):
                        temp.append(pkt)
                alt = []
            else:
                for pkt in temp:
                    if pkt.haslayer(TCP) and pkt["TCP"].sport != Rules[i]["TCPsport"]:
                        alt.append(pkt)
                    elif not pkt.haslayer(TCP):
                        alt.append(pkt)
                temp = alt
                alt = []
        elif "src_MAC" in Rules[i]:
            if temp == []:
                for pkt in pcap:
                    if pkt['Ethernet'].src != Rules[i]['src_MAC']:  # filters out the has_layer
                        temp.append(pkt)  # sends the packet to be written if it meets criteria
                    else:
                        pass
                alt = []
            else:
                for pkt in temp:
                    if pkt['Ethernet'].src != Rules[i]['src_MAC']:  # filters out the has_layer
                        alt.append(pkt)  # sends the packet to be written if it meets criteria
                    else:
                        pass
                temp = alt
                alt = []
        elif "dst_MAC" in Rules[i]:
            if temp == []:
                for pkt in pcap:
                    if pkt['Ethernet'].dst != Rules[i]['dst_MAC']:  # filters out the has_layer
                        temp.append(pkt)  # sends the packet to be written if it meets criteria
                    else:
                        pass
                alt = []
            else:
                for pkt in temp:
                    if pkt['Ethernet'].dst != Rules[i]['dst_MAC']:  # filters out the has_layer
                        alt.append(pkt)  # sends the packet to be written if it meets criteria
                    else:
                        pass
                temp = alt
                alt = []



    for mod_pkt in temp:
        write(mod_pkt)

    input("press enter to clear fileterd.pcap")
    open('filtered.pcap', 'w').close()

# slel='C:\Users\USER\Desktop\waza.pcapng'


# template = {'src_ip': "192.168.0.2",
#          'dst_ip': "197.224.119.2",
#          'protocol': "UDP",
#          'TCPsport': 58837, or UDPsport :80
#          'TCPdport': 56646, or UDPdport : 80
#          'dst_MAC': "10:51:72:5f:34:5b",
#          'src_MAC': "c8:ff:28:2c:71:d7"}
