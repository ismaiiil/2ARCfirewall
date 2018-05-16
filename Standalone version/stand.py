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


def display():
    global InRules, i, OutRules
    get_inrules = open("in_rules")
    InRules = json.load(get_inrules)
    get_inrules.close()
    print("INBOUND rules: \n")
    for i in range(1, len(InRules)):
        print(str(i) + " " + str(InRules[i]))
    print("\n")
    get_outrules = open("out_rules")
    OutRules = json.load(get_outrules)
    get_outrules.close()
    print("OUTBOUND rules: \n")
    for i in range(1, len(OutRules)):
        print(str(i) + " " + str(OutRules[i]))


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
    if args.DELETE > 0:
        del loadedRules[args.DELETE]
    else:
        print("Please input valid index")
    f = open("in_rules", 'w')
    json.dump(loadedRules, f)
    f.close()
    display()
if (args.DELETE is not None) and args.OUTBOUND:
    get_rules = open("out_rules")
    loadedRules = json.load(get_rules)
    get_rules.close()
    if 0 < args.DELETE <= len(loadedRules):
        del loadedRules[args.DELETE]
    else:
        print("Please input valid index")
    f = open("out_rules", 'w')
    json.dump(loadedRules, f)
    f.close()
    display()
if (args.ADD is not None) and args.INBOUND:
    get_rules = open("in_rules")
    loadedRules = json.load(get_rules)
    get_rules.close()
    loadedRules.append(my_dict)

    f = open("in_rules", 'w')
    json.dump(loadedRules, f)
    f.close()
    display()
if (args.ADD is not None) and args.OUTBOUND:
    get_rules = open("out_rules")
    loadedRules = json.load(get_rules)
    get_rules.close()
    loadedRules.append(my_dict)
    f = open("out_rules", 'w')
    json.dump(loadedRules, f)
    f.close()
    display()
if args.DISPLAY == "table":
    display()
if (args.FILTER is not None) and (args.MAC is not None):
    pcap = rdpcap(args.FILTER)  # user input path to cap file
    mac = args.MAC
    temp = []
    alt = []

    g = open("in_rules")
    InRules = json.load(g)
    g.close()

    h = open("out_rules")
    OutRules = json.load(h)
    h.close()

    # load JSON file into THIS
    def isOutgoing(pkt):
        return pkt['Ethernet'].src == mac

    def write(packet):
        wrpcap('filtered.pcap', packet, append=True)

    for i in range(0, len(InRules)):
        if "src_ip" in InRules[i]:
            if temp == []:
                for pkt in pcap:
                    if not isOutgoing(pkt):
                        if pkt.haslayer(IP) and pkt['IP'].src != InRules[i]['src_ip']:  # filters out the has_layer
                            temp.append(pkt)  # sends the packet to be written if it meets criteria
                        else:
                            pass
                alt = []
            else:
                for pkt in temp:
                    if not isOutgoing(pkt):
                        if pkt.haslayer(IP) and pkt['IP'].src != InRules[i]['src_ip']:  # filters out the has_layer
                            alt.append(pkt)  # sends the packet to be written if it meets criteria
                        else:
                            pass
                temp = alt
                alt = []
        elif "dst_ip" in InRules[i]:
            if temp == []:
                for pkt in pcap:
                    if not isOutgoing(pkt):
                        if pkt.haslayer(IP) and pkt['IP'].dst != InRules[i]['dst_ip']:  # filters out the has_layer
                            temp.append(pkt)  # sends the packet to be written if it meets criteria
                        else:
                            pass
                alt = []
            else:
                for pkt in temp:
                    if not isOutgoing(pkt):
                        if pkt.haslayer(IP) and pkt['IP'].dst != InRules[i]['dst_ip']:  # filters out the has_layer
                            alt.append(pkt)  # sends the packet to be written if it meets criteria
                        else:
                            pass
                temp = alt
                alt = []
        elif "UDPdport" in InRules[i]:
            if temp == []:
                for pkt in pcap:
                    if not isOutgoing(pkt):
                        if pkt.haslayer(UDP) and (pkt["UDP"].dport != int(InRules[i]["UDPdport"])):
                            temp.append(pkt)
                        elif not pkt.haslayer(UDP):
                            temp.append(pkt)
                alt = []
            else:
                for pkt in temp:
                    if not isOutgoing(pkt):
                        if pkt.haslayer(UDP) and pkt["UDP"].dport != int(InRules[i]["UDPdport"]):
                            alt.append(pkt)
                        elif not pkt.haslayer(UDP):
                            alt.append(pkt)
                temp = alt
                alt = []
        elif "UDPsport" in InRules[i]:
            if temp == []:
                for pkt in pcap:
                    if not isOutgoing(pkt):
                        if pkt.haslayer(UDP) and (pkt["UDP"].sport != int(InRules[i]["UDPsport"])):
                            temp.append(pkt)
                        elif not pkt.haslayer(UDP):
                            temp.append(pkt)
                alt = []
            else:
                for pkt in temp:
                    if not isOutgoing(pkt):
                        if pkt.haslayer(UDP) and pkt["UDP"].sport != int(InRules[i]["UDPsport"]):
                            alt.append(pkt)
                        elif not pkt.haslayer(UDP):
                            alt.append(pkt)
                temp = alt
                alt = []
        elif "TCPdport" in InRules[i]:
            if temp == []:
                for pkt in pcap:
                    if not isOutgoing(pkt):
                        if pkt.haslayer(TCP) and (pkt["TCP"].dport != int(InRules[i]["TCPdport"])):
                            temp.append(pkt)
                        elif not pkt.haslayer(TCP):
                            temp.append(pkt)
                alt = []
            else:
                for pkt in temp:
                    if not isOutgoing(pkt):
                        if pkt.haslayer(TCP) and pkt["TCP"].dport != int(InRules[i]["TCPdport"]):
                            alt.append(pkt)
                        elif not pkt.haslayer(TCP):
                            alt.append(pkt)
                temp = alt
                alt = []
        elif "TCPsport" in InRules[i]:
            if temp == []:
                for pkt in pcap:
                    if not isOutgoing(pkt):
                        if pkt.haslayer(TCP) and (pkt["TCP"].sport != int(InRules[i]["TCPsport"])):
                            temp.append(pkt)
                        elif not pkt.haslayer(TCP):
                            temp.append(pkt)
                alt = []
            else:
                for pkt in temp:
                    if not isOutgoing(pkt):
                        if pkt.haslayer(TCP) and pkt["TCP"].sport != int(InRules[i]["TCPsport"]):
                            alt.append(pkt)
                        elif not pkt.haslayer(TCP):
                            alt.append(pkt)
                temp = alt
                alt = []
        elif "src_MAC" in InRules[i]:
            if temp == []:
                for pkt in pcap:
                    if not isOutgoing(pkt):
                        if pkt['Ethernet'].src != InRules[i]['src_MAC']:  # filters out the has_layer
                            temp.append(pkt)  # sends the packet to be written if it meets criteria
                        else:
                            pass
                alt = []
            else:
                for pkt in temp:
                    if not isOutgoing(pkt):
                        if pkt['Ethernet'].src != InRules[i]['src_MAC']:  # filters out the has_layer
                            alt.append(pkt)  # sends the packet to be written if it meets criteria
                        else:
                            pass
                temp = alt
                alt = []
        elif "dst_MAC" in InRules[i]:
            if temp == []:
                for pkt in pcap:
                    if not isOutgoing(pkt):
                        if pkt['Ethernet'].dst != InRules[i]['dst_MAC']:  # filters out the has_layer
                            temp.append(pkt)  # sends the packet to be written if it meets criteria
                        else:
                            pass
                alt = []
            else:
                for pkt in temp:
                    if not isOutgoing(pkt):
                        if pkt['Ethernet'].dst != InRules[i]['dst_MAC']:  # filters out the has_layer
                            alt.append(pkt)  # sends the packet to be written if it meets criteria
                        else:
                            pass
                temp = alt
                alt = []
        elif "icmp" in InRules[i]:
            if temp == []:
                for pkt in pcap:
                    if not isOutgoing(pkt):
                        if pkt.haslayer(ICMP) and (pkt["ICMP"].code != int(InRules[i]["icmp"])):
                            temp.append(pkt)
                        elif not pkt.haslayer(ICMP):
                            temp.append(pkt)
                alt = []
            else:
                for pkt in temp:
                    if not isOutgoing(pkt):
                        if pkt.haslayer(ICMP) and pkt["ICMP"].code != int(InRules[i]["icmp"]):
                            alt.append(pkt)
                        elif not pkt.haslayer(ICMP):
                            alt.append(pkt)
                temp = alt
                alt = []
        else:
            if temp == []:
                for pkt in pcap:
                    if not isOutgoing(pkt):
                        temp.append(pkt)
                alt = []
            else:
                for pkt in temp:
                    if not isOutgoing(pkt):
                        alt.append(pkt)
                temp = alt
                alt = []

    for mod_pkt in temp:
        write(mod_pkt)

    temp = []

    for i in range(0, len(OutRules)):
        if "src_ip" in OutRules[i]:
            if temp == []:
                for pkt in pcap:
                    if isOutgoing(pkt):
                        if pkt.haslayer(IP) and pkt['IP'].src != OutRules[i]['src_ip']:  # filters out the has_layer
                            temp.append(pkt)  # sends the packet to be written if it meets criteria
                        else:
                            pass
                alt = []
            else:
                for pkt in temp:
                    if isOutgoing(pkt):
                        if pkt.haslayer(IP) and pkt['IP'].src != OutRules[i]['src_ip']:  # filters out the has_layer
                            alt.append(pkt)  # sends the packet to be written if it meets criteria
                        else:
                            pass
                temp = alt
                alt = []
        elif "dst_ip" in OutRules[i]:
            if temp == []:
                for pkt in pcap:
                    if isOutgoing(pkt):
                        if pkt.haslayer(IP) and pkt['IP'].dst != OutRules[i]['dst_ip']:  # filters out the has_layer
                            temp.append(pkt)  # sends the packet to be written if it meets criteria
                        else:
                            pass
                alt = []
            else:
                for pkt in temp:
                    if isOutgoing(pkt):
                        if pkt.haslayer(IP) and pkt['IP'].dst != OutRules[i]['dst_ip']:  # filters out the has_layer
                            alt.append(pkt)  # sends the packet to be written if it meets criteria
                        else:
                            pass
                temp = alt
                alt = []
        elif "UDPdport" in OutRules[i]:
            if temp == []:
                for pkt in pcap:
                    if isOutgoing(pkt):
                        if pkt.haslayer(UDP) and (pkt["UDP"].dport != int(OutRules[i]["UDPdport"])):
                            temp.append(pkt)
                        elif not pkt.haslayer(UDP):
                            temp.append(pkt)
                alt = []
            else:
                for pkt in temp:
                    if isOutgoing(pkt):
                        if pkt.haslayer(UDP) and pkt["UDP"].dport != int(OutRules[i]["UDPdport"]):
                            alt.append(pkt)
                        elif not pkt.haslayer(UDP):
                            alt.append(pkt)
                temp = alt
                alt = []
        elif "UDPsport" in OutRules[i]:
            if temp == []:
                for pkt in pcap:
                    if isOutgoing(pkt):
                        if pkt.haslayer(UDP) and (pkt["UDP"].sport != int(OutRules[i]["UDPsport"])):
                            temp.append(pkt)
                        elif not pkt.haslayer(UDP):
                            temp.append(pkt)
                alt = []
            else:
                for pkt in temp:
                    if isOutgoing(pkt):
                        if pkt.haslayer(UDP) and pkt["UDP"].sport != int(OutRules[i]["UDPsport"]):
                            alt.append(pkt)
                        elif not pkt.haslayer(UDP):
                            alt.append(pkt)
                temp = alt
                alt = []
        elif "TCPdport" in OutRules[i]:
            if temp == []:
                for pkt in pcap:
                    if isOutgoing(pkt):
                        if pkt.haslayer(TCP) and (pkt["TCP"].dport != int(OutRules[i]["TCPdport"])):
                            temp.append(pkt)
                        elif not pkt.haslayer(TCP):
                            temp.append(pkt)
                alt = []
            else:
                for pkt in temp:
                    if isOutgoing(pkt):
                        if pkt.haslayer(TCP) and pkt["TCP"].dport != int(OutRules[i]["TCPdport"]):
                            alt.append(pkt)
                        elif not pkt.haslayer(TCP):
                            alt.append(pkt)
                temp = alt
                alt = []
        elif "TCPsport" in OutRules[i]:
            if temp == []:
                for pkt in pcap:
                    if isOutgoing(pkt):
                        if pkt.haslayer(TCP) and (pkt["TCP"].sport != int(OutRules[i]["TCPsport"])):
                            temp.append(pkt)
                        elif not pkt.haslayer(TCP):
                            temp.append(pkt)
                alt = []
            else:
                for pkt in temp:
                    if isOutgoing(pkt):
                        if pkt.haslayer(TCP) and pkt["TCP"].sport != int(OutRules[i]["TCPsport"]):
                            alt.append(pkt)
                        elif not pkt.haslayer(TCP):
                            alt.append(pkt)
                temp = alt
                alt = []
        elif "src_MAC" in OutRules[i]:
            if temp == []:
                for pkt in pcap:
                    if isOutgoing(pkt):
                        if pkt['Ethernet'].src != OutRules[i]['src_MAC']:  # filters out the has_layer
                            temp.append(pkt)  # sends the packet to be written if it meets criteria
                        else:
                            pass
                alt = []
            else:
                for pkt in temp:
                    if isOutgoing(pkt):
                        if pkt['Ethernet'].src != OutRules[i]['src_MAC']:  # filters out the has_layer
                            alt.append(pkt)  # sends the packet to be written if it meets criteria
                        else:
                            pass
                temp = alt
                alt = []
        elif "dst_MAC" in OutRules[i]:
            if temp == []:
                for pkt in pcap:
                    if isOutgoing(pkt):
                        if pkt['Ethernet'].dst != OutRules[i]['dst_MAC']:  # filters out the has_layer
                            temp.append(pkt)  # sends the packet to be written if it meets criteria
                        else:
                            pass
                alt = []
            else:
                for pkt in temp:
                    if isOutgoing(pkt):
                        if pkt['Ethernet'].dst != OutRules[i]['dst_MAC']:  # filters out the has_layer
                            alt.append(pkt)  # sends the packet to be written if it meets criteria
                        else:
                            pass
                temp = alt
                alt = []
        elif "icmp" in OutRules[i]:
            if temp == []:
                for pkt in pcap:
                    if isOutgoing(pkt):
                        if pkt.haslayer(ICMP) and (pkt["ICMP"].code != int(OutRules[i]["icmp"])):
                            temp.append(pkt)
                        elif not pkt.haslayer(ICMP):
                            temp.append(pkt)
                alt = []
            else:
                for pkt in temp:
                    if isOutgoing(pkt):
                        if pkt.haslayer(ICMP) and pkt["ICMP"].code != int(OutRules[i]["icmp"]):
                            alt.append(pkt)
                        elif not pkt.haslayer(ICMP):
                            alt.append(pkt)
                temp = alt
                alt = []
        else:
            if temp == []:
                for pkt in pcap:
                    if isOutgoing(pkt):
                        temp.append(pkt)
                alt = []
            else:
                for pkt in temp:
                    if isOutgoing(pkt):
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
#          'icmp': 1, #icmp code to be blocked
#          'TCPsport': 58837, or UDPsport :80
#          'TCPdport': 56646, or UDPdport : 80
#          'dst_MAC': "10:51:72:5f:34:5b",
#          'src_MAC': "c8:ff:28:2c:71:d7"}
