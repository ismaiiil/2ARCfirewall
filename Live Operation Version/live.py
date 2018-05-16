import argparse
import json
import pydivert
from pydivert import Protocol

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
parser.add_argument("--START", action='store_true', help="runs the firewall")
parser.add_argument("-in", "--INBOUND", action='store_true')
parser.add_argument("-out", "--OUTBOUND", action='store_true')
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
if args.DISPLAY == "table":
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
if args.START:
    print("Firewall STARTED")
    g = open("in_rules")
    InRules = json.load(g)
    g.close()

    h = open("out_rules")
    OutRules = json.load(h)
    h.close()

    with pydivert.WinDivert() as w:
        for packet in w:
            if packet.is_inbound:
                # print("packet inbound")
                for i in range(0, len(InRules) + 1):
                    if i == len(InRules):
                        # print("inbound packet sent")
                        w.send(packet)
                        break
                    elif "src_ip" in InRules[i]:
                        if i < len(InRules) and str(packet.src_addr) == InRules[i]["src_ip"]:
                            print("Inbound " + str(packet.src_addr) + " source dropped")
                            break
                    elif "dst_ip" in InRules[i]:
                        if i < len(InRules) and str(packet.dst_addr) == InRules[i]["dst_ip"]:
                            print("Inbound " + str(packet.dst_addr) + " destination dropped")
                            break
                    elif "UDPsport" in InRules[i]:
                        if i < len(InRules) and (packet.protocol[0] == Protocol.UDP) and str(packet.udp.src_port) == \
                                InRules[i]["UDPsport"]:
                            print("Inbound " + str(packet.udp.src_port) + " sport dropped")
                            break
                    elif "UDPdport" in InRules[i]:
                        if i < len(InRules) and (packet.protocol[0] == Protocol.UDP) and str(packet.udp.dst_port) == \
                                InRules[i]["UDPdport"]:
                            print("Inbound " + str(packet.udp.dst_port) + " dport dropped")
                            break
                    elif "TCPsport" in InRules[i]:
                        if i < len(InRules) and (packet.protocol[0] == Protocol.TCP) and str(packet.tcp.src_port) == \
                                InRules[i]["TCPsport"]:
                            print("Inbound " + str(packet.tcp.src_port) + " sport dropped")
                            break
                    elif "TCPdport" in InRules[i]:
                        if i < len(InRules) and (packet.protocol[0] == Protocol.TCP) and str(packet.tcp.dst_port) == \
                                InRules[i]["TCPdport"]:
                            print("Inbound " + str(packet.tcp.dst_port) + " dport dropped")
                            break
                    elif "icmp" in InRules[i]:
                        if i < len(InRules) and packet.protocol[0] == Protocol.ICMP and packet.icmp.code == int(
                                InRules[i]["icmp"]):
                            print("Inbound " + " icmp code " + str(packet.icmp.code) + " dropped")
                            break

            elif packet.is_outbound:
                for i in range(0, len(OutRules) + 1):
                    if i == len(OutRules):
                        # print("inbound packet sent")
                        w.send(packet)
                        break
                    elif "src_ip" in OutRules[i]:
                        if i < len(OutRules) and str(packet.src_addr) == OutRules[i]["src_ip"]:
                            print("Outbound " + str(packet.src_addr) + " source dropped")
                            break
                    elif "dst_ip" in OutRules[i]:
                        if i < len(OutRules) and str(packet.dst_addr) == OutRules[i]["dst_ip"]:
                            print("Outbound " + str(packet.dst_addr) + " destination dropped")
                            break
                    elif "UDPsport" in OutRules[i]:
                        if i < len(OutRules) and (packet.protocol[0] == Protocol.UDP) and str(packet.udp.src_port) == \
                                OutRules[i]["UDPsport"]:
                            print("Outbound " + str(packet.udp.src_port) + " sport dropped")
                            break
                    elif "UDPdport" in OutRules[i]:
                        if i < len(OutRules) and (packet.protocol[0] == Protocol.UDP) and str(packet.udp.dst_port) == \
                                OutRules[i]["UDPdport"]:
                            print("Outbound " + str(packet.udp.dst_port) + " dport dropped")
                            break
                    elif "TCPsport" in OutRules[i]:
                        if i < len(OutRules) and (packet.protocol[0] == Protocol.TCP) and str(packet.tcp.src_port) == \
                                OutRules[i]["TCPsport"]:
                            print("Outbound " + str(packet.tcp.src_port) + " sport dropped")
                            break
                    elif "TCPdport" in OutRules[i]:
                        if i < len(OutRules) and (packet.protocol[0] == Protocol.TCP) and str(packet.tcp.dst_port) == \
                                OutRules[i]["TCPdport"]:
                            print("Outbound " + str(packet.tcp.dst_port) + " dport dropped")
                            break
                    elif "icmp" in OutRules[i]:
                        if i < len(OutRules) and packet.protocol[0] == Protocol.ICMP and packet.icmp.code == int(
                                OutRules[i]["icmp"]):
                            print("Outbound " + " icmp code " + str(packet.icmp.code) + " dropped")
                            break
                            # print("packet outbound")
