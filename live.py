import json
import socket

import pydivert
from pydivert import Protocol
from scapy.layers.inet import TCP, UDP

g = open("in_rules")
InRules = json.load(g)
g.close()

h = open("out_rules")
OutRules = json.load(h)
h.close()

print("test")

with pydivert.WinDivert() as w:
    for packet in w:
        if packet.is_inbound:
            # print("packet inbound")
            for i in range(0, len(InRules)+1):
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
                    if i < len(InRules)and (packet.protocol[0] == Protocol.UDP) and str(packet.udp.src_port) == InRules[i]["UDPsport"]:
                        print("Inbound " + str(packet.udp.src_port) + " sport dropped")
                        break
                elif "UDPdport" in InRules[i]:
                    if i < len(InRules)and (packet.protocol[0] == Protocol.UDP) and str(packet.udp.dst_port) == InRules[i]["UDPdport"]:
                        print("Inbound " + str(packet.udp.dst_port) + " dport dropped")
                        break
                elif "TCPsport" in InRules[i]:
                    if i < len(InRules)and (packet.protocol[0] == Protocol.TCP) and str(packet.tcp.src_port) == InRules[i]["TCPsport"]:
                        print("Inbound " + str(packet.tcp.src_port) + " sport dropped")
                        break
                elif "TCPdport" in InRules[i]:
                    if i < len(InRules)and (packet.protocol[0] == Protocol.TCP) and str(packet.tcp.dst_port) == InRules[i]["TCPdport"]:
                        print("Inbound " + str(packet.tcp.dst_port) + " dport dropped")
                        break
                elif "icmp" in InRules[i]:
                    if i < len(InRules) and packet.protocol[0] == Protocol.ICMP and packet.icmp.code == int(InRules[i]["icmp"]):
                        print("Inbound " + " icmp code " + str(packet.icmp.code) + " dropped")
                        break


        elif packet.is_outbound:
            for i in range(0, len(OutRules)+1):
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
                    if i < len(OutRules) and (packet.protocol[0] == Protocol.UDP) and str(packet.udp.src_port) == OutRules[i]["UDPsport"]:
                        print("Outbound " + str(packet.udp.src_port) + " sport dropped")
                        break
                elif "UDPdport" in OutRules[i]:
                    if i < len(OutRules) and (packet.protocol[0] == Protocol.UDP) and str(packet.udp.dst_port) == OutRules[i]["UDPdport"]:
                        print("Outbound " + str(packet.udp.dst_port) + " dport dropped")
                        break
                elif "TCPsport" in OutRules[i]:
                    if i < len(OutRules) and (packet.protocol[0] == Protocol.TCP) and str(packet.tcp.src_port) == OutRules[i]["TCPsport"]:
                        print("Outbound " + str(packet.tcp.src_port) + " sport dropped")
                        break
                elif "TCPdport" in OutRules[i]:
                    if i < len(OutRules) and (packet.protocol[0] == Protocol.TCP) and str(packet.tcp.dst_port) == OutRules[i]["TCPdport"]:
                        print("Outbound " + str(packet.tcp.dst_port) + " dport dropped")
                        break
                elif "icmp" in OutRules[i]:
                    if i < len(OutRules) and packet.protocol[0] == Protocol.ICMP and packet.icmp.code == int(OutRules[i]["icmp"]):
                            print("Outbound " + " icmp code " + str(packet.icmp.code) + " dropped")
                            break
            # print("packet outbound")
        else:
            print("??????????????????????????????????????????????????????????")
            w.send(packet)


    # HOPOPT = 0
    # ICMP = 1
    # TCP = 6
    # UDP = 17
    # ROUTING = 43
    # FRAGMENT = 44
    # AH = 51
    # ICMPV6 = 58
    # NONE = 59
    # DSTOPTS = 60
