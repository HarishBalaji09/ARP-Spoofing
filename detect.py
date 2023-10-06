from scapy.all import *
from scapy.layers.inet import IP, TCP
from scapy.layers.l2 import ARP, Ether
import threading
import datetime

IP_MAC_PAIRS = {}
ARP_REQ_TABLE = {}


def sniff_requests():
   
    sniff(filter='arp', lfilter=outgoing_req, prn=add_req, iface=conf.iface)


def sniff_replays():
   
    sniff(filter='arp', lfilter=incoming_reply, prn=check_arp_header, iface=conf.iface)


def print_arp(pkt):
    
    if pkt[ARP].op == 1:
        print(pkt[ARP].hwsrc, ' who has ', pkt[ARP].pdst)
    else:
        print(pkt[ARP].psrc, ' is at ', pkt[ARP].hwsrc)


def incoming_reply(pkt):
   
    return pkt[ARP].psrc != str(get_if_addr(conf.iface)) and pkt[ARP].op == 2


def outgoing_req(pkt):
    
    return pkt[ARP].psrc == str(get_if_addr(conf.iface)) and pkt[ARP].op == 1


def add_req(pkt):

    ARP_REQ_TABLE[pkt[ARP].pdst] = datetime.datetime.now()


def check_arp_header(pkt):
   
    if not pkt[Ether].src == pkt[ARP].hwsrc or not pkt[Ether].dst == pkt[ARP].hwdst:
        return alarm('inconsistent ARP message')
    return known_traffic(pkt)


def known_traffic(pkt):
   
   
    if pkt[ARP].psrc not in IP_MAC_PAIRS.keys():
        return spoof_detection(pkt)

    elif IP_MAC_PAIRS[pkt[ARP].psrc] == pkt[ARP].hwsrc:
        return

    return alarm('IP-MAC pair change detected')


def spoof_detection(pkt):

    ip_ = pkt[ARP].psrc
    t = datetime.datetime.now()
    mac = pkt[0][ARP].hwsrc
   
    if ip_ in ARP_REQ_TABLE.keys() and (t - ARP_REQ_TABLE[ip_]).total_seconds() <= 5:
        ip = IP(dst=ip_)
        SYN = TCP(sport=40508, dport=40508, flags="S", seq=12345)
        E = Ether(dst=mac)
        
        if not srp1(E / ip / SYN, verbose=False, timeout=2):
            alarm('No TCP ACK, fake IP-MAC pair')
       
        else:
            IP_MAC_PAIRS[ip_] = pkt[ARP].hwsrc
    
    else:
        send(ARP(op=1, pdst=ip_), verbose=False)


def alarm(alarm_type):
 
    print('Under Attack ', alarm_type)


if __name__ == "__main__":
    req_ = threading.Thread(target=sniff_requests, args=())
    req_.start()
    rep_ = threading.Thread(target=sniff_replays, args=())
    rep_.start()