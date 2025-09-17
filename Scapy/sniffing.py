from scapy.all import sniff

def show(pkt):
    if pkt.haslayer("Dot11"):
        print(pkt.summary())
sniff(prn=show)