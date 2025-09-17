from scapy.all import sniff,IP,TCP

def tcp_dump(pkt):
    if pkt.haslayer(IP) :
        ip=pkt[IP]
        tcp=pkt[TCP]
        print(f"{ip.src}:{tcp.sport} -> {ip.dst}:{tcp.dport} len={len(pkt)} ")






sniff(filter="tcp",prn=tcp_dump)