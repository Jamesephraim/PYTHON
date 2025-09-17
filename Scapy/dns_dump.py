from scapy.all import IP, DNS, sniff, DNSQR, UDP

def dns_dump(pkt):
    if pkt.haslayer(DNS) and pkt.haslayer(DNSQR):
        ip = pkt[IP]
        dns = pkt[DNS]  # ✅ You had 'tcp' instead of 'dns' here
        q = dns.qd.qname.decode(errors='ignore') if dns.qd else b''
        print(f"{ip.src} -> {ip.dst} asked for {q}")

sniff(filter="udp port 53", prn=dns_dump, store=0)
