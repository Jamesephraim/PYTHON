from scapy.all import *
from threading import Thread
from faker import Faker

def send_beacon(ssid, mac, infinite=True):
    dot11 = Dot11(type=0, subtype=8, addr1="ff:ff:ff:ff:ff:ff", addr2=mac, addr3=mac)
    # ESS+privacy to appear as secured on some devices
    beacon = Dot11Beacon(cap="ESS+privacy")
    essid = Dot11Elt(ID="SSID", info=ssid, len=len(ssid))
    frame = RadioTap()/dot11/beacon/essid
    sendp(frame, inter=0.1, loop=1, iface=iface, verbose=0)

if __name__ == "__main__":
    # number of access points
    n_ap = 5
    iface = "wlan0mon"
    # generate random SSIDs and MACs
    faker = Faker()
    ssids_macs = [ (faker.name(), faker.mac_address()) for i in range(n_ap) ]
    for ssid, mac in ssids_macs:
        Thread(target=send_beacon, args=(ssid, mac)).start()
