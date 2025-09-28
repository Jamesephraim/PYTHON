from scapy.all import *

#Captuer STP frame
pkt=sniff(filter="ether dst 01:02:03:04:05:06",count=1)

#view total packet frame
pkt[0]
#View detailed
pkt[0].show()
#802.3 Ethernet
pkt[0][0].show()
#Logical Link control
pkt[0][1].show()
#STP frame view
pkt[0][2].show()
