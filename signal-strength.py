import sys, os
from scapy.all import *

interface='wlan0' # monitor interface
aps = {} # dictionary to store unique APs

# process unique sniffed Beacons and ProbeResponses. 
def sniffAP(p):
    if ( (p.haslayer(Dot11Beacon) or p.haslayer(Dot11ProbeResp))):
        ssid       = p[Dot11Elt].info
        bssid      = p[Dot11].addr3    
        channel    = int( ord(p[Dot11Elt:3].info))
        
        capability = p.sprintf("{Dot11Beacon:%Dot11Beacon.cap%}\
                {Dot11ProbeResp:%Dot11ProbeResp.cap%}")
        
        if bssid !=sys.argv[2]:
          return
        try:
            extra = p.notdecoded
            rssi = -(256-ord(extra[-4:-3]))
        except:
            rssi = -100
            
        print("%02d %s %s %s" % (int(channel), p.dBm_AntSignal, bssid, ssid) )

if __name__ == "__main__":
    if len(sys.argv) != 3:
        print("Usage %s monitor_interface" % sys.argv[0])
        sys.exit(1)

    interface = sys.argv[1]

    # Print the program header
    print("-=-=-=-=-=-= AIROSCAPY =-=-=-=-=-=-")
    print("CH PWR BSSID             SSID")

    # Start the sniffer
    sniff(iface=interface,prn=sniffAP)