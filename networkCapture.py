

from scapy.all import *
import datetime


def process_packet(packet):
  
    timestamp = datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')

   
    print(f"\n[+] Packet Captured at {timestamp}")

    
    if packet.haslayer(IP):
        ip_layer = packet[IP]
        print(f"Source IP: {ip_layer.src}")
        print(f"Destination IP: {ip_layer.dst}")
        print(f"Protocol: {ip_layer.proto}")

  
    if packet.haslayer(TCP):
        tcp_layer = packet[TCP]
        print(f"Source Port: {tcp_layer.sport}")
        print(f"Destination Port: {tcp_layer.dport}")
        print(f"Sequence Number: {tcp_layer.seq}")

   
    if packet.haslayer(UDP):
        udp_layer = packet[UDP]
        print(f"Source Port: {udp_layer.sport}")
        print(f"Destination Port: {udp_layer.dport}")

   
    if packet.haslayer(ICMP):
        icmp_layer = packet[ICMP]
        print("ICMP Packet Detected")

    print("\nPacket Hex Dump:")
    print(hexdump(packet))



def start_sniffer(interface):
    print(f"[*] Starting network sniffer on interface {interface}...")
    
 
    sniff(iface=interface, prn=process_packet, store=False)


if __name__ == "__main__":
    
    interface = input("Enter the interface to sniff on (e.g., eth0, wlan0): ")
    
    
    start_sniffer(interface)
