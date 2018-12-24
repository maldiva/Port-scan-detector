from scapy.all import *
import sys

def divide() :
	print("----------------------------------------------------------")

class Attacker:
	def __init__(self, ip, port):
		self.ip = ip
		self.ports = []
		self.ports.append(port)
		self.incomplete_ports = []

	def add_port(self, port):
		self.ports.append(port)

	def show(self):
		self.ports.sort()
		temp = len(str(self.ports[len(self.ports)-1]))
		print("IP source: ", self.ip)
		print("Ports scanned from this IP: ")
		for count, port in enumerate(self.ports) :
			if count % 10 != 0 :
				print ('{:>{width}}'.format(port,width=temp),end = " ")

			elif count % 10 == 0 :
				print("")
				print ('{:>{width}}'.format(port,width=temp),end = " ")

		print("")
		if len(self.incomplete_ports) != 0 :
			self.incomplete_ports.sort()
			temp = len(str(self.incomplete_ports[len(self.incomplete_ports)-1]))
			print("")
			print("Ports unsuccessfully scanned from this IP: ")
			for count, port in enumerate(self.incomplete_ports) :
				if count % 10 != 0 :
					print ('{:>{width}}'.format(port,width=temp),end = " ")
				elif count % 10 == 0 :
					print("")
					print ('{:>{width}}'.format(port,width=temp),end = " ")
			print("")


	def add_incomplete_port(self, port):
		self.incomplete_ports.append(port)


def check_for_xmas(packets) :
	
	xmas_packets = 0
	attackers = []
	for packet in packets:
		if TCP in packet and packet[TCP].flags == 0x29 :
			xmas_packets = xmas_packets + 1
			if len(attackers) != 0 :
				for attacker in attackers :
					if attacker.ip == packet[IP].src :
						attacker.add_port(packet[TCP].dport)
					else :
						temp = Attacker(packet[IP].src,packet[TCP].dport)
						attackers.append(temp)
			else :
				temp = Attacker(packet[IP].src, packet[TCP].dport)
				attackers.append(temp)
	
	if xmas_packets == 0 :
		print("Xmas scan not detected")
	else :
		print ("Xmas scan detected. Number of packets :", xmas_packets)
		for attacker in attackers :
			attacker.show()

def check_for_udp(packets) :

	udp_packets = 0
	attackers = []
	for packet in packets:
		if UDP in packet and packet[UDP].len == 8 :
			udp_packets = udp_packets + 1
			if len(attackers) != 0 :
				for attacker in attackers :
					if attacker.ip == packet[IP].src :
						attacker.add_port(packet[UDP].dport)
					else :
						temp = Attacker(packet[IP].src,packet[UDP].dport)
						attackers.append(temp)
			else :
				temp = Attacker(packet[IP].src, packet[UDP].dport)
				attackers.append(temp)
	
	if udp_packets == 0 :
		print("UDP scan not detected")
	else :
		print ("UDP scan detected. Number of empty UDP packets :", udp_packets)
		for attacker in attackers :
			attacker.show()


def check_for_null(packets) :

	null_packets = 0
	attackers = []
	for packet in packets:
		if TCP in packet and packet[TCP].flags == 0x0 :
			null_packets = null_packets + 1
			if len(attackers) != 0 :
				for attacker in attackers :
					if attacker.ip == packet[IP].src :
						attacker.add_port(packet[TCP].dport)
					else :
						temp = Attacker(packet[IP].src,packet[TCP].dport)
						attackers.append(temp)
			else :
				temp = Attacker(packet[IP].src, packet[TCP].dport)
				attackers.append(temp)
	
	if null_packets == 0 :
		print("NULL scan not detected")
	else :
		print ("NULL scan detected. Number of packets :", null_packets)
		for attacker in attackers :
			attacker.show()

def check_for_half(packets) :
	half_packets            = 0
	half_packets_complete   = 0
	half_packets_incomplete = 0
	attackers =[]

	for current, packet in  enumerate(packets):
		if TCP in packet and packet[TCP].flags == 0x002 :
			if current < (len(packets) -1) :
				if TCP in packets[current+1] and (packets[current+1])[TCP].flags == 0x012:
					if current < (len(packets)-2) :
						if TCP in packets[current+2] and (packets[current+2])[TCP].flags == 0x004 :
							half_packets_complete =  half_packets_complete + 1
							half_packets = half_packets + 1
							if len(attackers) != 0 :
								for attacker in attackers :
									if attacker.ip == packet[IP].src :
										attacker.add_port(packet[TCP].dport)
									else :
										temp = Attacker(packet[IP].src,packet[TCP].dport)
										attackers.append(temp)
							else :
								temp = Attacker(packet[IP].src, packet[TCP].dport)
								attackers.append(temp)
				elif TCP in packets[current+1] and (packets[current+1])[TCP].flags == 0x014:
							half_packets_incomplete = half_packets_incomplete + 1
							half_packets = half_packets + 1
							if len(attackers) != 0 :
								for attacker in attackers :
									if attacker.ip == packet[IP].src :
										attacker.add_incomplete_port(packet[TCP].dport)
									else :
										temp = Attacker(packet[IP].src,packet[TCP].dport)
										attackers.append(temp)
							else :
								temp = Attacker(packet[IP].src, packet[TCP].dport)
								temp.add_incomplete_port(packet[TCP].dport)
								attackers.append(temp)
	if half_packets == 0 :
		print("Half scan not detected")
	else :
		print ("Half scan detected. Number of packets :", half_packets)
		for attacker in attackers :
			attacker.show()

def check_for_icmp(packets) :
	
	icmp_packets = 0
	icmp = []
	for packet in packets:
		if ICMP in packet :
			if packet[ICMP].type == 8 :  
				icmp_packets = icmp_packets + 1
				icmp.append( [ packet[IP].src, packet[IP].dst] )
	if icmp_packets == 0 :
		print("ICMP scan not detected")
	else :
		print ("ICMP scan detected. Number of packets :", icmp_packets)
		for x in icmp:
			print("ICMP packet. Source: ", x[0], "Destination: ", x[1])


packets = rdpcap(sys.argv[1])

divide()
check_for_xmas(packets)
divide()
check_for_udp (packets)
divide()
check_for_null(packets)
divide()
check_for_half(packets)
divide()
check_for_icmp(packets)
divide()