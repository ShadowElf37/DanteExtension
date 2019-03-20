import mdns
from packet import *
from socket import *
from uuid import getnode as get_mac

multicast_ip = '224.0.0.251'
multicast_port = '5353'
multicast_mac = '01:00:5E:00:00:FB'
src_ip = gethostbyname(gethostname())
src_mac = get_mac()

class Packet:
	def __init__(self, payload=''):
		self.payload = payload
		self.l2 = MACHeader(src_mac, multicast_mac)
		self.l3 = IPHeader(src_ip, multicast_ip, protocol=IPPROTO_UDP)
		self.l4 = UDPHeader(self.payload, multicast_port)

	def ip_len_recalc(self):
        t = 0
        for h in [h for h in [self.l2, self.l3, self.l4] if h is not None]:
            t += len(h.compile())
        t += len(self.datagram)
        self.l3.header[2] = t

class Client:
	def __init__(self, fqdn, interface='eth0'):
		self.fqdn = fqdn
		self.BUFFER = 1024
		self.interface = interface
		self.socket = socket(AF_PACKET, SOCK_RAW)
		self.socket.bind((interface, 0))
		# self.socket.connect((multicast_ip, multicast_port))

	def construct_query(self, name, type):
		return mdns.Query(name, type)

	def construct_packet(self, name, type):
		return Packet(mdns.Query(name, type).compile())

	def send(self, packet):
		self.socket.send(packet.compile())

	def recv(self):
		return Record(self.socket.recv(self.BUFFER))
