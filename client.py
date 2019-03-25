import mdns
from packet import *
from socket import *
from uuid import getnode as get_mac

multicast_ip = '224.0.0.251' # 224.0.0.251
multicast_leave_ip = '224.0.0.2'
multicast_port = 5353
multicast_mac = '01:00:5E:00:00:FB'
src_ip = '10.1.2.174' # gethostbyname(gethostname())
src_mac = ':'.join([hex(get_mac())[2:][i*2:(i+1)*2] for i in range(len(hex(get_mac())[2:])//2)])

class Packet:
	def __init__(self, payload='', min_osi_layer=2):
		self.payload = payload
		self.l2 = self.l3 = self.l4 = None
		self.min_osi_layer = min_osi_layer

		if min_osi_layer <= 2:
			self.l2 = MACHeader(src_mac, multicast_mac)
		if min_osi_layer <= 3:
			self.l3 = IPHeader(src_ip, multicast_ip, protocol=IPPROTO_UDP)
		if min_osi_layer <= 4:
			self.l4 = UDPHeader(self.payload, multicast_port)

	def ip_len_recalc(self):
		t = 0
		for h in [h for h in [self.l2, self.l3, self.l4] if h is not None]:
			t += len(h.compile())
		t += len(self.payload)
		self.l3.header[2] = t

	def compile(self):
		self.ip_len_recalc()
		return b''.join([p.compile() for p in [self.l2, self.l3, self.l4] if p is not None])

class Client:
	def __init__(self, fqdn, interface='eth0', min_osi_layer=2):
		self.fqdn = fqdn
		self.minlvl = min_osi_layer
		self.BUFFER = 1024
		self.interface = interface
		# self.socket = socket(AF_PACKET, SOCK_RAW)
		self.socket = socket(AF_INET, SOCK_RAW, IPPROTO_RAW)
		# self.socket.bind((interface, 0))
		# # self.socket.bind((src_ip, 0))
		# # self.socket.connect((multicast_ip, multicast_port))

	def construct_query(self, destname, type, contents=''):
		return mdns.Query(destname, type)

	def construct_packet(self, destname, type, contents=''):
		return Packet(mdns.Query(destname, type).compile(), self.minlvl)

	def send(self, packet):
		self.socket.sendto(packet.compile(), (multicast_ip, multicast_port))
		# self.socket.send(packet.compile())
		return 0

	def recv(self):
		return mdns.Record(self.socket.recv(self.BUFFER))
