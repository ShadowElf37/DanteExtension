from socket import socket
from packet import *

def multiord(s):
	num = 0
	for char in s:
		num <<= 8
		num += ord(char)
	return num

class Query:
	TYPES = {
		'A': 1,
		'PTR': 12,
		'TXT': 16,
			 }

	def __init__(self, name, type, unicast=0, cls=1):
		self.name = name
		self.type = Query.TYPES.get(type, 16)
		self.unicast = unicast
		self.cls = cls

	def compile(self):
		return bytes(self.name + chr(0) + chr((self.type << 16) + (unicast << 15) + cls))

class Record:
	def __init__(self, byte):
		self.raw = byte.decode()
		self.name = byte[:byte.find(chr(0))]
		etc = byte[byte.find(chr(0))+1:]
		self.type = multiord(etc[:2])
		ccf = multiord(etc[2:4])
		self.cache_flush = bin(ccf)[2]
		self.cls = bin(ccf)[3:]
		self.ttl = multiord(etc[4:8])
		self.dlen = multiord(etc[8:10])
		self.data = etc[10:]
