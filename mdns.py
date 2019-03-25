from socket import socket
from packet import *

def bchr(n, enc='utf-8'):
	return chr(n).encode(enc)

def multiord(s):
	num = 0
	# print(s)
	for char in s: # this automatically ords it apparently
		# print(char)
		num <<= 8
		num += char
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
		return (self.name + chr(0) + chr((self.type << 16) + (self.unicast << 15) + self.cls)).encode()

class Record:
	def __init__(self, byte):
		try:
			self.raw = byte.decode()
		except:
			print('An illegal character was encountered in packet decoding.')
			self.raw = None
		self.name = byte[:byte.find(bchr(0))]
		etc = byte[byte.find(bchr(0))+1:]
		print(etc)
		self.type = multiord(etc[:2])
		ccf = multiord(etc[2:4])
		self.cache_flush = bin(ccf)[2]
		self.cls = bin(ccf)[3:]
		self.ttl = multiord(etc[4:8])
		self.dlen = multiord(etc[8:10])
		self.data = etc[10:]
