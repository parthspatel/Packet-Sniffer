import socket
import struct
import textwrap

TAB1 = '\t - '
TAB2 = '\t\t - '
TAB3 = '\t\t\t - '
TAB4 = '\t\t\t\t - '

DATATAB1 = '\t   '
DATATAB2 = '\t\t   '
DATATAB3 = '\t\t\t   '
DATATAB4 = '\t\t\t\t   '

def main():
	f = open('packets.txt','w')
	f.write('\n')

	#connection = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(3)) use this on linux, replace bottom 4 lines with this one
	connection = socket.socket(socket.AF_INET, socket.SOCK_RAW,socket.IPPROTO_IP)
	connection.bind(("127.0.0.1", 0))
	connection.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
	connection.ioctl(socket.SIO_RCVALL, socket.RCVALL_ON)
	try:
		while True:
			f.write('\n')
			rawData, addr = connection.recvfrom(65536)
			rxMac, txMac, ethProto, data = upackEternetFrame(rawData)
			print('\nEthernet Frame:')
			print('Receiver: {}, Source: {}, Protocol: {}'.format(rxMac, txMac, ethProto))

			# protocol 8 for IPv4
			if ethProto == 8:
				(version, headerLength, ttl, proto, src, target, data) = IPv4Unpack(data)
				print(TAB1 + 'IPv4 Packet: ')
				print(TAB2 + 'Version: {}, Header Length: {}, TTL: {}'.format(version, headerLength, ttl))
				print(TAB2 + 'Protocol: {}, Source: {}, Target: {}'.format(proto, src, target))

				# ICMP
				if proto == 1:
					ICMPtype, code, checksum, data = ICMPUnpack(data)
					print(TAB1 + 'ICMP Packet: ')
					print(TAB2 + 'Type: {}, Code: {}, Checksum: {}'.format(ICMPtype, code, checksum))
					print(TAB2 + 'Data: ')
					print(FormatMuliLine(DATATAB3, data))
					f.write('Receiver: {}, Source: {}, EthernetProtocol: {}, Protocol: {}, Data: {}'.format(rxMac, txMac, ethProto, proto, data))

				# TCP
				elif proto == 6:
					srcPort, destPort, seq, acknowledgement, flagUrg, flagAck, flagPsh, flagRst, flagSyn, flagFin, data = TCPUnpack(data)
					print(TAB1 + 'TCP Segment: ')
					print(TAB2 + 'Source Port: {}, Destination Port: {}'.format(srcPort, destPort))
					print(TAB2 + 'Sequence: {}, Acknowledgement: {}'.format(seq, acknowledgement))
					print(TAB2 + 'Flags: ')
					print(TAB3 + 'URG: {}, ACK: {}, PSH: {}, RST: {}, SYN: {}, FIN: {}'.format(flagUrg, flagAck, flagPsh, flagRst, flagSyn, flagFin))
					print(TAB2 + 'Data:')
					print(FormatMuliLine(DATATAB3, data))
					f.write('Receiver: {}, Source: {}, EthernetProtocol: {}, Protocol: {}, Data: {}'.format(rxMac, txMac, ethProto, proto, data))

				# UDP
				elif proto == 17:
					srcPort, destPort, length, data = UDPUnpack(data)
					print(TAB1 + 'UDP Segment: ')
					print(TAB2 + 'Source Port: {}, Destination Port: {}, Length: {}'.format(srcPort,destPort,length))
					f.write('Receiver: {}, Source: {}, EthernetProtocol: {}, Protocol: {}, Data: {}'.format(rxMac, txMac, ethProto, proto, data))

				# Other
				else:
					print(TAB1 + 'Data: ')
					proto(FormatMuliLine(DATATAB2, data))
					f.write('Receiver: {}, Source: {}, EthernetProtocol: {}, Protocol: {}, Data: {}'.format(rxMac, txMac, ethProto, proto, data))

			else:
				print('Data: ')
				print(FormatMuliLine(DATATAB1, data))
				f.write('Receiver: {}, Source: {}, EthernetProtocol: {}, Data: {}'.format(rxMac, txMac, ethProto, data))
	except (KeyboardInterrupt,SystemExit):
		pass
	f.close()
# Helper Functions
# --------------------

# Unpack Ethernet Frame
# 	Framework: Sync, Receiver, Sender, Type, Payload, CRC
# 	Sync: 8bytes, makes sure pc & router are in sync
# 	CRC: frame check, that makes sure all the data is recieved correctly w/o errors
# 	Recevier: who is reciveing data
# 	Sender: who is sending data
# 	Type: Internet Protocol type (IPv4, IPv6, ARP Req/Resp)
# 	Payload: Data in the package
#	returns pieces of frame
def upackEternetFrame(data):
	# reciever, sender, protocol
	rxMac, txMac, proto = struct.unpack('! 6s 6s H', data[:14]) # 6bytes + 6bytes + 2bytes short int
	return getMacAddress(rxMac), getMacAddress(txMac), socket.htons(proto), data[14:] # size of data is unknown, all we know is it will have the first 14

# Return Formatted MAC address
#	AA:BB:CC:DD:EE:FF < MAC address return format at str
#	input is an ittr
def getMacAddress(byteAddress):
	byteString = map('{:02x}'.format, byteAddress) # turn the address into a str
	return ':'.join(byteString).upper() # join all the chunks with : and make them all uppercase

# Unpack IPv4 packet
def IPv4Unpack(data):
	versionHeaderLength = data[0]
	version = versionHeaderLength >> 4
	headerLength = (versionHeaderLength & 15)
	ttl, proto, src, target = struct.unpack('! 8x B B 2x 4s 4s', data[:20])
	#header + data returned
	return version, headerLength, ttl, proto, IPv4(src), IPv4(target), data[headerLength:]

# Returns properly formatted IPv4 address
def IPv4(addr):
	return '.'.join(map(str,addr))

# Unpack ICMP packet
def ICMPUnpack(data):
	ICMPtype, code, checksum = struct.unpack('! B B H', data[:4])
	return ICMPtype, code, checksum, data[4:]

# Unpack TCP segment
def TCPUnpack(data):
	(srcPort, destPort, seq, acknowledgement, offsetReservedFlags) = struct.unpack('! H H L L H', data[:14])

	offset = (offsetReservedFlags >> 12 ) * 4

	flagUrg =  (offsetReservedFlags & 32) >> 5
	flagAck = (offsetReservedFlags & 16) >> 4
	flagPsh = (offsetReservedFlags & 8) >> 3
	flagRst = (offsetReservedFlags & 4) >> 2
	flagSyn = (offsetReservedFlags & 2) >> 1
	flagFin = offsetReservedFlags & 1

	return srcPort, destPort, seq, acknowledgement, flagUrg, flagAck, flagPsh, flagRst, flagSyn, flagFin, data[offset:]

# Unpack UDP segment
def UDPUnpack(data):
	srcPort, destPort, size = struct.unpack('! H H 2x H', data[:8])
	return srcPort, destPort, size, data[8:]

# Format multi-line data
def FormatMuliLine(prefix, string, size=80):
	size -= len(prefix)
	if isinstance(string, bytes):
		string = ''.join(r'\x{:02x}'.format(byte) for byte in string)
		if size % 2:
			size -= 1
	return '\n'.join([prefix + line for line in textwrap.wrap(string, size)])





main()
