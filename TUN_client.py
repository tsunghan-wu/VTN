import os, sys
import pytun
import socket, select
import array
from pytun import TunTapDevice
from ENC import *
from DNStest import DNSquery

class TunTap(object):
	def __init__(self, name, ip, netmask):
		self.tun = TunTapDevice(name=name, flags=pytun.IFF_TUN|pytun.IFF_NO_PI)
		self.tun.addr = ip
		self.tun.netmask = netmask
		self.mtu = 1500
		self.tun.persist(True)
		self.tun.up()
	def getfd(self):
		return self.tun
	def recv(self):
		return self.tun.read(self.mtu)
	def send(self, buf):
		print(len(buf), buf)
		self.tun.write(buf)

def tap_open(name, ip, netmask):
	tun = TunTap(name, ip, netmask)
	return tun

'''
information
- dev name : tap0
	- ip : 192.168.1.1
	- 
'''

def parse(data):
	# ip header
	print (len(data))
	version_ihl = data[0]
	ihl_len = data[0] & 0xf
	type_of_srvice = data[1]
	length = data[2:4]
	identification = data[4:6]
	fragment_offset = data[6:8]
	ttl = data[8]
	protocol = data[9]
	ip_checksum = data[10:12]
	src_ip = f'{data[12]}.{data[13]}.{data[14]}.{data[15]}'
	dst_ip = f'{data[16]}.{data[17]}.{data[18]}.{data[19]}'

	# tcp header
	ts = 4 * ihl_len
	#src_port = int('0x' + str(data[18]) + str(data[19]), 16)
	src_port = data[ts]*256+data[ts+1]
	dst_port = data[ts+2]*256+data[ts+3]
	seq_num = data[ts+4:ts+8]
	ack = data[ts+8:ts+12]
	shift = data[ts+12] >> 4
	win = data[ts+14:ts:16]
	tcp_checksum = data[16:18]
	tot_offset = ts + shift * 4

	return dst_ip, dst_port, src_port
	
def query(ip, port):
	# TODO : query DNS
	if ip == "192.168.1.8":
		return 1, "172.16.57.184", port
	else:
		return 0, "172.16.57.184", port

def rewrite(data):
	version_ihl = data[0]
	ihl_len = data[0] & 0xf
	type_of_srvice = data[1]
	length = data[2:4]
	identification = data[4:6]
	fragment_offset = data[6:8]
	ttl = data[8]
	protocol = data[9]
	ip_checksum = data[10:12]
	src_ip = f'{data[12]}.{data[13]}.{data[14]}.{data[15]}'
	dst_ip = f'{data[16]}.{data[17]}.{data[18]}.{data[19]}'

	# tcp header
	ts = 4 * ihl_len
	#src_port = int('0x' + str(data[18]) + str(data[19]), 16)
	src_port = data[ts]*256+data[ts+1]
	dst_port = data[ts+2]*256+data[ts+3]
	seq_num = data[ts+4:ts+8]
	ack = data[ts+8:ts+12]
	shift = data[ts+12] >> 4
	win = data[ts+14:ts:16]
	tcp_checksum = data[16:18]
	tot_offset = ts + shift * 4

	return data[tot_offset:]

def main(tap_ip):
	# create tap device
	ip_str = ".".join(str(x) for x in tap_ip)
	print (ip_str)
	tun = tap_open('tap0',ip_str,'255.255.255.0')

	# maintain a dictionary stores everything
	connection_table = {}
	invert_conntable = {}
	# select
	input_fd = [tun.tun.fileno()]
	input_service = [tun.tun]

	while True:
		rs, ws, xs = select.select(input_fd, [], [])
		for s in rs:
			if s == tun.tun.fileno(): # receive from our machine
				data = tun.recv()
				ip, dst_port, src_port = parse(data)
				print (f'>>> ip = {ip}')
				if ip not in connection_table:
					flag, ip2, dst_port = DNSquery(ip,'172.16.57.186')
					#flag, ip2, dst_port = query(ip, dst_port)
					print (ip2)
					# new socket
					ss = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
					ss.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
					ss.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
	
					# socket connect
					ss.connect((ip2, 9489))
					connection_table[ip] = (flag, len(input_fd))
					invert_conntable[ss] = (flag, ip)
					input_service.append(ss)
					input_fd.append(ss.fileno())
					
					# new connection
					src_ip = bytes(tap_ip)
					ss.send(src_ip)
					# data = rewrite(data)
					if flag:
						key = bytes([0 for _ in range(16)])
						data = Encrypt(data, key)
					print (f'1 st. send {data}')
					ss.send(data)
					
				else:
					# send data
					flag, idx = connection_table[ip]
					ss = input_service[idx]
					#data = rewrite(data)
					if flag:	# encryption
						key = bytes([1 for _ in range(16)])
						data = Encrypt(data, key)
					print (f'2 later. send {data}')
					ss.send(data)
			else:					# receive data
				idx = input_fd.index(s)
				conn = input_service[idx]
				flag, ip = invert_conntable[conn]
				data = conn.recv(1024)
				print (f'recv {data}')
				if len(data)==0:
					continue
				key = bytes([1 for _ in range(16)])
				data = Decrypt(data, key)
				#data = recv_rewrite(data)
				tun.send(data)
				
if __name__ == "__main__":
	main([192, 168, 1, 1])
