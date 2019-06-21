import socket
import select
import os, sys
import pytun
from pytun import TunTapDevice
from ENC import *

class TunTap(object):
	def __init__(self, name, ip, netmask):
		self.tun = TunTapDevice(name=name, flags=pytun.IFF_TUN|pytun.IFF_NO_PI)
		self.tun.addr = ip
		self.tun.netmask = netmask
		self.mtu = 1500
		# self.tun.persist(True)
		self.tun.up()
	def getfd(self):
		return self.tun
	def recv(self):
		return self.tun.read(self.mtu)
	def send(self, buf):
		self.tun.write(buf)

def tap_open(name, ip, netmask):
	tun = TunTap(name, ip, netmask)
	return tun

def setupFirewall(port):
	cmd = f'firewall-cmd --add-port={port}/tcp --permanent; firewall-cmd --reload'
	os.system(cmd)

def closeService(port):
	print ("Close Service")
	cmd = f'firewall-cmd --zone=public --remove-port={port}/tcp; firewall-cmd --reload'
	os.system(cmd)
	exit()

def parse(data):
	return bytes(data[16:20])

def main(port, TAP):
	# set up tap if needed
	if TAP is True:
		tun = tap_open("tap0", "192.168.1.8", "255.255.255.0")

	# setup firewall
	setupFirewall(port)

	# open socke and listen
	s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
	s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
	s.bind(('0.0.0.0', port))
	print ("Bind done !")
	s.listen(5)

	input_service = [None, 1, s]
	input_fd = [tun.tun.fileno(), sys.stdin, s.fileno()]
	
	conn_table = {}
	tmp = None
	while True:
		rs, ws, xs = select.select(input_fd, [], [])
		for r in rs:
			if r == s.fileno():	# new connection
				conn, addr = s.accept()
				print (f'New connection from {addr}')
				input_fd.append(conn.fileno())	# add fd into select list
				input_service.append(conn)	# add fd into select list
				data = conn.recv(4)
				print (f'data = {data}')
				conn_table[data] = conn 
			elif r == sys.stdin:	# read command
				data = input()
				if "close" in data:
					closeService(port)
			elif r == tun.tun.fileno():
				data = tun.recv()
				dst_ip = parse(data)
				if dst_ip in conn_table:
					conn = conn_table[dst_ip]
					key = bytes([1 for _ in range(16)])
					data = Encrypt(data, key)
					conn.send(data)
			else:
				idx = input_fd.index(r)
				conn = input_service[idx]
				disconnect = False
				try:
					data = conn.recv(3000)
				except:
					disconnect = True
					data = None
				if not data or disconnect is True:	# disconnect
					print ("Disconnection from peer")
					input_service = input_service[:idx] \
						+ input_service[idx+1:]
					input_fd = input_fd[:idx] + input_fd[idx+1:]
					conn.close()
				else:
					key = bytes([1 for _ in range(16)])
					data = Decrypt(data, key)
					tun.send(data)
					#conn.sendall(data)

if __name__ == "__main__":
	port = 9489
	main(port, TAP=True)
