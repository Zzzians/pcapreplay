from scapy.all import *
import dpkt
import socket
def ip_to_str(address):
	return socket.inet_ntop(socket.AF_INET, address)
def dupIP(ip):
	version=ip.v
	tos=ip.tos
	ID=ip.id
	dst=ip_to_str(ip.dst)
	src=ip_to_str(ip.src)
	ttl=ip.ttl
	proto=ip.p
	frag=ip.off & dpkt.ip.IP_OFFMASK
	do_not_fragment = bool(ip.off & dpkt.ip.IP_DF)
        more_fragments = bool(ip.off & dpkt.ip.IP_MF)
	flags=do_not_fragment*2+more_fragments*1
	npkt=IP(version=version,id=ID,tos=tos,ttl=ttl,proto=proto,src=src,dst=dst,flags=flags,frag=frag)
	return npkt
def dupTCP(tcp):
	sport=tcp.sport
	dport=tcp.dport
	ack=tcp.ack
	flags=tcp.flags
	seq=tcp.seq
	urgptr=tcp.urp
	window=tcp.win
	dataofs=tcp.off*4
	npkt=TCP(sport=sport,dport=dport,ack=ack,seq=seq,window=window,flags=flags,urgptr=urgptr)
	print tcp.off,tcp.off_x2
	return npkt
def dupUDP(udp):
	sport=udp.sport
	dport=udp.dport
	npkt=UDP(sport=sport,dport=dport)
	return npkt
def dupICMP(icmp):
	TYPE=icmp.type
	code=icmp.code
	npkt=ICMP(code=code,type=TYPE)
	return npkt
def sendpkt(pcap):
	for (ts,buf) in pcap:
		eth=dpkt.ethernet.Ethernet(buf)
		ip=eth.data
		Ip=dupIP(ip)
		tcp=ip.data
		Tcp=dupTCP(tcp)
		Raw=tcp.data
		send(Ip/Tcp/Raw)
f=open('tcp2.pcap')
pcap=dpkt.pcap.Reader(f)
sendpkt(pcap)		
			

