import dns.name
import dns.message
import dns.query
import dns.flags

def DNSquery(domain,name_server):
	'''
	domain = 'jwang.com'
	name_server = '172.16.215.103'
	'''
	ADDITIONAL_RDCLASS = 65531
	
	domain_orig = domain
	domain = '.'.join(domain.split('.')[::-1])+'.in-addr.arpa'
	domain = dns.name.from_text(domain)
	if not domain.is_absolute():
		domain = somain.concatenate(dns.name.root)
	request = dns.message.make_query(domain,dns.rdatatype.PTR)
	request.flags |= dns.flags.AD
	response = dns.query.udp(request,name_server)
	response = str(response).split('\n')
	flag = 1
	for i in response:
		if ' IN PTR ' in i:
			domain = i.split(' ')[-1]
			flag = 0
			break
	if flag==1:
		return [0,domain_orig,0]

	domain = dns.name.from_text(domain)
	if not domain.is_absolute():
		domain = somain.concatenate(dns.name.root)
	request = dns.message.make_query(domain,dns.rdatatype.ANY)
	request.flags |= dns.flags.AD
	request.find_rrset(request.additional,dns.name.root,ADDITIONAL_RDCLASS,
			dns.rdatatype.OPT,create=True,force_unique=True)
	response = dns.query.udp(request,name_server)
	response = str(response).split('\n')
	for i in response:
		if ' IN TYPE65531 ' in i:
			hexd = int(i.strip().split(' ')[-1],16)
			ip = ''
			for j in range(4):
				ip = str(hexd&0xff)+'.'+ip
				hexd>>=8
			ip = ip[:-1]
			port = 9489
			return [1,ip,port]
		elif ' IN A ' in i:
			orig = i
	ip = orig.strip().split(' ')[-1]
	return [0,ip,0]

print(DNSquery('192.168.1.8','172.16.57.186'))
#print(DNSquery('test.com','172.16.57.186'))
