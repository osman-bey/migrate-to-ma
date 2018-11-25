arp = '''Internet  10.164.2.177            -   a493.4c95.40c0  ARPA   Vlan1000
Internet  10.164.2.181           17   a08c.f8b9.d9cd  ARPA   Vlan1000
Internet  10.164.2.200           17   a08c.f8b9.d9cd  ARPA   Vlan1000
Internet  10.165.193.193          1   a493.4c95.40c0  ARPA   Vlan2000'''


for i in arp.splitlines():
	arp_list = i.strip().split()
	if arp_list[2] is not "-":
		print(arp_list[1])