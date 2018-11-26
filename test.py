from pprint import pprint

arp = '''
Type escape sequence to abort.
Sending 5, 100-byte ICMP Echos to 10.166.13.34, timeout is 2 seconds:
.....
Success rate is 0 percent (0/5)
'''

arp1 = '''
Type escape sequence to abort.
Sending 5, 100-byte ICMP Echos to 10.166.13.34, timeout is 2 seconds:
.!!!!
Success rate is 75 percent (0/5)
'''

list1 = []

list1.append(arp)
list1.append(arp1)

for i in list1:
	for j in i.splitlines():
		if "Success rate is 0 percent" in j:
			print("0 percent")
		else:
			print("ok percent") 