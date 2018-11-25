import xml.etree.ElementTree as ET



file = open("xmlfile.txt")
filer = file.read()

file_output = []

file_output = filer.splitlines()

remove_list = []

for i in file_output:
	if "Load for five secs" in i:
		remove_list.append(i)		
	elif "Time source is NTP" in i:
		remove_list.append(i)
	elif i is "":
		remove_list.append(i)



for i in remove_list:
	file_output.remove(i)
		
file_output[0] = "<?xml version=\"1.0\" encoding=\"UTF-8\"?><Device-Configuration>"

output = "\n".join(file_output)











tree = ET.fromstring(output)
#root = tree.getroot()

cmd_template = '''
interface {0}
no ip address
no vrf forwarding
vrf forwarding MA
ip address {1} {2}
'''



for i in tree.findall('interface'):
	
	print(i)
	vlan = i.find('Param').text
	
	ipaddress = i.find(".//IPAddress").text
	ipsubnetmask = i.find(".//IPSubnetMask").text
	
	cmd = cmd_template.format(vlan, ipaddress, ipsubnetmask)
	print(cmd)





