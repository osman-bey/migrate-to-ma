import xml.etree.ElementTree as ET


tree = ET.parse('xmlfile.txt')
root = tree.getroot()

cmd_template = '''
interface {0}
no ip address
no vrf forwarding
vrf forwarding MA
ip address {1} {2}
'''

for i in root.findall('interface'):
	
	vlan = i.find('Param').text
	vrf = i.find(".//VRFName").text
	ipaddress = i.find(".//IPAddress").text
	ipsubnetmask = i.find(".//IPSubnetMask").text
	
	cmd = cmd_template.format(vlan, ipaddress, ipsubnetmask)
	print(cmd)

	



