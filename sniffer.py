
import socket
import binascii

s=socket.socket(socket.PF_PACKET, socket.SOCK_RAW, socket.ntohs(0x0003))
IP_protocols = ['HOPOPT', 'ICMP', 'IGMP', 'GGP', 'IPv4', 'ST', 'TCP', 'CBT', 'EGP', 'IGP', 'BBN-RCC-MON', 'NVP-II', 'PUP', 'ARGUS', 'EMCON', 'XNET', 'CHAOS', 'UDP', 'MUX', 'DCN-MEAS', 'HMP', 'PRM', 'XNS-IDP', 'TRUNK-1', 'TRUNK-2', 'LEAF-1', 'LEAF-2', 'RDP', 'IRTP', 'ISO-TP4', 'NETBLT', 'MFE-NSP', 'MERIT-INP', 'DCCP', '3PC', 'IDPR', 'XTP', 'DDP', 'IDPR-CMTP', 'TP++', 'IL', 'IPv6', 'SDRP', 'IPv6-Route', 'IPv6-Frag', 'IDRP', 'RSVP', 'GRE', 'DSR', 'BNA', 'ESP', 'AH', 'I-NLSP', 'SWIPE', 'NARP', 'MOBILE', 'TLSP', 'SKIP', 'IPv6-ICMP', 'IPv6-NoNxt', 'IPv6-Opts', '', 'CFTP', '', 'SAT-EXPAK', 'KRYPTOLAN', 'RVD', 'IPPC', 'SAT-MON', 'VISA', 'IPCV', 'CPNX', 'CPHB', 'WSN', 'PVP', 'BR-SAT-MON', 'SUN-ND', 'WB-MON', 'WB-EXPAK', 'ISO-IP', 'VMTP', 'SECURE-VMTP', 'VINES', 'TTP', 'IPTM', 'NSFNET-IGP', 'DGP', 'TCF', 'EIGRP', 'OSPFIGP', 'Sprite-RPC', 'LARP', 'MTP', 'AX.25', 'IPIP', 'MICP', 'SCC-SP', 'ETHERIP', 'ENCAP', '', 'GMTP', 'IFMP', 'PNNI', 'PIM', 'ARIS', 'SCPS', 'QNX', 'A/N', 'IPComp', 'SNP', 'Compaq-Peer', 'IPX-in_IP', 'VRRP', 'PGM', '', 'L2TP', 'DDX', 'IATP', 'STP', 'SRP', 'UTI', 'SMP', 'SM', 'PTP', 'ISIS over IPv4', 'FIRE', 'CRTP', 'CRUDP', 'SSCOPMCE', 'IPLT', 'SPS', 'PIPE', 'SCTP', 'FC', 'RSVP-E2E-IGNORE', 'Mobility Header', 'UDPLite', 'MPLS-in-IP', 'manet', 'HIP', 'Shim6', 'WESP', 'ROHC']
Ports = {'20':'FTP', '21':'FTP', '22':'SSH', '23':'Telnet', '25':'SMTP', '53':'DNS', '67':'DHCP', '68':'DHCP', '69':'TFTP', '80':'HTTP', '110':'POP3', '123':'NTP', '137':'NetBIOS', '138':'NetBIOS', '139':'NetBIOS', '143':'IMAP', '161':'SNMP', '162':'SNMP', '179':'BGP', '389':'LDAP', '443':'HTTPS', '636':'LDAPS', '989':'SFTP', '990':'SFTP'}
iteration = 1
while True:
	packet = s.recvfrom(65565)

	print("----------------------------------------------------------------------------------------")
	print("					PACKET -", iteration)
	print("----------------------------------------------------------------------------------------")

	# 23 IP protocol
	protocol_type = int((packet[0])[23])
	if protocol_type > 142:
		print("Protocol Type: Unknown with protocol code:", protocol_type)
	else:
		print("Protocol Type: " + IP_protocols[protocol_type] + " (" + str(protocol_type) + ")")

	# PACKET SOURCE INFORMATION
	print("----------------------------------SOURCE INFO----------------------------------")
	# 6-11 Source MAC Address
	print("Source Address:", hex((packet[0])[6]) + ":" + hex((packet[0])[7]) + ":" + hex((packet[0])[8]) + ":" + hex((packet[0])[9]) + ":" + hex((packet[0])[10]) + ":" + hex((packet[0])[11]))

	# 26-29 Source IP
	print("Source IP:", int((packet[0])[26]) , "." , int((packet[0])[27]) , "." , int((packet[0])[28]) , "." , int((packet[0])[29]))

	# 34-35 Source Port
	source_port = ((int((packet[0])[34])) * 256) + int((packet[0])[35])
	if str(source_port) in Ports.keys():
		print("Source Port:", Ports[str(source_port)] + " (", source_port, ")")
	else:
		print("Source Port:", source_port)

	# PACKET DESTINATION INFORMATION
	print("------------------------------DESTINATION INFO-----------------------------------")
	# 0-5 Destination MAC Address
	print("Destination Address:", hex((packet[0])[0]) + ":" + hex((packet[0])[1]) + ":" + hex((packet[0])[2]) + ":" + hex((packet[0])[3]) + ":" + hex((packet[0])[4]) + ":" + hex((packet[0])[5]))

	# 30-33 Destination IP
	print("Destination IP:", int((packet[0])[30]) , "." , int((packet[0])[31]) , "." , int((packet[0])[32]) , "." , int((packet[0])[33]))

	# 36-37 Destination Port
	destination_port = ((int((packet[0])[36])) * 256) + int((packet[0])[37])
	if str(destination_port) in Ports.keys():
		print("Destination Port:", Ports[str(destination_port)] + " (", destination_port, ")")
	else:
		print("Destination Port:", destination_port)

	print('\n\n')
	iteration += 1;
