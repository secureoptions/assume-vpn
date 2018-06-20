import boto3
from ec2_metadata import ec2_metadata
from swvars import VPNIDS
import xml.etree.ElementTree as ET
from subprocess import call

# Stop the strongswan service so we can update its configuration smoothly
call(["service","strongswan","stop"])

# Get rid of possible whitespaces in the VGWs string and then turn the string into a iterable list
VPNIDS = VPNIDS.replace(" ", "")
VPNIDS = VPNIDS.split(',')

# Other needed variables
SWCONF='/etc/strongswan/ipsec.conf'
SWSECRET='/etc/strongswan/ipsec.secrets'
UPDOWN='/etc/strongswan/aws.updown'
BGPDCONF='/etc/quagga/bgpd.conf'
TRACKFILE='/etc/strongswan/.vpntrackfile'

def make_vpn(x):
	# Now iterate through regions, and see if any of the specified VGWs are located in that region. If so, build a VPN to it
	ec2 = boto3.client('ec2')
			try:
					VPN = ec2.describe_vpn_connections(VpnConnectionIds=[x])
					
					# Determine if VPN is static or dynamic routing type
					if VPN['VpnConnections'][0]['Options']['StaticRoutesOnly'] == False:
						z = 'dynamic'
					else:
						# The VPN is static, and we need to determine if its VGW is attached to a VPC to retrieve that VPC's CIDR (for local static route)
						VGWID = VPN['VpnConnections'][0]['VpnGatewayId']
						
						try: 		
								VPCID = ec2.describe_vpn_gateways(
									VpnGatewayIds=[VGWID]
									)
								VPCID = VPCID['VpnGateways'][0]['VpcAttachments'][0]['VpcId']
								
								CIDR = ec2.describe_vpcs(
									VpcIds=[VPCID]
									)
								CIDR = CIDR['Vpcs'][0]['CidrBlock']
								
								z = CIDR
								
						except IndexError as e:
							if e == "list index out of range":
								# There is no attached VPC to this VGW. use the following route as a placeholder
								z = '127.0.0.10/32'
						
					
					# Get customer gateway config
					DOWNLOADCONFIG = VPN['VpnConnections'][0]['CustomerGatewayConfiguration']
					
					# Let's extract our information to build the VPN in strongswan and openswan
					root = ET.fromstring(DOWNLOADCONFIG)
					
					# The download config file is formatted different for dynamic vs static. Extract data according to format
					if z.lower() == 'dynamic':
						# TUNNEL 1 INFO
						CGW_OUTSIDE = root[3][0][0][0].text
						LOCAL_INSIDE1 = root[3][0][1][0].text
						REMOTE_OUTSIDE1 = root[3][1][0][0].text
						REMOTE_INSIDE1 = root[3][1][1][0].text
						PSK1 = root[3][2][5].text
						
						# TUNNEL 2 INFO
						LOCAL_INSIDE2 = root[4][0][1][0].text
						REMOTE_OUTSIDE2 = root[4][1][0][0].text
						REMOTE_INSIDE2 = root[4][1][1][0].text
						PSK2 = root[4][2][5].text
						REMOTE_ASN = root[3][1][2][0].text
					else:
						# TUNNEL 1 INFO
						CGW_OUTSIDE = root[4][0][0][0].text
						LOCAL_INSIDE1 = root[4][0][1][0].text
						REMOTE_OUTSIDE1 = root[4][1][0][0].text
						REMOTE_INSIDE1 = root[4][1][1][0].text
						PSK1 = root[4][2][5].text
						
						# TUNNEL 2 INFO
						LOCAL_INSIDE2 = root[5][0][1][0].text
						REMOTE_OUTSIDE2 = root[5][1][0][0].text
						REMOTE_INSIDE2 = root[5][1][1][0].text
						PSK2 = root[5][2][5].text
						REMOTE_ASN = z
					
					def unique_num():
						# Generate a unique mark and vti number that is not already in use
						num = 10
						file = open(SWCONF, 'r').read()
						global VTINUM
						VTINUM = file.count('conn') + 10
						return VTINUM
						
						
					
					# Function to append a new ipsec configuration with appropriate parameters
					def add_config(li,ro,ri,vtinum,psk,num):
						with open(SWCONF,'ab') as f:
							f.write('conn ' + str(x) + '-' + num + '\n')
							f.write('\tkeyexchange=' + str(IKEVERSION) + '\n')
							f.write('\tauto=start\n')
							f.write('\ttype=tunnel\n')
							f.write('\tauthby=secret\n')
							f.write('\tleftid=' + str(CGW_OUTSIDE) + '\n')
							f.write('\tleft=%defaultroute\n')
							f.write('\tright=' + str(ro) + '\n')
							f.write('\tikelifetime='+ str(IKELIFETIME) + '\n')
							f.write('\tlifetime=' + str(ESPLIFETIME) + '\n')
							f.write('\tmargintime=' + str(MARGIN) + '\n')
							f.write('\trekeyfuzz=' + str(FUZZ) + '\n')
							f.write('\tesp=' + str(ESPPARAMETERS) + '\n')
							f.write('\tike=' + str(IKEPARAMETERS) + '\n')
							f.write('\tkeyingtries=%forever\n')
							f.write('\tleftsubnet=0.0.0.0/0\n')
							f.write('\trightsubnet=0.0.0.0/0\n')
							f.write('\tdpddelay=10s\n')
							f.write('\tdpdtimeout=30s\n')
							f.write('\tdpdaction=restart\n')
							f.write('\tmark=' + str(vtinum) + '\n')
							f.write('\tleftupdown="/etc/strongswan/aws.updown -ln vti' + str(vtinum) + ' -ll ' + li + ' -lr ' + ri + ' -m ' + str(vtinum) + ' -t ' + z +' -a ' + REMOTE_ASN + '"\n')
							
						with open(SWSECRET,'ab') as f:
							f.write(ro + ' : PSK "' + psk + '"\n')
							
					# Add first tunnel
					unique_num()
					add_config(LOCAL_INSIDE1,REMOTE_OUTSIDE1,REMOTE_INSIDE1,VTINUM,PSK1,'0')
					
					# Add second tunnel
					unique_num()
					add_config(LOCAL_INSIDE2,REMOTE_OUTSIDE2,REMOTE_INSIDE2,VTINUM,PSK2,'1')
					
					# Get allocation id of EIP so we can associate it with our CGW_OUTSIDE
					EIP = ec2.describe_addresses(
						PublicIPs=[CGW_OUTSIDE]
							)
					ALLOC_ID = EIP['Addresses'][0]['AllocationId']
					
					ENI = ec2.describe_network_interfaces(
							Filters=[{
								'Name' : 'attachment.instance-id',
								'Values' : [ec2_metadata.instance_id]
								}]
								)
					ENI = ENI['NetworkInterfaces'][0]['NetworkInterfaceId']
					
					# Associate the EIP with our eni
					ec2.associate_address(
						AllocationId=ALLOC_ID,
						AllowReassociation=True,
						NetworkInterfaceId=ENI
						)
						
			except:
				pass

for v in VPNIDS:
	make_vpn(v)

# Start the strongswan service back up again
call(["service","strongswan","start"])
