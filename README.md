# assume-vpn

1) Deploy __assume-vpn.json__ Cloudformation template
2) Fill out parameters. You can specify a single VPN id or multiple VPN ids (separated by commas) that you want to assume 

Important:
- The CGW is capable of assuming one or more VPNs
- Additional VPNs must use the same CGW id as the first VPN assumed or strongswan will not assume that particular VPN.
- Cloudformation stack must be launched in the same region as the VPN that you want to assume
- You can add additional VPN ids through the CF stack update API, but you cannot remove existing VPNs
