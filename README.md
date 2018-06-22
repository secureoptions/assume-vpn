# assume-vpn

1) Deploy __assume-vpn.json__ Cloudformation template
2) Fill out parameters. You can specify a single VPN id or multiple VPN ids (separated by commas) that you want to assume 

Note: All VPNs must use the same CGW id or strongswan will not assume that particular VPN.
