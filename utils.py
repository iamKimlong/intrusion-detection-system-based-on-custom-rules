# utils.py

def ip_in_subnet(ip, subnet):
    # Function to check if an IP is in a given subnet
    import ipaddress
    return ipaddress.IPv4Address(ip) in ipaddress.IPv4Network(subnet)
