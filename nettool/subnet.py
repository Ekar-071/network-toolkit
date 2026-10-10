import ipaddress


def describe(cidr: str) -> dict:
    """Décrit un réseau IPv4/IPv6 (ex. 192.168.1.0/24)."""
    net = ipaddress.ip_network(cidr, strict=False)
    hosts = list(net.hosts()) if net.num_addresses <= 2**16 else None
    info = {
        "network": str(net.network_address),
        "prefix": net.prefixlen,
        "netmask": str(net.netmask),
        "broadcast": str(net.broadcast_address) if net.version == 4 else None,
        "addresses": net.num_addresses,
        "usable_hosts": max(net.num_addresses - 2, 0) if net.version == 4 and net.prefixlen < 31 else net.num_addresses,
        "private": net.is_private,
    }
    if hosts:
        info["first_host"], info["last_host"] = str(hosts[0]), str(hosts[-1])
    return info


def split(cidr: str, new_prefix: int) -> list[str]:
    """Découpe un réseau en sous-réseaux de longueur de préfixe `new_prefix`."""
    net = ipaddress.ip_network(cidr, strict=False)
    if new_prefix <= net.prefixlen:
        raise ValueError("Le nouveau préfixe doit être plus grand que le préfixe actuel")
    return [str(s) for s in net.subnets(new_prefix=new_prefix)]
