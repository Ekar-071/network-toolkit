import socket


def resolve(name: str) -> dict[str, list[str]]:
    """Résout un nom d'hôte en adresses IPv4 / IPv6."""
    out: dict[str, list[str]] = {"ipv4": [], "ipv6": []}
    for family, _, _, _, sockaddr in socket.getaddrinfo(name, None, proto=socket.IPPROTO_TCP):
        key = "ipv4" if family == socket.AF_INET else "ipv6"
        if sockaddr[0] not in out[key]:
            out[key].append(sockaddr[0])
    return out
