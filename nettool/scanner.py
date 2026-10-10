import socket
from concurrent.futures import ThreadPoolExecutor


def parse_ports(spec: str) -> list[int]:
    """'22,80,8000-8010' -> [22, 80, 8000, ..., 8010]"""
    ports: set[int] = set()
    for part in spec.split(","):
        part = part.strip()
        if not part:
            continue
        if "-" in part:
            start, end = (int(x) for x in part.split("-", 1))
            if start > end:
                raise ValueError(f"Plage invalide : {part}")
            ports.update(range(start, end + 1))
        else:
            ports.add(int(part))
    if not ports or min(ports) < 1 or max(ports) > 65535:
        raise ValueError("Ports valides : 1 à 65535")
    return sorted(ports)


def is_open(host: str, port: int, timeout: float = 0.5) -> bool:
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True
    except OSError:
        return False


def service_name(port: int) -> str:
    try:
        return socket.getservbyport(port)
    except OSError:
        return "inconnu"


def scan(host: str, ports: list[int], timeout: float = 0.5, workers: int = 100) -> list[int]:
    """Scan TCP connect. À utiliser uniquement sur des machines dont vous avez l'autorisation."""
    with ThreadPoolExecutor(max_workers=workers) as pool:
        results = pool.map(lambda p: (p, is_open(host, p, timeout)), ports)
    return [p for p, ok in results if ok]
