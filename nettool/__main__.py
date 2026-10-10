import argparse
import sys

from . import dns_tools, http_check, scanner, subnet


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(prog="nettool", description="Boîte à outils réseau pédagogique")
    sub = p.add_subparsers(dest="cmd", required=True)

    s = sub.add_parser("subnet", help="Décrire un réseau CIDR")
    s.add_argument("cidr")
    s.add_argument("--split", type=int, metavar="PREFIX", help="Découper en sous-réseaux /PREFIX")

    sc = sub.add_parser("scan", help="Scan TCP des ports d'une machine que vous possédez")
    sc.add_argument("host", nargs="?", default="127.0.0.1")
    sc.add_argument("--ports", default="1-1024")
    sc.add_argument("--timeout", type=float, default=0.5)

    d = sub.add_parser("dns", help="Résolution DNS")
    d.add_argument("name")

    h = sub.add_parser("headers", help="Auditer les en-têtes de sécurité HTTP d'un site")
    h.add_argument("url")

    args = p.parse_args(argv)
    try:
        if args.cmd == "subnet":
            for k, v in subnet.describe(args.cidr).items():
                print(f"{k:13s}: {v}")
            if args.split:
                print("sous-réseaux :", ", ".join(subnet.split(args.cidr, args.split)))
        elif args.cmd == "scan":
            print("Rappel : ne scannez que vos propres machines ou avec autorisation écrite.", file=sys.stderr)
            open_ports = scanner.scan(args.host, scanner.parse_ports(args.ports), args.timeout)
            for port in open_ports:
                print(f"{port}/tcp ouvert ({scanner.service_name(port)})")
            if not open_ports:
                print("Aucun port ouvert trouvé.")
        elif args.cmd == "dns":
            for fam, addrs in dns_tools.resolve(args.name).items():
                print(f"{fam}: {', '.join(addrs) or '-'}")
        elif args.cmd == "headers":
            status, headers = http_check.fetch_headers(args.url)
            report = http_check.analyze_headers(headers)
            print(f"HTTP {status}")
            for name in report["present"]:
                print(f"  [OK]       {name}")
            for name in report["missing"]:
                print(f"  [MANQUANT] {name} – {http_check.SECURITY_HEADERS[name]}")
    except (ValueError, OSError) as e:
        print(f"Erreur : {e}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
