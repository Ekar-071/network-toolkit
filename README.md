# nettool – boîte à outils réseau en Python

Petit outil en ligne de commande pour comprendre et manipuler les notions de base des réseaux, sans dépendance externe (bibliothèque standard uniquement).

**Stack :** Python 3.10+ · `socket` · `ipaddress` · `urllib` · `argparse` · pytest

## Fonctionnalités
| Commande | Rôle |
|---|---|
| `subnet 192.168.1.0/24 [--split 26]` | Masque, broadcast, nombre d'hôtes, plage utilisable, découpage en sous-réseaux (VLSM) |
| `scan [hôte] --ports 1-1024` | Scan TCP *connect* multi-threads avec nom de service |
| `dns exemple.fr` | Résolution IPv4 / IPv6 |
| `headers https://exemple.fr` | Audit des en-têtes de sécurité HTTP (HSTS, CSP, X-Frame-Options…) |

## Utilisation
```bash
python -m nettool subnet 10.0.0.0/24 --split 26
python -m nettool scan 127.0.0.1 --ports 20-100,443,8000-8100
python -m nettool dns example.org
python -m nettool headers https://example.org
pytest -q
```

## ⚠️ Usage responsable
Le scan de ports ne doit viser que **vos propres machines, un laboratoire personnel ou un système pour lequel vous avez une autorisation écrite**. Scanner des machines tierces peut être illégal.

## Pistes d'amélioration
- Scan UDP, détection de bannières de services
- Balayage ping d'un réseau (ICMP) et table ARP
- Export JSON / CSV des résultats
- Valider les concepts sur un labo virtuel (VirtualBox, Packet Tracer, GNS3)
