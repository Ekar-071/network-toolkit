import urllib.request

SECURITY_HEADERS = {
    "Strict-Transport-Security": "Force HTTPS (HSTS)",
    "Content-Security-Policy": "Limite les sources de contenu (anti-XSS)",
    "X-Frame-Options": "Protège contre le clickjacking",
    "X-Content-Type-Options": "Empêche le MIME sniffing",
    "Referrer-Policy": "Contrôle les informations de provenance",
}


def analyze_headers(headers: dict[str, str]) -> dict[str, list[str]]:
    """Sépare les en-têtes de sécurité présents et manquants (insensible à la casse)."""
    lower = {k.lower() for k in headers}
    return {
        "present": [h for h in SECURITY_HEADERS if h.lower() in lower],
        "missing": [h for h in SECURITY_HEADERS if h.lower() not in lower],
    }


def fetch_headers(url: str, timeout: float = 5.0) -> tuple[int, dict[str, str]]:
    if not url.startswith(("http://", "https://")):
        raise ValueError("L'URL doit commencer par http:// ou https://")
    req = urllib.request.Request(url, method="HEAD", headers={"User-Agent": "nettool/1.0"})
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        return resp.status, dict(resp.headers.items())
