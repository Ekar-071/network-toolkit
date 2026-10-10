import socket
import threading

import pytest

from nettool import http_check, scanner, subnet
from nettool.__main__ import main


def test_subnet_describe():
    info = subnet.describe("192.168.1.77/24")
    assert info["network"] == "192.168.1.0"
    assert info["netmask"] == "255.255.255.0"
    assert info["broadcast"] == "192.168.1.255"
    assert info["usable_hosts"] == 254
    assert info["first_host"] == "192.168.1.1" and info["last_host"] == "192.168.1.254"
    assert info["private"] is True


def test_subnet_split():
    assert subnet.split("10.0.0.0/24", 26) == ["10.0.0.0/26", "10.0.0.64/26", "10.0.0.128/26", "10.0.0.192/26"]
    with pytest.raises(ValueError):
        subnet.split("10.0.0.0/24", 24)


def test_parse_ports():
    assert scanner.parse_ports("80, 22,8000-8002") == [22, 80, 8000, 8001, 8002]
    for bad in ("0", "70000", "10-5", ""):
        with pytest.raises(ValueError):
            scanner.parse_ports(bad)


def test_scan_finds_local_open_port():
    server = socket.socket()
    server.bind(("127.0.0.1", 0))
    server.listen()
    port = server.getsockname()[1]
    threading.Thread(target=lambda: server.accept(), daemon=True).start()
    closed = socket.socket()
    closed.bind(("127.0.0.1", 0))
    closed_port = closed.getsockname()[1]
    closed.close()  # port libéré -> fermé
    try:
        assert scanner.scan("127.0.0.1", [port, closed_port]) == [port]
    finally:
        server.close()


def test_analyze_headers_case_insensitive():
    report = http_check.analyze_headers({"strict-transport-security": "max-age=1", "Server": "x"})
    assert report["present"] == ["Strict-Transport-Security"]
    assert "Content-Security-Policy" in report["missing"]


def test_fetch_headers_rejects_bad_scheme():
    with pytest.raises(ValueError):
        http_check.fetch_headers("file:///etc/passwd")


def test_cli_subnet(capsys):
    assert main(["subnet", "172.16.0.0/16"]) == 0
    assert "255.255.0.0" in capsys.readouterr().out
    assert main(["subnet", "pas-un-reseau"]) == 1
