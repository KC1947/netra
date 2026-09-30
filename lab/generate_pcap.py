"""Build deterministic baseline, correlation, and mixed-enterprise captures.

s1 SMTP 25   STARTTLS -> TLS1.3 clean
s2 SMTP 25   STARTTLS -> TLS1.0 legacy, weak self-signed cert   (downgrade)
s3 SMTP 25   no STARTTLS, AUTH PLAIN in cleartext               (credential exposure)
s4 SMTP 25   STARTTLS-strip (250-XSNVVQRW) then cleartext AUTH  (suspected)
s5 IMAPS 993 implicit TLS1.2 ECDHE, expired cert
s6 SMTP 465  implicit TLS1.3, hybrid PQ group X25519MLKEM768

``--multiclient`` writes out/multiclient.pcap with six stable client profiles
replayed against three servers with distinct version/cipher-selection policy.

``--enterprise`` writes tests/fixtures/mixed_enterprise.pcap.  Its immutable
answer key is tests/enterprise_ground_truth.json and deliberately predates the
generator implementation.
"""
import argparse
import base64
import datetime
import os
from pathlib import Path

from scapy.all import Ether, IP, TCP, UDP, Raw, wrpcap
from scapy.utils import RawPcapNgWriter, RawPcapWriter

if __package__:
    from .tls_wire import (client_hello, server_hello, certificate, app_data,
                           V_TLS13, V_TLS12, V_TLS11, V_TLS10,
                           G_X25519, G_X25519MLKEM768)
else:
    from tls_wire import (client_hello, server_hello, certificate, app_data,
                          V_TLS13, V_TLS12, V_TLS11, V_TLS10,
                          G_X25519, G_X25519MLKEM768)

HERE = os.path.dirname(__file__)
CERTS = os.path.join(HERE, "certs")
CLIENT = "10.0.0.10"
SERVER = "10.0.0.20"

# cipher code points
C_AES128_GCM_13 = 0x1301
C_AES256_GCM_13 = 0x1302
C_ECDHE_ECDSA_GCM = 0xc02b
C_ECDHE_RSA_GCM = 0xc02f
C_RSA_AES_CBC = 0x002f
C_RSA_AES256_CBC = 0x0035
C_FALLBACK_SCSV = 0x5600

ENTERPRISE_SEED = 0x5EC0
ENTERPRISE_CAPTURE = (
    Path(HERE).resolve().parent / "tests" / "fixtures" / "mixed_enterprise.pcap"
)

# Static DER material makes --enterprise byte-for-byte reproducible even when
# lab/certs_build.py is rerun.  These certificates contain fixture-only keys.
_VALID_RSA_DER = base64.b64decode(
    "MIICsjCCAZqgAwIBAgICA+kwDQYJKoZIhvcNAQELBQAwHDEaMBgGA1UEAwwR"
    "Q29ycCBGaXh0dXJlIFJvb3QwHhcNMjYwMTAxMDAwMDAwWhcNMzAwMTAxMDAw"
    "MDAwWjAcMRowGAYDVQQDDBFtYWlsLmNvcnAuZXhhbXBsZTCCASIwDQYJKoZI"
    "hvcNAQEBBQADggEPADCCAQoCggEBALIloW7fYCq2pM7z8cFYfmah09LXGpuh"
    "E73S9CAAti2CjhFfk+1h4O9RpHReleffTi6wicdO3+1ZWOX+MwtjFEJuVgkV"
    "KcKtQKqZH4NhrhkmdPi7b3k2umBOuRqR8wdrgoHOXQMI7A1JgjnGk+ZPTa97"
    "uIHRZRJ6o95mnEQd3CRYqR9kuSaD+0V+uM5jYl7XSs206HUNVlgcx9CznhPb"
    "CjXN3OiDRkVQIXCBteN48PPQnHCEzUjcdnfGeqtVn778EeeHMwkpyVz6ktCG2"
    "XX85+6h9DK/HBUQLCIDng63WVD2gNhk97yNSs3DaiZW9lTFUlGVxuoW79mHN"
    "svRNL0FC5kCAwEAATANBgkqhkiG9w0BAQsFAAOCAQEAKC4C/KWT9aIyF8aK"
    "YpIhhYSqeG8RGyDuyp/zQ+7o7bM1L0ZhYNnkz6V2kIDFlBgJBaFdJmxIvZhV"
    "rjP7qvNa4yqA9aPGs0TE03CoFKT2UfM1GP2llr31UUYvQOogImdf61+TfiMm"
    "6iRyv0O3e+YPRyHYKQ9riQRmg2VCDdiWfn6Q4UcJ8l1UVI86R9K2gzH7Q7Zx"
    "77+P65/jGXJbq8/UTAQZBTUAGnFacWP2pKGucj/ocLH55LexBJk7Y+bZ8cQpV"
    "csYurqS4I8fXzIKsl6K2sYttVzJug3FK0qoeVbNr1VF1TjwIbCZDMjoGCiJ2"
    "gyUq1tBMW6FYR9dHzUpQEqdMQ=="
)
_VALID_ECDSA_P256_DER = base64.b64decode(
    "MIIBMDCB1qADAgECAgID6jAKBggqhkjOPQQDAjAfMR0wGwYDVQQDDBRDb3Jw"
    "IEZpeHR1cmUgRUMgUm9vdDAeFw0yNjAxMDEwMDAwMDBaFw0zMDAxMDEwMDAw"
    "MDBaMCMxITAfBgNVBAMMGGltYXBzLWVjZHNhLmNvcnAuZXhhbXBsZTBZMBMG"
    "ByqGSM49AgEGCCqGSM49AwEHA0IABHyQYuj6PgWPl0a40BHCJVOqmSMa7FNP"
    "q8SoJgauhV8VhX1+RO18T/DwnkCguoU4A4O02bOpsg3a4gROF/+BuegwCgYI"
    "KoZIzj0EAwIDSQAwRgIhAObA34dDVyNKZ/7kHVRcQN3ErTTtjZW2K9P3NaYn"
    "ocajAiEAk6IWTDvn/QeCYL9f+zyAto9wg44169ASrEtYR7Zsqlg="
)
_WEAK_SELFSIGNED_DER = base64.b64decode(
    "MIIBwzCCASygAwIBAgIURKferzqYHFtiWTuWrt+KwPMdtuAwDQYJKoZIhvcN"
    "AQELBQAwHjEcMBoGA1UEAwwTbWFpbC5sZWdhY3kuZXhhbXBsZTAeFw0yNjA4"
    "MDIwMDAwMDBaFw0yNzA2MjgwMDAwMDBaMB4xHDAaBgNVBAMME21haWwubGVn"
    "YWN5LmV4YW1wbGUwgZ8wDQYJKoZIhvcNAQEBBQADgY0AMIGJAoGBANeVLmfP"
    "tLA+JkgosMeSJPS/2M9w5LuycgyvaeyYveEtJSpbdPhBCWzUdliH95FkA3jO"
    "BqHPpmWmsgtAJGo3GVoh+FE58HB3jugHg5Cd63iJBQK8loc3GpRDfTmy2W2l3"
    "gyPAFwxC9Lgi8q4d/6xCwBNtBEa2zSj291DBEy1HSHNAgMBAAEwDQYJKoZI"
    "hvcNAQELBQADgYEAp1OGBBpskO3xHyHJLjhNVTQv5/GW0juOSsZR81dXDXSg"
    "pDUJ0Ck1OArJrGZL55VXuQNXWmFFPdFakNgLPhko4SjR6MlPXFIU/x5e9C0W"
    "mifrEvA1Qgr1j5Jz80sYvykRYDKV00Qw35kLqyEgaSjNaqe/VLCi5liYiqEAG"
    "+jeRdY="
)
_EXPIRED_RSA_DER = base64.b64decode(
    "MIICwTCCAamgAwIBAgIUd/AX5PT5E1x4Vw9Nhn4Uf5MsTkQwDQYJKoZIhvcN"
    "AQELBQAwGjEYMBYGA1UEAwwPRXhhbXBsZSBSb290IENBMB4XDTI1MDEwMTAw"
    "MDAwMFoXDTI2MDEwMTAwMDAwMFowGzEZMBcGA1UEAwwQaW1hcC5leGFtcGxl"
    "LmNvbTCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBANDZN8DobN2N"
    "vzc4fsBd3XTG+LcsVIasYkxjVakeZZCCnxYKrUhArENSnQw7WL90Zikmb6Uz"
    "tGQnwnUjd+VwcZgEnlFJ56M8JbyJYQ3a8tFwxK7vO8dq2LOh7EvDu3VBShob"
    "bntJ7Fmj3lMgVPWebXl1i3PTP/LaUrRwJeGhZJPYx1k9ZKhbHu4tL4ZChOzRa"
    "NeC5QosIEuxmaI7Upjd5shG0roLda9Q3NqBS4f/BQwXY/8NMAkbauW5JXlNL"
    "8AYgBAhKU+oei78uPkIl3gPmahWaX0lkFNJ79oLav5YUoP4iqzOqD4v8GNUf"
    "vwH+Oen0Pq019KjEyPHIZ26/zCGg5ECAwEAATANBgkqhkiG9w0BAQsFAAOCAQ"
    "EAELOu/d/wVj3+85y8VnTntQxhqCQM3c9nWxjg6A1+3inKaVnTGc7HJ6L5JM"
    "yFlcvhYOoX5e5iD7qwXmcCcdLqH8DabZZNIno7G98Pq7vPNrbHgwosB9uCMd"
    "t91mhsK3ilgla4bC2a8JxfUpf+P4GDx+Cg6qVaKQZ2oBR9RKzMUGQTvgjxLD"
    "OHzBrMYJSfEMMAMJVkh8ekY2n0F6Zlex8SF2bgV2+yU/xkRcMW82TMMrWkT1"
    "a1+0Cb8hq173wOXxCv6AyrpO3jx4HYSTVGi7vKqPH4dMsIX64jId/HhxBCkE"
    "7ygezefdTZXnfXqyy9VLZ+ob8/T5Hxd53g86L0rapSdQ=="
)

_VERSION_NAMES = {V_TLS12: "TLS1.2", V_TLS13: "TLS1.3"}
_CIPHER_NAMES = {
    C_AES128_GCM_13: "TLS_AES_128_GCM_SHA256",
    C_AES256_GCM_13: "TLS_AES_256_GCM_SHA384",
    C_ECDHE_RSA_GCM: "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
    C_RSA_AES_CBC: "TLS_RSA_WITH_AES_128_CBC_SHA",
}

# Profiles 1 and 2 are the identifying opposite-order TLS 1.2 pair. Profile 3
# proves that the alternative cipher is genuinely supported by server A.
CLIENT_PROFILES = (
    {
        "id": "c1_tls12_ecdhe_first",
        "ip": "10.0.0.11",
        "versions": (V_TLS12,),
        "ciphers": (C_ECDHE_RSA_GCM, C_RSA_AES_CBC),
    },
    {
        "id": "c2_tls12_rsa_first",
        "ip": "10.0.0.12",
        "versions": (V_TLS12,),
        "ciphers": (C_RSA_AES_CBC, C_ECDHE_RSA_GCM),
    },
    {
        "id": "c3_tls12_rsa_only",
        "ip": "10.0.0.13",
        "versions": (V_TLS12,),
        "ciphers": (C_RSA_AES_CBC,),
    },
    {
        "id": "c4_dual_aes128_first",
        "ip": "10.0.0.14",
        "versions": (V_TLS13, V_TLS12),
        "ciphers": (C_AES128_GCM_13, C_AES256_GCM_13,
                    C_ECDHE_RSA_GCM, C_RSA_AES_CBC),
    },
    {
        "id": "c5_tls13_aes256_only",
        "ip": "10.0.0.15",
        "versions": (V_TLS13,),
        "ciphers": (C_AES256_GCM_13,),
    },
    {
        "id": "c6_dual_aes256_first",
        "ip": "10.0.0.16",
        "versions": (V_TLS13, V_TLS12),
        "ciphers": (C_AES256_GCM_13, C_AES128_GCM_13,
                    C_RSA_AES_CBC, C_ECDHE_RSA_GCM),
    },
)

MULTICLIENT_SERVERS = (
    {
        "id": "server A",
        "ip": "10.0.1.20",
        "policy": "server_order",
        "versions": (V_TLS13, V_TLS12),
        "tls13_order": (C_AES256_GCM_13, C_AES128_GCM_13),
        "tls12_order": (C_ECDHE_RSA_GCM, C_RSA_AES_CBC),
        "certificate": "weak_selfsigned.der",
    },
    {
        "id": "server B",
        "ip": "10.0.2.20",
        "policy": "client_order",
        "versions": (V_TLS13, V_TLS12),
        "tls13_order": (C_AES128_GCM_13, C_AES256_GCM_13),
        "tls12_order": (C_ECDHE_RSA_GCM, C_RSA_AES_CBC),
        "certificate": "expired.der",
    },
    {
        "id": "server C",
        "ip": "10.0.3.20",
        "policy": "tls13_only",
        "selection": "server_order",
        "versions": (V_TLS13,),
        "tls13_order": (C_AES128_GCM_13, C_AES256_GCM_13),
        "tls12_order": (),
        "certificate": None,
    },
)


def load(name):
    with open(os.path.join(CERTS, name), "rb") as f:
        return f.read()


class Session:
    """Collects (direction, payload) steps, emits ordered TCP packets."""
    def __init__(self, cport, sport, *, client_ip=CLIENT, server_ip=SERVER,
                 tcp_handshake=False):
        self.cport, self.sport = cport, sport
        self.client_ip, self.server_ip = client_ip, server_ip
        self.tcp_handshake = tcp_handshake
        self.steps = []           # ('c'|'s', bytes)
    def c(self, data):            # client -> server
        self.steps.append(("c", data if isinstance(data, bytes) else data.encode())); return self
    def s(self, data):            # server -> client
        self.steps.append(("s", data if isinstance(data, bytes) else data.encode())); return self
    def packets(self, t0):
        pk, cseq, sseq, t = [], 1000, 5000, t0
        if self.tcp_handshake:
            handshake = (
                Ether(src="02:00:00:00:00:01", dst="02:00:00:00:00:02")
                / IP(src=self.client_ip, dst=self.server_ip)
                / TCP(sport=self.cport, dport=self.sport, flags="S", seq=cseq),
                Ether(src="02:00:00:00:00:02", dst="02:00:00:00:00:01")
                / IP(src=self.server_ip, dst=self.client_ip)
                / TCP(sport=self.sport, dport=self.cport, flags="SA", seq=sseq,
                      ack=cseq + 1),
                Ether(src="02:00:00:00:00:01", dst="02:00:00:00:00:02")
                / IP(src=self.client_ip, dst=self.server_ip)
                / TCP(sport=self.cport, dport=self.sport, flags="A", seq=cseq + 1,
                      ack=sseq + 1),
            )
            for packet in handshake:
                packet.time = t
                t += 0.01
                pk.append(packet)
            cseq += 1
            sseq += 1
        for direction, data in self.steps:
            if direction == "c":
                p = Ether(src="02:00:00:00:00:01", dst="02:00:00:00:00:02")/IP(src=self.client_ip, dst=self.server_ip)/TCP(sport=self.cport, dport=self.sport,
                        flags="PA", seq=cseq, ack=sseq)/Raw(load=data)
                cseq += len(data)
            else:
                p = Ether(src="02:00:00:00:00:02", dst="02:00:00:00:00:01")/IP(src=self.server_ip, dst=self.client_ip)/TCP(sport=self.sport, dport=self.cport,
                        flags="PA", seq=sseq, ack=cseq)/Raw(load=data)
                sseq += len(data)
            p.time = t; t += 0.01
            pk.append(p)
        return pk, t + 0.5


# The six demonstration scenarios must be byte-reproducible.
# tls_wire defaults to os.urandom, so every handshake here names a fixed seed --
# the same discipline the multiclient and enterprise builders already follow.
SCENARIO_SEED = 200


def s1():
    x = Session(40001, 25)
    x.s("220 mail.example.com ESMTP\r\n")
    x.c("EHLO client.example.com\r\n")
    x.s("250-mail.example.com\r\n250-PIPELINING\r\n250 STARTTLS\r\n")
    x.c("STARTTLS\r\n")
    x.s("220 2.0.0 Ready to start TLS\r\n")
    x.c(client_hello(random_bytes=_fixed_random(SCENARIO_SEED + 1)))
    x.s(server_hello(V_TLS13, C_AES128_GCM_13, group=G_X25519,
                     random_bytes=_fixed_random(SCENARIO_SEED + 2)))
    x.s(app_data(random_bytes=_fixed_random(SCENARIO_SEED + 3)))
    x.c(app_data(random_bytes=_fixed_random(SCENARIO_SEED + 4)))
    return x


def s2():
    x = Session(40002, 25)
    x.s("220 mail.legacy.example ESMTP\r\n")
    x.c("EHLO client.example.com\r\n")
    x.s("250-mail.legacy.example\r\n250 STARTTLS\r\n")
    x.c("STARTTLS\r\n")
    x.s("220 Go ahead\r\n")
    # offers 1.3/1.2, server drops to 1.0
    x.c(client_hello(random_bytes=_fixed_random(SCENARIO_SEED + 11)))
    x.s(server_hello(V_TLS10, C_RSA_AES_CBC,
                     random_bytes=_fixed_random(SCENARIO_SEED + 12)))
    x.s(certificate(load("weak_selfsigned.der")))
    x.s(app_data(random_bytes=_fixed_random(SCENARIO_SEED + 13)))
    return x


def s3():
    x = Session(40003, 25)
    x.s("220 mail.example.com ESMTP\r\n")
    x.c("EHLO client.example.com\r\n")
    x.s("250-mail.example.com\r\n250 PIPELINING\r\n")     # no STARTTLS offered
    x.c("AUTH PLAIN AGxvZ2luAHN1cGVyc2VjcmV0\r\n")        # credentials in the clear
    x.s("235 2.7.0 Authentication successful\r\n")
    return x


def s4():
    x = Session(40004, 25)
    x.s("220 mail.example.com ESMTP\r\n")
    x.c("EHLO client.example.com\r\n")
    # capability mangled: STARTTLS (8 chars) replaced by XSNVVQRW (8 chars)
    x.s("250-mail.example.com\r\n250-PIPELINING\r\n250 XSNVVQRW\r\n")
    x.c("AUTH PLAIN AGxvZ2luAHN1cGVyc2VjcmV0\r\n")        # client falls back to clear
    x.s("235 2.7.0 Authentication successful\r\n")
    return x


def s5():
    x = Session(40005, 993)                               # implicit TLS
    x.c(client_hello(random_bytes=_fixed_random(SCENARIO_SEED + 21)))
    x.s(server_hello(V_TLS12, C_ECDHE_RSA_GCM,            # 1.2 + ECDHE (FS)
                     random_bytes=_fixed_random(SCENARIO_SEED + 22)))
    x.s(certificate(load("expired.der")))
    x.s(app_data(random_bytes=_fixed_random(SCENARIO_SEED + 23)))
    x.c(app_data(random_bytes=_fixed_random(SCENARIO_SEED + 24)))
    return x


def s6():
    x = Session(40006, 465)                               # implicit TLS
    x.c(client_hello(random_bytes=_fixed_random(SCENARIO_SEED + 31)))
    x.s(server_hello(V_TLS13, C_AES128_GCM_13, group=G_X25519MLKEM768,   # hybrid PQ
                     random_bytes=_fixed_random(SCENARIO_SEED + 32)))
    x.s(app_data(random_bytes=_fixed_random(SCENARIO_SEED + 33)))
    x.c(app_data(random_bytes=_fixed_random(SCENARIO_SEED + 34)))
    return x


SCENARIO_BUILDERS = (
    ("s1", "clean_tls13", s1),
    ("s2", "legacy_downgrade", s2),
    ("s3", "cleartext_auth", s3),
    ("s4", "strip_attack", s4),
    ("s5", "expired_cert", s5),
    ("s6", "pq_ready", s6),
)


def generate_scenarios(output_directory):
    """Write one self-contained capture per six-session demonstration case."""
    destination = Path(output_directory).resolve()
    destination.mkdir(parents=True, exist_ok=True)
    timestamp = datetime.datetime(2026, 9, 5, tzinfo=datetime.timezone.utc).timestamp()
    paths = {}
    for session_id, capture_id, builder in SCENARIO_BUILDERS:
        packets, _ = builder().packets(timestamp)
        path = destination / f"{capture_id}.pcap"
        wrpcap(str(path), packets)
        paths[session_id] = path
    return paths


def generate_unsupported_linktype_fixture(output_path):
    """Write deterministic pcapng records under unsupported link type 258."""
    path = Path(output_path).resolve()
    path.parent.mkdir(parents=True, exist_ok=True)
    writer = RawPcapNgWriter(str(path))
    writer.linktype = 258
    writer.write_header(None)
    timestamp = datetime.datetime(2026, 9, 26, tzinfo=datetime.timezone.utc).timestamp()
    for index, payload in enumerate((
        b"NETRA unsupported link type 258 fixture frame one",
        b"NETRA unsupported link type 258 fixture frame two",
    )):
        writer.write_packet(
            payload, sec=timestamp + index, caplen=len(payload), wirelen=len(payload),
        )
    writer.close()
    return path


def _fixed_random(seed):
    """Return deterministic synthetic bytes without sharing mutable RNG state."""
    return lambda length: bytes((seed + 37 * index) % 256 for index in range(length))


def _negotiate(server, client):
    negotiated_version = next(
        (version for version in server["versions"] if version in client["versions"]),
        None,
    )
    if negotiated_version is None:
        return None, None
    server_order = (
        server["tls13_order"] if negotiated_version == V_TLS13
        else server["tls12_order"]
    )
    supported = set(server_order)
    if server.get("selection", server["policy"]) == "client_order":
        negotiated_cipher = next(
            (cipher for cipher in client["ciphers"] if cipher in supported), None
        )
    else:
        offered = set(client["ciphers"])
        negotiated_cipher = next(
            (cipher for cipher in server_order if cipher in offered), None
        )
    return negotiated_version, negotiated_cipher


def _multiclient_session(server, client, server_index, client_index):
    negotiated_version, negotiated_cipher = _negotiate(server, client)
    session = Session(
        41001 + client_index,
        465,
        client_ip=client["ip"],
        server_ip=server["ip"],
    )
    session.c(client_hello(
        offered=client["versions"],
        ciphers=client["ciphers"],
        random_bytes=_fixed_random(16 + client_index),
    ))
    if negotiated_version is not None and negotiated_cipher is not None:
        seed = 64 + server_index * 16 + client_index
        session.s(server_hello(
            negotiated_version,
            negotiated_cipher,
            group=G_X25519 if negotiated_version == V_TLS13 else None,
            random_bytes=_fixed_random(seed),
        ))
        if negotiated_version == V_TLS12:
            session.s(certificate(load(server["certificate"])))
        session.s(app_data(32, random_bytes=_fixed_random(seed + 64)))
        session.c(app_data(24, random_bytes=_fixed_random(seed + 96)))
    return session, negotiated_version, negotiated_cipher


def generate_multiclient(output_path=None):
    """Write the 3-server × 6-client correlation fixture and print its oracle."""
    started = datetime.datetime(2026, 9, 6, tzinfo=datetime.timezone.utc).timestamp()
    packets, timestamp, summary = [], started, []
    for server_index, server in enumerate(MULTICLIENT_SERVERS):
        outcomes = []
        for client_index, client in enumerate(CLIENT_PROFILES):
            session, version, cipher = _multiclient_session(
                server, client, server_index, client_index
            )
            session_packets, timestamp = session.packets(timestamp)
            packets.extend(session_packets)
            outcomes.append((client["id"], version, cipher))
        summary.append((server, outcomes))

    if output_path is None:
        output_directory = os.path.abspath(os.path.join(HERE, "..", "out"))
        os.makedirs(output_directory, exist_ok=True)
        output_path = os.path.join(output_directory, "multiclient.pcap")
    else:
        output_path = os.path.abspath(os.fspath(output_path))
        os.makedirs(os.path.dirname(output_path), exist_ok=True)
    wrpcap(output_path, packets)
    print(f"Wrote {output_path}  ({len(packets)} packets, 18 sessions)")
    for server, outcomes in summary:
        print(f"{server['id']} ({server['ip']}:465, {server['policy']}):")
        for client_id, version, cipher in outcomes:
            version_name = _VERSION_NAMES.get(version, "NO_COMMON_VERSION")
            cipher_name = _CIPHER_NAMES.get(cipher, "none")
            print(f"  {client_id}: {version_name} / {cipher_name}")
    return output_path, summary


def _enterprise_smtp_tls(index, *, hostname, server_ip, server_port, versions,
                         ciphers, selected_version, selected_cipher,
                         certificate_der=None, group=None, tcp_handshake=False,
                         downgrade_sentinel=None, malformed_tail=False):
    """Build one explicit SMTP STARTTLS session without private user data."""
    session = Session(
        42000 + index, server_port,
        client_ip=f"10.21.{index // 200}.{10 + index}", server_ip=server_ip,
        tcp_handshake=tcp_handshake,
    )
    session.s(f"220 {hostname} ESMTP fixture ready\r\n")
    session.c(f"EHLO workstation-{index}.corp.example\r\n")
    session.s(
        f"250-{hostname}\r\n250-PIPELINING\r\n250 STARTTLS\r\n"
    )
    session.c("STARTTLS\r\n")
    session.s("220 2.0.0 Ready to start TLS\r\n")
    session.c(client_hello(
        offered=versions,
        ciphers=ciphers,
        server_name=hostname,
        groups=(G_X25519,),
        random_bytes=_fixed_random(ENTERPRISE_SEED + index * 11),
    ))
    session.s(server_hello(
        selected_version,
        selected_cipher,
        group=group,
        random_bytes=_fixed_random(ENTERPRISE_SEED + index * 11 + 1),
        downgrade_sentinel=downgrade_sentinel,
    ))
    if selected_version != V_TLS13 and certificate_der is not None:
        session.s(certificate(certificate_der))
    session.s(app_data(
        40, random_bytes=_fixed_random(ENTERPRISE_SEED + index * 11 + 2)
    ))
    session.c(app_data(
        32, random_bytes=_fixed_random(ENTERPRISE_SEED + index * 11 + 3)
    ))
    if malformed_tail:
        # A bounded, incomplete TLS record at the end cannot obscure the
        # complete handshake that precedes it.
        session.s(b"\x16\x03\x03\x00\x20\x01\x02\x03")
    return session


def _enterprise_implicit_tls(index, *, hostname, server_ip, server_port,
                             versions, ciphers, selected_version,
                             selected_cipher, certificate_der=None, group=None,
                             malformed_tail=False):
    """Build an implicit-TLS session that intentionally begins without SYN."""
    session = Session(
        42000 + index, server_port,
        client_ip=f"10.21.{index // 200}.{10 + index}", server_ip=server_ip,
    )
    session.c(client_hello(
        offered=versions,
        ciphers=ciphers,
        server_name=hostname,
        groups=(group or G_X25519,),
        random_bytes=_fixed_random(ENTERPRISE_SEED + index * 11),
    ))
    session.s(server_hello(
        selected_version,
        selected_cipher,
        group=group,
        random_bytes=_fixed_random(ENTERPRISE_SEED + index * 11 + 1),
    ))
    if selected_version != V_TLS13 and certificate_der is not None:
        session.s(certificate(certificate_der))
    session.s(app_data(
        40, random_bytes=_fixed_random(ENTERPRISE_SEED + index * 11 + 2)
    ))
    session.c(app_data(
        32, random_bytes=_fixed_random(ENTERPRISE_SEED + index * 11 + 3)
    ))
    if malformed_tail:
        session.c(b"\x16\x03\x03\x00\x18\xff")
    return session


def _enterprise_starttls_non_smtp(index, *, protocol, hostname, server_ip,
                                  server_port, versions, ciphers,
                                  selected_version, selected_cipher,
                                  certificate_der, tcp_handshake=True):
    session = Session(
        42000 + index, server_port,
        client_ip=f"10.21.{index // 200}.{10 + index}", server_ip=server_ip,
        tcp_handshake=tcp_handshake,
    )
    if protocol == "imap":
        session.s("* OK [CAPABILITY IMAP4rev1 STARTTLS] fixture ready\r\n")
        session.c("a001 STARTTLS\r\n")
        session.s("a001 OK Begin TLS negotiation now\r\n")
    elif protocol == "pop3":
        session.s("+OK POP3 fixture ready\r\n")
        session.c("STLS\r\n")
        session.s("+OK Begin TLS negotiation\r\n")
    else:
        raise ValueError(f"unsupported enterprise cleartext protocol: {protocol}")
    session.c(client_hello(
        offered=versions,
        ciphers=ciphers,
        server_name=hostname,
        groups=(G_X25519,),
        random_bytes=_fixed_random(ENTERPRISE_SEED + index * 11),
    ))
    session.s(server_hello(
        selected_version,
        selected_cipher,
        random_bytes=_fixed_random(ENTERPRISE_SEED + index * 11 + 1),
    ))
    session.s(certificate(certificate_der))
    session.s(app_data(
        40, random_bytes=_fixed_random(ENTERPRISE_SEED + index * 11 + 2)
    ))
    session.c(app_data(
        32, random_bytes=_fixed_random(ENTERPRISE_SEED + index * 11 + 3)
    ))
    return session


def _enterprise_mail_sessions():
    """Return the 25 ordered mail sessions fixed by the enterprise answer key."""
    sessions = []

    server_order = "mx-order.corp.example"
    server_order_cases = (
        ((V_TLS12,), (C_ECDHE_RSA_GCM, C_RSA_AES_CBC), V_TLS12,
         C_ECDHE_RSA_GCM, None, False),
        ((V_TLS12,), (C_RSA_AES_CBC, C_ECDHE_RSA_GCM), V_TLS12,
         C_ECDHE_RSA_GCM, None, False),
        ((V_TLS12,), (C_RSA_AES_CBC,), V_TLS12,
         C_RSA_AES_CBC, None, False),
        ((V_TLS12,), (C_FALLBACK_SCSV, C_ECDHE_RSA_GCM, C_RSA_AES_CBC),
         V_TLS12, C_ECDHE_RSA_GCM, None, True),
        ((V_TLS13,), (C_AES128_GCM_13, C_AES256_GCM_13), V_TLS13,
         C_AES256_GCM_13, G_X25519, False),
        ((V_TLS13,), (C_AES256_GCM_13, C_AES128_GCM_13), V_TLS13,
         C_AES256_GCM_13, G_X25519, False),
    )
    for index, (versions, ciphers, selected_version, selected_cipher,
                group, malformed) in enumerate(server_order_cases, start=1):
        sessions.append(_enterprise_smtp_tls(
            index,
            hostname=server_order,
            server_ip="10.20.1.10",
            server_port=25,
            versions=versions,
            ciphers=ciphers,
            selected_version=selected_version,
            selected_cipher=selected_cipher,
            certificate_der=_VALID_RSA_DER,
            group=group,
            tcp_handshake=index in {1, 3, 5},
            malformed_tail=malformed,
        ))

    client_order = "submit-client.corp.example"
    client_order_cases = (
        ((V_TLS12,), (C_ECDHE_RSA_GCM, C_RSA_AES_CBC), V_TLS12,
         C_ECDHE_RSA_GCM, None, False),
        ((V_TLS12,), (C_RSA_AES_CBC, C_ECDHE_RSA_GCM), V_TLS12,
         C_RSA_AES_CBC, None, False),
        ((V_TLS12,), (C_RSA_AES256_CBC, C_ECDHE_RSA_GCM, C_RSA_AES_CBC),
         V_TLS12, C_ECDHE_RSA_GCM, None, True),
        ((V_TLS12,), (C_ECDHE_RSA_GCM, C_RSA_AES256_CBC), V_TLS12,
         C_ECDHE_RSA_GCM, None, False),
        ((V_TLS13,), (C_AES128_GCM_13, C_AES256_GCM_13), V_TLS13,
         C_AES128_GCM_13, G_X25519, False),
        ((V_TLS13,), (C_AES256_GCM_13, C_AES128_GCM_13), V_TLS13,
         C_AES256_GCM_13, G_X25519, False),
    )
    for offset, (versions, ciphers, selected_version, selected_cipher,
                 group, malformed) in enumerate(client_order_cases, start=7):
        sessions.append(_enterprise_smtp_tls(
            offset,
            hostname=client_order,
            server_ip="10.20.2.10",
            server_port=587,
            versions=versions,
            ciphers=ciphers,
            selected_version=selected_version,
            selected_cipher=selected_cipher,
            certificate_der=_VALID_RSA_DER,
            group=group,
            tcp_handshake=offset in {7, 9, 11},
            malformed_tail=malformed,
        ))

    ambiguous = "relay-ambiguous.corp.example"
    ambiguous_cases = (
        ((V_TLS12,), (C_ECDHE_RSA_GCM, C_RSA_AES_CBC), V_TLS12,
         C_ECDHE_RSA_GCM, None, False),
        ((V_TLS12,), (C_RSA_AES_CBC, C_ECDHE_RSA_GCM), V_TLS12,
         C_ECDHE_RSA_GCM, None, False),
        ((V_TLS12,), (C_ECDHE_RSA_GCM,), V_TLS12,
         C_ECDHE_RSA_GCM, None, False),
        ((V_TLS12,), (C_RSA_AES_CBC, C_ECDHE_RSA_GCM), V_TLS12,
         C_ECDHE_RSA_GCM, None, True),
        ((V_TLS13,), (C_AES128_GCM_13, C_AES256_GCM_13), V_TLS13,
         C_AES128_GCM_13, G_X25519, False),
        ((V_TLS13,), (C_AES256_GCM_13, C_AES128_GCM_13), V_TLS13,
         C_AES128_GCM_13, G_X25519, False),
    )
    for offset, (versions, ciphers, selected_version, selected_cipher,
                 group, malformed) in enumerate(ambiguous_cases, start=13):
        sessions.append(_enterprise_implicit_tls(
            offset,
            hostname=ambiguous,
            server_ip="10.20.3.10",
            server_port=465,
            versions=versions,
            ciphers=ciphers,
            selected_version=selected_version,
            selected_cipher=selected_cipher,
            certificate_der=_VALID_RSA_DER,
            group=group,
            malformed_tail=malformed,
        ))

    sessions.append(_enterprise_starttls_non_smtp(
        19,
        protocol="imap",
        hostname="imap-legacy.corp.example",
        server_ip="10.20.4.10",
        server_port=143,
        versions=(V_TLS11,),
        ciphers=(C_ECDHE_RSA_GCM,),
        selected_version=V_TLS11,
        selected_cipher=C_ECDHE_RSA_GCM,
        certificate_der=_EXPIRED_RSA_DER,
    ))
    sessions.append(_enterprise_implicit_tls(
        20,
        hostname="imaps-ecdsa.corp.example",
        server_ip="10.20.5.10",
        server_port=993,
        versions=(V_TLS12,),
        ciphers=(C_ECDHE_ECDSA_GCM,),
        selected_version=V_TLS12,
        selected_cipher=C_ECDHE_ECDSA_GCM,
        certificate_der=_VALID_ECDSA_P256_DER,
    ))
    sessions.append(_enterprise_starttls_non_smtp(
        21,
        protocol="pop3",
        hostname="pop-legacy.corp.example",
        server_ip="10.20.6.10",
        server_port=110,
        versions=(V_TLS10,),
        ciphers=(C_RSA_AES_CBC,),
        selected_version=V_TLS10,
        selected_cipher=C_RSA_AES_CBC,
        certificate_der=_WEAK_SELFSIGNED_DER,
    ))
    sessions.append(_enterprise_implicit_tls(
        22,
        hostname="pops-pq.corp.example",
        server_ip="10.20.7.10",
        server_port=995,
        versions=(V_TLS13,),
        ciphers=(C_AES128_GCM_13,),
        selected_version=V_TLS13,
        selected_cipher=C_AES128_GCM_13,
        group=G_X25519MLKEM768,
    ))

    clear_auth = Session(
        42023, 25, client_ip="10.21.0.33", server_ip="10.20.8.10",
        tcp_handshake=True,
    )
    clear_auth.s("220 auth-clear.corp.example ESMTP fixture ready\r\n")
    clear_auth.c("EHLO workstation-23.corp.example\r\n")
    clear_auth.s(
        "250-auth-clear.corp.example\r\n250-PIPELINING\r\n250 AUTH PLAIN\r\n"
    )
    clear_auth.c("AUTH PLAIN <redacted-fixture-credential>\r\n")
    clear_auth.s("535 5.7.8 Authentication rejected by fixture\r\n")
    sessions.append(clear_auth)

    strip = Session(
        42024, 25, client_ip="10.21.0.34", server_ip="10.20.9.10"
    )
    strip.s("220 strip-edge.corp.example ESMTP fixture ready\r\n")
    strip.c("EHLO workstation-24.corp.example\r\n")
    strip.s(
        "250-strip-edge.corp.example\r\n250-PIPELINING\r\n250 XSNVVQRW\r\n"
    )
    strip.c("AUTH PLAIN <redacted-fixture-credential>\r\n")
    strip.s("535 5.7.8 Authentication rejected by fixture\r\n")
    sessions.append(strip)

    sessions.append(_enterprise_smtp_tls(
        25,
        hostname="submit-downgrade.corp.example",
        server_ip="10.20.10.10",
        server_port=587,
        versions=(V_TLS13, V_TLS12),
        ciphers=(C_FALLBACK_SCSV, C_ECDHE_RSA_GCM),
        selected_version=V_TLS12,
        selected_cipher=C_ECDHE_RSA_GCM,
        certificate_der=_VALID_RSA_DER,
        tcp_handshake=False,
        downgrade_sentinel=b"DOWNGRD\x01",
        malformed_tail=True,
    ))
    return sessions


def _enterprise_noise(started):
    """Return deterministic high-volume non-mail traffic and messy frames."""
    packets = []
    timestamp = started
    noise_flows = (
        ("192.0.2.10", "198.51.100.10", 51000, 80, b"GET /status HTTP/1.1\r\n\r\n"),
        ("192.0.2.11", "198.51.100.11", 51001, 22, b"SSH-2.0-fixture\r\n"),
        ("192.0.2.12", "198.51.100.12", 51002, 5432, b"PGSQL-FIXTURE\x00"),
        ("192.0.2.13", "198.51.100.13", 51003, 8443, b"METRIC fixture=1\n"),
    )
    for flow_index, (client_ip, server_ip, client_port, server_port,
                     prefix) in enumerate(noise_flows):
        cseq, sseq = 8000 + flow_index * 100000, 4000 + flow_index * 100000
        client_ether = Ether(
            src=f"02:00:00:10:00:{flow_index + 1:02x}",
            dst=f"02:00:00:20:00:{flow_index + 1:02x}",
        )
        server_ether = Ether(
            src=f"02:00:00:20:00:{flow_index + 1:02x}",
            dst=f"02:00:00:10:00:{flow_index + 1:02x}",
        )
        handshake = (
            client_ether/IP(src=client_ip, dst=server_ip)/TCP(
                sport=client_port, dport=server_port, flags="S", seq=cseq
            ),
            server_ether/IP(src=server_ip, dst=client_ip)/TCP(
                sport=server_port, dport=client_port, flags="SA", seq=sseq,
                ack=cseq + 1,
            ),
            client_ether/IP(src=client_ip, dst=server_ip)/TCP(
                sport=client_port, dport=server_port, flags="A", seq=cseq + 1,
                ack=sseq + 1,
            ),
        )
        for packet in handshake:
            packet.time = timestamp
            timestamp += 0.001
            packets.append(packet)
        cseq += 1
        sseq += 1
        for frame_index in range(560):
            pad = bytes(
                (ENTERPRISE_SEED + flow_index * 17 + frame_index + byte_index) % 256
                for byte_index in range(32)
            )
            payload = (prefix if frame_index == 0 else b"NOISE ") + pad
            packet = (
                client_ether/IP(src=client_ip, dst=server_ip)/TCP(
                    sport=client_port, dport=server_port, flags="PA", seq=cseq,
                    ack=sseq,
                )/Raw(load=payload)
            )
            packet.time = timestamp
            timestamp += 0.001
            packets.append(packet)
            cseq += len(payload)

    # Non-TCP traffic is intentionally outside mail triage.
    for index in range(5):
        packet = (
            Ether(src=f"02:00:00:30:00:{index + 1:02x}",
                  dst="02:00:00:30:00:c8")
            / IP(src=f"203.0.113.{10 + index}", dst="203.0.113.200")
            / UDP(sport=53000 + index, dport=53)
            / Raw(load=b"OFFLINE-DNS-FIXTURE-" + bytes([index]) * 24)
        )
        packet.time = timestamp
        timestamp += 0.001
        packets.append(packet)

    # Five deliberately short IPv4 frames exercise malformed-record accounting.
    for index in range(5):
        packet = (
            Ether(src=f"02:00:00:40:00:{index + 1:02x}",
                  dst="02:00:00:40:00:ff", type=0x0800)
            / Raw(load=b"\x45\x00" + bytes([index]) * 5)
        )
        packet.time = timestamp
        timestamp += 0.001
        packets.append(packet)
    return packets


def _write_enterprise_pcap(output_path, packets, truncated_indices):
    """Write stable microsecond timestamps and selected snaplen truncations."""
    writer = RawPcapWriter(str(output_path), linktype=1, snaplen=65535, sync=True)
    writer.write_header(None)
    for index, packet in enumerate(packets):
        raw = bytes(packet)
        microseconds = round(float(packet.time) * 1_000_000)
        seconds, usec = divmod(microseconds, 1_000_000)
        caplen = len(raw) - 12 if index in truncated_indices else len(raw)
        writer.write_packet(
            raw[:caplen], sec=seconds, usec=usec,
            caplen=caplen, wirelen=len(raw),
        )
    writer.close()


def generate_enterprise(output_path=None):
    """Write the answer-key-driven mixed enterprise fixture deterministically."""
    path = Path(output_path).resolve() if output_path else ENTERPRISE_CAPTURE
    path.parent.mkdir(parents=True, exist_ok=True)
    timestamp = datetime.datetime(
        2026, 9, 20, 10, 0, tzinfo=datetime.timezone.utc
    ).timestamp()
    packets = []
    for session in _enterprise_mail_sessions():
        session_packets, timestamp = session.packets(timestamp)
        packets.extend(session_packets)

    noise_start = len(packets)
    noise = _enterprise_noise(timestamp)
    packets.extend(noise)
    # Truncate three UDP records while leaving all answer-key mail evidence whole.
    udp_start = noise_start + 4 * (3 + 560)
    _write_enterprise_pcap(path, packets, {udp_start, udp_start + 1, udp_start + 2})
    print(f"Wrote {path}  ({len(packets)} frames; seed {ENTERPRISE_SEED})")
    return path


def generate_sample():
    """Preserve the original six-session demonstration capture."""
    t0 = datetime.datetime(2026, 9, 5, tzinfo=datetime.timezone.utc).timestamp()
    all_pk, t = [], t0
    for maker in (s1, s2, s3, s4, s5, s6):
        pk, t = maker().packets(t)
        all_pk += pk
    os.makedirs(os.path.join(HERE, "..", "out"), exist_ok=True)
    out = os.path.join(HERE, "..", "out", "sample.pcap")
    wrpcap(out, all_pk)
    print(f"Wrote {out}  ({len(all_pk)} packets, 6 sessions)")


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument(
        "--multiclient",
        action="store_true",
        help="write out/multiclient.pcap instead of the six-session demo capture",
    )
    mode.add_argument(
        "--scenarios",
        metavar="DIRECTORY",
        help="write the six self-contained scenario captures into DIRECTORY",
    )
    mode.add_argument(
        "--unsupported-fixture",
        metavar="PATH",
        help="write a deterministic pcapng fixture with link type 258",
    )
    mode.add_argument(
        "--enterprise",
        action="store_true",
        help="write tests/fixtures/mixed_enterprise.pcap from its answer key",
    )
    args = parser.parse_args(argv)
    if args.multiclient:
        generate_multiclient()
    elif args.scenarios:
        generate_scenarios(args.scenarios)
    elif args.unsupported_fixture:
        generate_unsupported_linktype_fixture(args.unsupported_fixture)
    elif args.enterprise:
        generate_enterprise()
    else:
        generate_sample()


if __name__ == "__main__":
    main()
