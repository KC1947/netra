"""Hand-craft minimal-but-real TLS handshake bytes.

We build these by hand because a modern OpenSSL will refuse to negotiate
TLS 1.0 / 1024-bit RSA / SHA-1, so we cannot capture a real weak server.
The structure is genuine TLS (opens in Wireshark); we only include the
fields our passive parser reads.
"""
import struct, os

# TLS record content types
CT_HANDSHAKE = 0x16
CT_APPDATA = 0x17
# handshake message types
HS_CLIENT_HELLO = 0x01
HS_SERVER_HELLO = 0x02
HS_CERTIFICATE = 0x0b
# version code points
V_TLS10 = 0x0301
V_TLS11 = 0x0302
V_TLS12 = 0x0303
V_TLS13 = 0x0304
# named groups
G_X25519 = 0x001d
# All three RFC 10024 hybrid post-quantum groups. HNDL classifies from the
# registry, so a fixture must be able to exercise the SecP variants too.
G_SECP256R1MLKEM768 = 0x11eb
G_X25519MLKEM768 = 0x11ec
G_SECP384R1MLKEM1024 = 0x11ed
# Obsoleted by RFC 10024: a legacy tell, never quantum-safe.
G_X25519KYBER768DRAFT00 = 0x6399


def _u16(n): return struct.pack("!H", n)
def _u24(n): return struct.pack("!I", n)[1:]


def _record(content_type, legacy_version, payload):
    return bytes([content_type]) + _u16(legacy_version) + _u16(len(payload)) + payload


def _handshake(msg_type, body):
    return bytes([msg_type]) + _u24(len(body)) + body


def _ext(ext_type, data):
    return _u16(ext_type) + _u16(len(data)) + data


def client_hello(offered=(V_TLS13, V_TLS12), *,
                 ciphers=(0x1301, 0xc02f, 0x002f), server_name=None,
                 groups=(), random_bytes=os.urandom):
    """A client hello with caller-controlled ordered version/cipher offers."""
    body = b""
    body += _u16(V_TLS12)                 # legacy client_version
    body += random_bytes(32)               # random
    body += bytes([0])                    # session_id length 0
    suites = b"".join(_u16(cipher) for cipher in ciphers)
    body += _u16(len(suites)) + suites    # cipher_suites
    body += bytes([1, 0])                 # compression: 1 method, null
    # extensions
    sv = bytes([len(offered) * 2]) + b"".join(_u16(v) for v in offered)
    exts = _ext(0x002b, sv)               # supported_versions
    if server_name is not None:
        hostname = server_name.encode("ascii")
        name = bytes([0]) + _u16(len(hostname)) + hostname
        exts += _ext(0x0000, _u16(len(name)) + name)  # server_name
    if groups:
        group_vector = b"".join(_u16(group) for group in groups)
        exts += _ext(0x000a, _u16(len(group_vector)) + group_vector)
    body += _u16(len(exts)) + exts
    return _record(CT_HANDSHAKE, V_TLS10, _handshake(HS_CLIENT_HELLO, body))


def server_hello(negotiated, cipher, group=None, *, random_bytes=os.urandom,
                 downgrade_sentinel=None):
    """group set -> emit a key_share ext (TLS 1.3 style)."""
    body = b""
    legacy = V_TLS12 if negotiated >= V_TLS12 else negotiated
    body += _u16(legacy)                  # legacy_version
    random = random_bytes(32)
    if downgrade_sentinel is not None:
        if downgrade_sentinel not in (b"DOWNGRD\x00", b"DOWNGRD\x01"):
            raise ValueError("invalid RFC 8446 downgrade sentinel")
        random = random[:-8] + downgrade_sentinel
    body += random
    body += bytes([0])                    # session_id len 0
    body += _u16(cipher)
    body += bytes([0])                    # compression null
    exts = b""
    if negotiated == V_TLS13:
        exts += _ext(0x002b, _u16(V_TLS13))               # supported_versions (selected)
    if group is not None:
        ks = _u16(group) + _u16(32) + random_bytes(32)      # group + key_exchange
        exts += _ext(0x0033, ks)                          # key_share
    body += _u16(len(exts)) + exts
    return _record(CT_HANDSHAKE, V_TLS10, _handshake(HS_SERVER_HELLO, body))


def certificate(der_bytes):
    """TLS 1.0/1.2 Certificate message carrying one DER cert."""
    one = _u24(len(der_bytes)) + der_bytes
    body = _u24(len(one)) + one           # certificate_list
    return _record(CT_HANDSHAKE, V_TLS12, _handshake(HS_CERTIFICATE, body))


def app_data(n=48, *, random_bytes=os.urandom):
    return _record(CT_APPDATA, V_TLS12, random_bytes(n))
