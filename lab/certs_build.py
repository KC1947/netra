"""Generate real DER certificates for the lab, chosen to trigger findings.

  weak_selfsigned.der  -> self-signed, 1024-bit RSA  (for the TLS 1.0 session)
  expired.der          -> valid dates in the past    (for the TLS 1.2 session)

Certs are DER so our X.509 module parses them with `cryptography`.
"""
import datetime, os
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa

HERE = os.path.dirname(__file__)
OUT = os.path.join(HERE, "certs")


def _name(cn):
    return x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)])


def _write(path, cert):
    with open(path, "wb") as f:
        f.write(cert.public_bytes(serialization.Encoding.DER))


def build():
    os.makedirs(OUT, exist_ok=True)
    now = datetime.datetime(2026, 9, 1, tzinfo=datetime.timezone.utc)

    # 1) self-signed, weak 1024-bit key, valid now
    k1 = rsa.generate_private_key(public_exponent=65537, key_size=1024)
    c1 = (x509.CertificateBuilder()
          .subject_name(_name("mail.legacy.example"))
          .issuer_name(_name("mail.legacy.example"))          # issuer == subject
          .public_key(k1.public_key())
          .serial_number(x509.random_serial_number())
          .not_valid_before(now - datetime.timedelta(days=30))
          .not_valid_after(now + datetime.timedelta(days=300))
          # cryptography rejects SHA-1 certificate signing; use SHA-256.
          .sign(k1, hashes.SHA256()))
    _write(os.path.join(OUT, "weak_selfsigned.der"), c1)

    # 2) expired at capture time (Sep 2026): expired Jan 2026
    k2 = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    issuer_k = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    c2 = (x509.CertificateBuilder()
          .subject_name(_name("imap.example.com"))
          .issuer_name(_name("Example Root CA"))               # issuer != subject
          .public_key(k2.public_key())
          .serial_number(x509.random_serial_number())
          .not_valid_before(datetime.datetime(2025, 1, 1, tzinfo=datetime.timezone.utc))
          .not_valid_after(datetime.datetime(2026, 1, 1, tzinfo=datetime.timezone.utc))
          .sign(issuer_k, hashes.SHA256()))
    _write(os.path.join(OUT, "expired.der"), c2)
    print("Wrote", os.path.join(OUT, "weak_selfsigned.der"))
    print("Wrote", os.path.join(OUT, "expired.der"))


if __name__ == "__main__":
    build()
