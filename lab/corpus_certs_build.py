"""One-time corpus certificate creation. Refuses to replace committed fixtures."""
from datetime import datetime, timezone
from pathlib import Path
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID


def main():
    dest = Path(__file__).resolve().parent / 'certs' / 'corpus'
    if any((dest / f'cert_{name}.der').exists() for name in ('A', 'B')):
        raise SystemExit('Corpus certificates already exist; never regenerate them.')
    dest.mkdir(parents=True, exist_ok=True)
    for index, name in enumerate(('A', 'B'), 1):
        key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        issuer_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        cert = (x509.CertificateBuilder()
                .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, 'mail.corpus.example')]))
                .issuer_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, f'Corpus CA {name}')]))
                .public_key(key.public_key()).serial_number(index)
                .not_valid_before(datetime(2026, 1, 1, tzinfo=timezone.utc))
                .not_valid_after(datetime(2027, 1, 1, tzinfo=timezone.utc))
                .add_extension(x509.SubjectAlternativeName([x509.DNSName('mail.corpus.example')]), critical=False)
                .sign(issuer_key, hashes.SHA256()))
        (dest / f'cert_{name}.der').write_bytes(cert.public_bytes(serialization.Encoding.DER))
    # Private keys exist only in memory and are never written.


if __name__ == '__main__':
    main()
