"""Deterministic, offline baseline and certificate-swap traffic."""
import argparse
from datetime import datetime, timezone
from pathlib import Path
import random
from scapy.layers.inet import IP, TCP
from scapy.layers.l2 import Ether
from scapy.packet import Raw
from scapy.utils import wrpcap
try:
    from . import tls_wire as wire
except ImportError:
    import tls_wire as wire

CAPTURE_TS = datetime(2026, 9, 5, tzinfo=timezone.utc).timestamp()
CERTS = Path(__file__).resolve().parent / 'certs' / 'corpus'


class Session:
    def __init__(self, client, server, cport, sport):
        self.client, self.server, self.cport, self.sport = client, server, cport, sport
        self.steps = []

    def c(self, data):
        self.steps.append(('c', data.encode() if isinstance(data, str) else data))

    def s(self, data):
        self.steps.append(('s', data.encode() if isinstance(data, str) else data))

    def packets(self, index):
        seq = {'c': 1000, 's': 5000}
        for step, (direction, data) in enumerate(self.steps):
            c = direction == 'c'
            packet = (Ether(src='02:00:00:00:00:01' if c else '02:00:00:00:00:02',
                            dst='02:00:00:00:00:02' if c else '02:00:00:00:00:01') /
                      IP(src=self.client if c else self.server, dst=self.server if c else self.client) /
                      TCP(sport=self.cport if c else self.sport, dport=self.sport if c else self.cport,
                          flags='PA', seq=seq[direction], ack=seq['s' if c else 'c']) / Raw(data))
            packet.time = CAPTURE_TS + index + step / 100
            seq[direction] += len(data)
            yield packet


def generate(kind, n=240, seed=7, out='out/baseline.pcap'):
    rng = random.Random(seed)
    if kind == 'baseline':
        counts = [int(n * p) for p in (.45, .10, .15)]
        modes = sum(([mode] * count for mode, count in zip(('start', 'pq', 'implicit'), counts)), [])
        modes += ['imap'] * (n - len(modes))
        rng.shuffle(modes)
    else:
        modes = ['imap'] * 41
    packets = []
    for index, mode in enumerate(modes):
        sport = 993 if mode == 'imap' else 465 if mode == 'implicit' else 25
        session = Session(f'10.1.0.{1 + index % 4}',
                          '10.2.0.1' if kind == 'certswap' else f'10.2.0.{1 + index % 3}',
                          41000 + index, sport)
        if sport == 25:
            session.s('220 mail.corpus.example ESMTP\r\n')
            session.c('EHLO client.corpus.example\r\n')
            session.s('250-mail.corpus.example\r\n250 STARTTLS\r\n')
            session.c('STARTTLS\r\n')
            session.s('220 Ready for TLS\r\n')
        session.c(wire.client_hello(random_bytes=rng.randbytes))
        version = wire.V_TLS12 if mode == 'imap' else wire.V_TLS13
        group = None if mode == 'imap' else wire.G_X25519MLKEM768 if mode == 'pq' else wire.G_X25519
        session.s(wire.server_hello(version, 0xc02f if mode == 'imap' else 0x1301,
                                    group=group, random_bytes=rng.randbytes))
        if mode == 'imap':
            cert_name = 'B' if kind == 'certswap' and index == 24 else 'A'
            session.s(wire.certificate((CERTS / f'cert_{cert_name}.der').read_bytes()))
        session.s(wire.app_data(random_bytes=rng.randbytes))
        session.c(wire.app_data(random_bytes=rng.randbytes))
        packets.extend(session.packets(index))
    Path(out).parent.mkdir(parents=True, exist_ok=True)
    wrpcap(str(out), packets)


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--kind', choices=['baseline', 'certswap'], required=True)
    parser.add_argument('--n', type=int, default=240)
    parser.add_argument('--seed', type=int, default=7)
    parser.add_argument('--out', required=True)
    args = parser.parse_args()
    if args.n < 1 or args.n > 24000:
        parser.error('n must be between 1 and 24000')
    generate(**vars(args))
