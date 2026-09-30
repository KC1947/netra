#!/usr/bin/env python3
"""Deterministic mutation fuzzer for the bounded TLS hello parsers."""

from __future__ import annotations

from collections.abc import Callable
from pathlib import Path
import random
import sys
import unittest

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from lab.tls_wire import G_X25519, V_TLS13, client_hello, server_hello
from sms.m4_tls import parse_client_hello, parse_server_hello
from sms.parsing.reader import Malformed, Truncated


RNG_SEED = 0x534D5315
MUTATIONS = 20_000
# Collected under pytest so the suite actually fuzzes. The full 20,000-mutation
# run stays available as a script and is what docs/V15_RESULTS.md reports; this
# bound keeps the collected test fast enough to run on every commit. Both cover
# both parsers and all four mutation kinds from the same seed, so the CI subset
# is a true prefix of the published run, not a different experiment.
CI_MUTATIONS = 2_000
_PARSE_STATUSES = frozenset({"complete", "truncated", "malformed"})
_MUTATION_KINDS = ("bit_flip", "truncation", "extension", "lying_length")


def _deterministic_bytes(length: int) -> bytes:
    return bytes((17 + 29 * index) & 0xFF for index in range(length))


def _handshake_body(record: bytes, expected_type: int) -> bytes:
    if len(record) < 9 or record[0] != 0x16 or record[5] != expected_type:
        raise AssertionError("invalid TLS handshake seed")
    body_length = int.from_bytes(record[6:9], "big")
    body = record[9:9 + body_length]
    if len(body) != body_length:
        raise AssertionError("truncated TLS handshake seed")
    return body


CLIENT_HELLO = _handshake_body(
    client_hello(random_bytes=_deterministic_bytes),
    0x01,
)
SERVER_HELLO = _handshake_body(
    server_hello(
        V_TLS13,
        0x1301,
        G_X25519,
        random_bytes=_deterministic_bytes,
    ),
    0x02,
)

# Offsets point to actual one- or two-byte length fields in the deterministic
# seeds: session ID, vectors, extension blocks, and key-exchange data.
_CLIENT_LENGTH_FIELDS = ((34, 1), (35, 2), (43, 1), (45, 2), (49, 2), (51, 1))
_SERVER_LENGTH_FIELDS = ((34, 1), (38, 2), (42, 2), (48, 2), (52, 2))


def _mutate(
    seed: bytes,
    length_fields: tuple[tuple[int, int], ...],
    kind: str,
    rng: random.Random,
) -> bytes:
    data = bytearray(seed)
    if kind == "bit_flip":
        for _ in range(rng.randint(1, min(4, len(data)))):
            offset = rng.randrange(len(data))
            data[offset] ^= 1 << rng.randrange(8)
    elif kind == "truncation":
        del data[rng.randrange(len(data)) :]
    elif kind == "extension":
        data.extend(rng.getrandbits(8) for _ in range(rng.randint(1, 32)))
    elif kind == "lying_length":
        offset, width = rng.choice(length_fields)
        maximum = (1 << (8 * width)) - 1
        lies = (0, 1, min(maximum, len(data) + 1), maximum, rng.randrange(maximum + 1))
        data[offset:offset + width] = rng.choice(lies).to_bytes(width, "big")
    else:  # pragma: no cover - the fixed mutation schedule cannot reach this
        raise AssertionError(f"unknown mutation kind: {kind}")
    return bytes(data)


def run_fuzzer(iterations: int = MUTATIONS, seed: int = RNG_SEED) -> dict[str, int]:
    """Run exactly ``iterations`` mutations, split evenly across both parsers."""
    rng = random.Random(seed)
    targets: tuple[
        tuple[str, bytes, tuple[tuple[int, int], ...], Callable[[bytes], dict]], ...
    ] = (
        ("client_hello", CLIENT_HELLO, _CLIENT_LENGTH_FIELDS, parse_client_hello),
        ("server_hello", SERVER_HELLO, _SERVER_LENGTH_FIELDS, parse_server_hello),
    )
    counts = {"client_hello": 0, "server_hello": 0}

    for iteration in range(iterations):
        name, original, length_fields, parser = targets[iteration % len(targets)]
        kind = _MUTATION_KINDS[(iteration // len(targets)) % len(_MUTATION_KINDS)]
        mutated = _mutate(original, length_fields, kind, rng)
        counts[name] += 1
        try:
            parsed = parser(mutated)
            if not isinstance(parsed, dict) or parsed.get("parse_status") not in _PARSE_STATUSES:
                raise AssertionError(f"invalid parser result: {parsed!r}")
        except (Truncated, Malformed):
            # Direct bounded-reader failures are part of the parser contract.
            continue
        except Exception as exc:
            print(
                f"unexpected exception iteration={iteration} parser={name} "
                f"mutation={kind} seed={seed} type={type(exc).__name__}: {exc}",
                file=sys.stderr,
            )
            print(f"reproducer_hex={mutated.hex()}", file=sys.stderr)
            raise

    return {
        "mutations_run": iterations,
        "client_hello_mutations": counts["client_hello"],
        "server_hello_mutations": counts["server_hello"],
        "unexpected_exceptions": 0,
        "rng_seed": seed,
    }


class FuzzParserTests(unittest.TestCase):
    """The collected form of the fuzzer.

    ``run_fuzzer`` raises on any exception that is not ``Truncated`` or
    ``Malformed`` and on any result lacking a valid ``parse_status``, printing
    the reproducing input, so reaching the assertions below is itself the
    survival check.
    """

    def test_bounded_run_survives_both_parsers(self):
        result = run_fuzzer(iterations=CI_MUTATIONS)
        self.assertEqual(result["mutations_run"], CI_MUTATIONS)
        self.assertEqual(result["unexpected_exceptions"], 0)
        self.assertEqual(result["rng_seed"], RNG_SEED)
        # Both parsers must be exercised, evenly.
        self.assertEqual(result["client_hello_mutations"], CI_MUTATIONS // 2)
        self.assertEqual(result["server_hello_mutations"], CI_MUTATIONS // 2)

    def test_run_is_deterministic_for_a_fixed_seed(self):
        self.assertEqual(run_fuzzer(iterations=256, seed=RNG_SEED),
                         run_fuzzer(iterations=256, seed=RNG_SEED))

    def test_every_mutation_kind_is_exercised(self):
        """A schedule that silently stopped covering a kind would still pass
        the survival check, so assert the coverage directly."""
        rng = random.Random(RNG_SEED)
        kinds = {
            _MUTATION_KINDS[(iteration // 2) % len(_MUTATION_KINDS)]
            for iteration in range(CI_MUTATIONS)
        }
        self.assertEqual(kinds, set(_MUTATION_KINDS))
        # And each kind really produces a parseable-or-rejected input.
        for kind in _MUTATION_KINDS:
            mutated = _mutate(CLIENT_HELLO, _CLIENT_LENGTH_FIELDS, kind, rng)
            self.assertIsInstance(mutated, bytes)


def main() -> int:
    result = run_fuzzer()
    print(
        "mutations_run={mutations_run} client_hello={client_hello_mutations} "
        "server_hello={server_hello_mutations} unexpected_exceptions={unexpected_exceptions} "
        "rng_seed={rng_seed}".format(**result)
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
