#!/usr/bin/env bash
# Start the complete offline SecureMailScope demo from a fresh terminal.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

if [[ ! -x .venv/bin/python ]]; then
  echo "Missing .venv. Run ./setup.sh once, then run ./scripts/demo.sh again." >&2
  exit 1
fi
source .venv/bin/activate

mkdir -p out
if [[ ! -f out/sample.pcap ]]; then
  python lab/generate_pcap.py
fi
if [[ ! -f out/baseline.pcap ]]; then
  python lab/generate_corpus.py --kind baseline --n 240 --seed 7 --out out/baseline.pcap
fi
if [[ ! -f out/anomaly_demo.pcap ]]; then
  python lab/generate_corpus.py --kind certswap --seed 11 --out out/anomaly_demo.pcap
fi

if [[ ! -f demo_captures/manifest.json || ! -f demo_captures/mixed_enterprise.pcap || ! -f demo_captures/anomaly_certswap.pcap ]]; then
  python lab/build_demo_library.py
fi

echo "SecureMailScope demo: http://127.0.0.1:8000"
exec python -m uvicorn server.app:app --host 127.0.0.1 --port 8000
