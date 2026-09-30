#!/bin/sh
set -eu

ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/../.." && pwd)
PYTHON_BIN=${PYTHON_BIN:-python}
OUT_DIR="$ROOT/out"
BACKGROUND="$OUT_DIR/haystack_background.pcap"
HAYSTACK="$OUT_DIR/haystack.pcap"
TRUTH="$OUT_DIR/haystack.truth.json"

mkdir -p "$OUT_DIR"

if [ ! -f "$ROOT/out/sample.pcap" ]; then
    "$PYTHON_BIN" "$ROOT/lab/generate_pcap.py"
fi
if [ ! -f "$ROOT/out/multiclient.pcap" ]; then
    "$PYTHON_BIN" "$ROOT/lab/generate_pcap.py" --multiclient
fi

# A public capture is accepted only with an adjacent truth document declaring
# zero mail sessions; otherwise precision could not honestly be measured.
if [ -n "${BACKGROUND_PCAP:-}" ] && [ -f "$BACKGROUND_PCAP" ] && \
   [ -f "${BACKGROUND_TRUTH:-}" ] && \
   "$PYTHON_BIN" -c 'import json,sys; raise SystemExit(json.load(open(sys.argv[1])).get("known_mail_sessions") != 0)' "$BACKGROUND_TRUTH"
then
    BACKGROUND=$(CDPATH= cd -- "$(dirname -- "$BACKGROUND_PCAP")" && pwd)/$(basename -- "$BACKGROUND_PCAP")
    BACKGROUND_KIND=annotated_public_non_mail
    echo "Using annotated public background capture: $BACKGROUND"
else
    BACKGROUND_KIND=synthetic_non_mail
    echo "No annotated public background capture is available; generating deterministic synthetic non-mail traffic."
    "$PYTHON_BIN" "$ROOT/lab/scripts/haystack_data.py" background --output "$BACKGROUND"
fi

if command -v mergecap >/dev/null 2>&1; then
    MERGECAP=$(command -v mergecap)
elif [ -x /Applications/Wireshark.app/Contents/MacOS/mergecap ]; then
    MERGECAP=/Applications/Wireshark.app/Contents/MacOS/mergecap
else
    echo "mergecap is required to build the haystack" >&2
    exit 1
fi

"$MERGECAP" -F pcap -w "$HAYSTACK" \
    "$BACKGROUND" "$ROOT/out/sample.pcap" "$ROOT/out/multiclient.pcap"

"$PYTHON_BIN" "$ROOT/lab/scripts/haystack_data.py" truth \
    --output "$TRUTH" \
    --haystack "$HAYSTACK" \
    --background "$BACKGROUND" \
    --background-kind "$BACKGROUND_KIND" \
    "$ROOT/out/sample.pcap" "$ROOT/out/multiclient.pcap"

echo "Haystack: $HAYSTACK"
echo "Truth: $TRUTH"
