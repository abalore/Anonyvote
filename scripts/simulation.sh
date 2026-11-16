#!/usr/bin/env bash
# A complete election simulated end to end against the real services.
#
# This is the system's acceptance test: census, blind registration, phase change, voting,
# closing, publication, independent count, fraud attempts and detection of a tampered board.
#
#   ./scripts/simulation.sh [NUMBER_OF_VOTERS]   (1000 by default)

set -euo pipefail

VOTERS=${1:-1000}
ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
WORK=$(mktemp -d "${TMPDIR:-/tmp}/anonyvote-simulation.XXXXXX")
REGISTRAR_PORT=${REGISTRAR_PORT:-5801}
BALLOTBOX_PORT=${BALLOTBOX_PORT:-5802}
REG="http://127.0.0.1:$REGISTRAR_PORT"
BOX="http://127.0.0.1:$BALLOTBOX_PORT"

step() { printf '\n\033[1;34m== %s\033[0m\n' "$1"; }
die() { printf '\033[1;31mFAILED: %s\033[0m\n' "$1" >&2; exit 1; }

pids=()
cleanup() {
    for pid in "${pids[@]:-}"; do kill "$pid" 2>/dev/null || true; done
    wait 2>/dev/null || true
}
trap cleanup EXIT

step "Building"
dotnet build -c Release "$ROOT/Anonyvote.slnx" -v q --nologo >/dev/null

bin() { echo "$ROOT/$1/bin/Release/net10.0/$2.dll"; }
admin()     { dotnet "$(bin src/Anonyvote.Admin Anonyvote.Admin)" "$@"; }
verify()    { dotnet "$(bin src/Anonyvote.Verify Anonyvote.Verify)" "$@"; }
simulator() { dotnet "$(bin tools/Anonyvote.Simulator Anonyvote.Simulator)" "$@"; }

ELECTION="$WORK/election/election.json"

step "1. Set up the election ($VOTERS voters)"
printf 'Ana Torres\nBruno Gil\nCarla Ruiz\nDiego Mena\nElena Sanz\nFelipe Ocana\nGemma Rios\nHugo Valle\n' \
    > "$WORK/candidates.txt"
# 5 trustees, 3 to open the ballot box: the whole key never reaches disk.
admin init --dir "$WORK/election" --name "Board of Directors 2027" \
           --candidates "$WORK/candidates.txt" --max-choices 3 \
           --trustees 5 --threshold 3 >/dev/null
[ -f "$WORK/election/election-private.pem" ] \
    && die "with a threshold split the whole key must NOT be left on disk"
admin codes --db "$WORK/registrar.db" --count "$VOTERS" --out "$WORK/codes.txt" 2>/dev/null
admin codes --db "$WORK/registrar.db" --count 1 --out "$WORK/code-js.txt" 2>/dev/null
admin phase --db "$WORK/registrar.db"  --election "$ELECTION" --kind registrar --set registration
admin phase --db "$WORK/ballotbox.db" --election "$ELECTION" --kind ballotbox --set setup

step "2. Start both services"
Anonyvote__Election="$ELECTION" \
Anonyvote__PrivateKey="$WORK/election/registrar-private.pem" \
Anonyvote__Database="$WORK/registrar.db" \
    dotnet "$(bin src/Anonyvote.Registrar Anonyvote.Registrar)" --urls "$REG" \
    > "$WORK/registrar.log" 2>&1 &
pids+=($!)

Anonyvote__Election="$ELECTION" \
Anonyvote__Database="$WORK/ballotbox.db" \
    dotnet "$(bin src/Anonyvote.BallotBox Anonyvote.BallotBox)" --urls "$BOX" \
    > "$WORK/ballotbox.log" 2>&1 &
pids+=($!)

for url in "$REG" "$BOX"; do
    for _ in $(seq 50); do
        curl -sf "$url/api/election" >/dev/null 2>&1 && break
        sleep 0.2
    done
    curl -sf "$url/api/election" >/dev/null || die "service $url will not start (see $WORK/*.log)"
done
echo "registrar at $REG · ballot box at $BOX"

step "3. Registration phase: $VOTERS codes -> blind credentials"
simulator register --registrar "$REG" --codes "$WORK/codes.txt" \
                   --out "$WORK/credentials.json"
simulator attacks --phase registration --registrar "$REG" --ballotbox "$BOX" \
                  --codes "$WORK/codes.txt" --credentials "$WORK/credentials.json"

echo "The real browser client, run under Node against the same service:"
node "$ROOT/tests/interop/voter.mjs" register --registrar "$REG" \
     --code "$(head -1 "$WORK/code-js.txt")" --out "$WORK/credential-js.json" \
    || die "the web client does not interoperate with the registrar"

step "4. Close registration and open voting"
admin phase --db "$WORK/registrar.db"  --election "$ELECTION" --set closed
admin phase --db "$WORK/ballotbox.db" --election "$ELECTION" --set voting

step "5. Voting phase"
simulator vote --ballotbox "$BOX" --credentials "$WORK/credentials.json" \
               --out "$WORK/expected.json"
node "$ROOT/tests/interop/voter.mjs" vote --ballotbox "$BOX" \
     --credential "$WORK/credential-js.json" --choices 1,2 \
    || die "the web client does not interoperate with the ballot box"

simulator attacks --phase voting --registrar "$REG" --ballotbox "$BOX" \
                  --codes "$WORK/codes.txt" --credentials "$WORK/credentials.json"

# The JS client's vote must show up in the final tally too.
python3 -I - "$WORK/expected.json" <<'PY'
import json, sys
path = sys.argv[1]
data = json.load(open(path))
for candidate in ("1", "2"):
    data["tally"][candidate] += 1
data["ballots"] += 1
json.dump(data, open(path, "w"))
PY

step "6. Close and publish"
admin phase --db "$WORK/ballotbox.db" --election "$ELECTION" --set closed

# Two shares are not enough: the threshold is 3.
if admin publish --ballotbox-db "$WORK/ballotbox.db" --registrar-db "$WORK/registrar.db" \
                 --election "$ELECTION" --out "$WORK/no.json" \
                 --share "$WORK/election/share-1.json" \
                 --share "$WORK/election/share-2.json" >/dev/null 2>&1; then
    die "the ballot box opened with fewer shares than the threshold"
fi
echo "  two shares do not open the ballot box (threshold 3)"

admin publish --ballotbox-db "$WORK/ballotbox.db" --registrar-db "$WORK/registrar.db" \
              --election "$ELECTION" --out "$WORK/results.json" \
              --share "$WORK/election/share-1.json" \
              --share "$WORK/election/share-3.json" \
              --share "$WORK/election/share-5.json"

step "7. Independent count"
verify "$WORK/results.json"

step "8. Does the count match what was voted?"
verify "$WORK/results.json" --json > "$WORK/obtained.json"
python3 -I - "$WORK/expected.json" "$WORK/obtained.json" <<'PY' || die "the count does NOT match"
import json, sys
expected = json.load(open(sys.argv[1]))
obtained = json.load(open(sys.argv[2]))
errors = []
if not obtained["ok"]: errors.append(f"the verifier found problems: {obtained['problems']}")
if obtained["ballots"] != expected["ballots"]: errors.append("different number of ballots")
if obtained["blank"] != expected["blank"]: errors.append("different number of blank votes")
if obtained["spoilt"] != 0: errors.append(f"{obtained['spoilt']} unexpected spoilt ballots")
for cid, votes in expected["tally"].items():
    if obtained["tally"].get(cid) != votes:
        errors.append(f"candidate {cid}: expected {votes}, counted {obtained['tally'].get(cid)}")
if errors:
    print("\n".join(f"  - {e}" for e in errors)); sys.exit(1)
print(f"  identical count: {expected['ballots']} ballots, {expected['blank']} blank")
PY

step "9. The results page agrees with the reference verifier"
# The browser recomputes the whole count from the published file. If its hash chain,
# signature checks or decryption disagreed with the C# verifier in any way, it would show up
# right here rather than in front of a voter.
node "$ROOT/tests/interop/verify.mjs" --results "$WORK/results.json" > "$WORK/browser.json" \
    || die "the browser-side verification rejected a valid election"
python3 -I - "$WORK/obtained.json" "$WORK/browser.json" <<'PY' || die "browser and reference verifier disagree"
import json, sys
reference = json.load(open(sys.argv[1]))
browser = json.load(open(sys.argv[2]))
fields = ["ok", "head", "ballots", "census", "credentials", "blank", "spoilt", "tally"]
differences = [f for f in fields if reference[f] != browser[f]]
if differences:
    print("\n".join(f"  - {f}: reference {reference[f]!r} vs browser {browser[f]!r}" for f in differences))
    sys.exit(1)
print(f"  identical verdict and tally, same chain head {browser['head'][:16]}...")
PY

step "10. The last voter's receipt is on the board"
RECEIPT=$(python3 -I -c 'import json,sys; print(json.load(open(sys.argv[1]))["receipt"])' "$WORK/expected.json")
verify "$WORK/results.json" --receipt "$RECEIPT" | grep -q "Receipt found" \
    || die "the receipt was not found on the board"
echo "  receipt $RECEIPT located"

step "11. Tampering with the published board must be detected"
python3 -I - "$WORK/results.json" "$WORK/tampered.json" <<'PY'
import json, sys, base64
data = json.load(open(sys.argv[1]))
entry = data["board"][len(data["board"]) // 2]
ct = bytearray(base64.b64decode(entry["ciphertext"]))
ct[-1] ^= 0x01                       # a single bit flipped in one ballot
entry["ciphertext"] = base64.b64encode(bytes(ct)).decode()
json.dump(data, open(sys.argv[2], "w"))
PY
if verify "$WORK/tampered.json" >/dev/null 2>&1; then
    die "the verifier did NOT detect a tampered board"
fi
echo "  detected: one altered bit breaks the hash chain"

step "12. The ballot box cuts off a flood of requests"
FLOOD_PORT=$((BALLOTBOX_PORT + 100))
Anonyvote__Election="$ELECTION" \
Anonyvote__Database="$WORK/ballotbox-flood.db" \
Anonyvote__RateLimit__PerSecond=5 \
Anonyvote__RateLimit__Queue=0 \
    dotnet "$(bin src/Anonyvote.BallotBox Anonyvote.BallotBox)" --urls "http://127.0.0.1:$FLOOD_PORT" \
    > "$WORK/ballotbox-flood.log" 2>&1 &
pids+=($!)
for _ in $(seq 50); do
    curl -sf "http://127.0.0.1:$FLOOD_PORT/api/election" >/dev/null 2>&1 && break
    sleep 0.2
done
simulator flood --ballotbox "http://127.0.0.1:$FLOOD_PORT" --count 40

step "SIMULATION PASSED"
echo "Files kept in $WORK for inspection"
