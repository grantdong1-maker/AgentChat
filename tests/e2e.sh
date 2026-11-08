#!/usr/bin/env bash
# End-to-end test of agentchat against a throwaway hub.
set -uo pipefail
export AGENTCHAT_HOME=/tmp/opencode/agentchat-test
export AGENTCHAT_RATE_MAX=12   # low cap so the flood test is quick
rm -rf "$AGENTCHAT_HOME"
AC="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)/bin/agentchat"
pass=0; fail=0

check() { # check DESC BOOL_EXPR_USING_d JSON_OR_TEXT
  local desc=$1 expr=$2 json=$3
  if AGENTCHAT_TEST_JSON="$json" python3 -c "
import json, os
raw = os.environ['AGENTCHAT_TEST_JSON'].strip()
try: d = json.loads(raw)
except Exception: d = raw
assert ($expr), d" 2>/dev/null; then
    pass=$((pass+1)); echo "ok    $desc"
  else
    fail=$((fail+1)); echo "FAIL  $desc :: $json"
  fi
}

echo "== start =="
$AC start >/dev/null || { echo "hub failed to start"; exit 1; }
check "hub healthy" "d['ok'] is True"        "$($AC status)"
check "signing on" "d['signing'] is True"    "$($AC status)"

echo "== identities =="
check "alice registered"  "'registered' in d" "$($AC register --name alice)"
check "bob registered"    "'registered' in d" "$($AC register --name bob)"
check "carlie registered" "'registered' in d" "$($AC register --name carlie)"
check "dupe name refused" "d == True" "$($AC register --name alice >/dev/null 2>&1; test $? -ne 0 && echo true)"

echo "== rooms =="
check "agent create refused" "d == True" "$($AC --as alice create --room dev --private >/dev/null 2>&1; test $? -ne 0 && echo true)"
check "refusal guides agents to request-room" "d == True" "$({ $AC --as alice create --room dev --private 2>&1 || true; } | grep -q 'request-room' && echo true)"
INV=$($AC --as alice create --room dev --private --admin)
check "human create with --admin works" "d['invite']" "$INV"
CODE=$(echo "$INV" | python3 -c "import json,sys; print(json.load(sys.stdin)['invite'])")
check "wrong invite refused" "d == True" "$($AC --as bob join --room dev --invite WRONG >/dev/null 2>&1; test $? -ne 0 && echo true)"
check "bad admin key refused" "d == True" "$(AGENTCHAT_ADMIN_KEY=not-the-key $AC --as alice create --room sneak --admin >/dev/null 2>&1; test $? -ne 0 && echo true)"
check "invite join works" "d['room']=='dev'" "$($AC --as bob join --room dev --invite $CODE)"
check "alice can see dev" "'dev' in str(d['rooms'])" "$($AC --as alice rooms)"
check "carlie cannot see private dev" "'dev' not in str(d['rooms'])" "$($AC --as carlie rooms)"

echo "== request -> human approval =="
REQ=$($AC --as bob request-room --room collab --why "pair on api refactor")
check "request accepted" "d['request']['id'] and d['request']['room']=='collab'" "$REQ"
check "requested room not created yet" "'collab' not in str(d['rooms'])" "$($AC --as bob rooms)"
REQID=$(echo "$REQ" | python3 -c "import json,sys;print(json.load(sys.stdin)['request']['id'])")
check "pending lists request" "'$REQID' in str(d['requests'])" "$($AC --as alice pending)"
APPR=$($AC --as alice approve $REQID)
check "approve creates room for requester" "d['room']=='collab' and d['for']=='bob'" "$APPR"
check "requester auto-joined" "'collab' in str(d['rooms'])" "$($AC --as bob rooms)"
check "requester DM-notified" "'approved' in str(d)" "$($AC --as bob pull --wait 2)"
NREQ=$($AC --as carlie request-room --room junkroom --why "mining" | python3 -c "import json,sys;print(json.load(sys.stdin)['request']['id'])")
$AC --as alice deny $NREQ >/dev/null
check "deny sends notice" "'declined' in str(d)" "$($AC --as carlie pull --wait 2)"
check "denied room does not exist" "d == True" "$($AC --as alice join --room junkroom >/dev/null 2>&1; test $? -ne 0 && echo true)"

echo "== broadcast + visibility =="
check "alice says in dev" "d['kind']=='chat' and d['seq']>0" "$($AC --as alice say --room dev hello-from-alice)"
check "bob receives broadcast" "'hello-from-alice' in str(d)" "$($AC --as bob pull --wait 2)"
check "bob verifies signatures" "all(m.get('sig_ok') is True for m in d['messages'] if m['kind']=='chat')" "$($AC --as bob history --room dev --limit 20)"
check "carlie cannot read private history" "d == True" "$($AC --as carlie history --room dev >/dev/null 2>&1; test $? -ne 0 && echo true)"

echo "== DMs =="
check "dm sent" "d['kind']=='dm'" "$($AC --as alice dm bob secret-payload)"
check "bob sees dm" "'secret-payload' in str(d)" "$($AC --as bob pull --wait 2)"
check "carlie cannot get dm" "d == True" "$(! $AC --as carlie pull --wait 0 | grep -q secret-payload && echo true)"

echo "== cursor & watch =="
check "watch exits after 1 msg" "d['messages_seen']>=1" "$(
  { sleep 1; $AC --as alice say --room dev wake-up >/dev/null & } ; $AC --as bob watch --idle-timeout 6 --max 1 | tail -1)"
check "no duplicate delivery" "d == True" "$(! $AC --as bob pull --wait 0 | grep -q wake-up && echo true)"

echo "== rate limit =="
codes=$(python3 - "$AC" <<'EOF'
import subprocess, sys
ac = sys.argv[1]
codes = set()
for i in range(30):
    r = subprocess.run([ac, "--as", "carlie", "say", "--room", "lobby", f"f{i}"],
                       capture_output=True, text=True)
    codes.add(r.returncode)
    if r.returncode != 0:
        break
print(" ".join(map(str, sorted(codes))))
EOF
)
check "flood gets 0 then non-0 (rate limited)" "d == '0 1'" "$codes"

echo "== restart persistence + tamper detection =="
$AC stop >/dev/null; $AC start >/dev/null
check "history survives restart" "'hello-from-alice' in str(d['messages'])" "$($AC --as alice history --room dev --limit 50)"
check "old token works after restart" "d['ok'] is True" "$($AC --as alice status-set back-up)"
# tamper a stored chat message server-side, rewind bob's cursor, bob must flag it
python3 - <<'EOF'
import json
p = '/tmp/opencode/agentchat-test/messages.jsonl'
ms = [json.loads(l) for l in open(p).read().splitlines()]
for m in ms:
    if m.get('kind') == 'chat':
        m['text'] = 'TAMPERED'; break
open(p, 'w').write('\n'.join(json.dumps(m) for m in ms) + '\n')
EOF
$AC stop >/dev/null; $AC start >/dev/null
python3 -c "import json; c=json.load(open('/tmp/opencode/agentchat-test/cursors.json')); c['bob']=0; json.dump(c, open('/tmp/opencode/agentchat-test/cursors.json','w'))"
check "bob flags tampered message" "any(m['text']=='TAMPERED' and m.get('sig_ok') is False for m in d['messages'])" "$($AC --as bob history --room dev --limit 200)"

echo
echo "passed=$pass failed=$fail"
$AC stop >/dev/null 2>&1
exit $((fail > 0))
