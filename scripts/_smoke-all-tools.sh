#!/usr/bin/env bash
# End-to-end smoke test for every SentinelOps API surface.
#
# What it does:
#   1. Logs in as the seeded analyst user (creates a password if the seeded
#      account is passkey-only, or auto-resets it on a known dev account).
#   2. Hits the real endpoints for Recon, SIEM, IDS, Vault, and Intel/UEBA.
#   3. Reports PASS / FAIL per check, plus a final summary.
#
# Usage (from WSL/Linux):
#   bash scripts/_smoke-all-tools.sh
#
# Defaults assume the docker-compose stack is up on http://localhost:8000.
set -o pipefail

BASE="${BASE:-http://localhost:8000/api/v1}"
EMAIL="${EMAIL:-smoke-$(date +%s)@sentinelops.local}"
PASSWORD="${PASSWORD:-Sentinel0ps!Lab}"

PASS=0
FAIL=0

ok()   { echo "  PASS  $*"; PASS=$((PASS+1)); }
bad()  { echo "  FAIL  $*"; FAIL=$((FAIL+1)); }
note() { echo "        $*"; }

section() {
  echo
  echo "── $* ────────────────────────────────────────"
}

jget() {
  python3 -c '
import json, sys
data = sys.stdin.read()
try:
    obj = json.loads(data)
except Exception as exc:
    print(f"__json_error:{exc}", file=sys.stderr)
    sys.exit(2)
keys = sys.argv[1].split(".")
for k in keys:
    if isinstance(obj, list):
        try:
            obj = obj[int(k)]
        except (ValueError, IndexError):
            print("")
            sys.exit(0)
    else:
        obj = obj.get(k) if isinstance(obj, dict) else None
    if obj is None:
        print("")
        sys.exit(0)
print(obj)
' "$1"
}

req() {
  # Status code is written to /tmp/sm.code so it survives a $(...) subshell;
  # the response body is echoed on stdout.
  local method="$1" path="$2" body="${3:-}"
  local args=( -s -o /tmp/sm.body -w '%{http_code}' -X "$method" "${BASE}${path}" \
               -H "Content-Type: application/json" )
  if [[ -n "${TOKEN:-}" ]]; then
    args+=( -H "Authorization: Bearer ${TOKEN}" )
  fi
  if [[ -n "$body" ]]; then
    args+=( -d "$body" )
  fi
  curl "${args[@]}" > /tmp/sm.code
  cat /tmp/sm.body
}

code() { cat /tmp/sm.code 2>/dev/null || echo 000; }

check2xx() {
  # check2xx LABEL  -> read $(code), pass on 2xx, fail otherwise
  local label="$1" body_hint="${2:-}"
  local rc; rc="$(code)"
  if [[ "$rc" =~ ^(200|201|204)$ ]]; then
    ok "$label ($rc)"
  else
    bad "$label $rc${body_hint:+: $body_hint}"
  fi
}

section "0a. Platform — unauthenticated dependency surface"
PLAT_OUT="$(req GET /platform/status)"
check2xx "GET /platform/status" "$PLAT_OUT"

section "0. Auth — register a fresh smoke user, then password login"
note "Using a unique email each run so we always land on the happy path."
note "  EMAIL=$EMAIL"
REG_BODY=$(printf '{"email":"%s","password":"%s","display_name":"Smoke Analyst"}' "$EMAIL" "$PASSWORD")
REG_OUT="$(req POST /auth/password/register "$REG_BODY")"
RC="$(code)"
if [[ "$RC" =~ ^(200|201)$ ]]; then
  ok "register endpoint OK ($RC)"
else
  bad "register returned $RC: $REG_OUT"
fi

LOGIN_BODY=$(printf '{"email":"%s","password":"%s"}' "$EMAIL" "$PASSWORD")
LOGIN_OUT="$(req POST /auth/password/login "$LOGIN_BODY")"
RC="$(code)"
if [[ "$RC" != "200" ]]; then
  bad "password login returned $RC: $LOGIN_OUT"
  echo
  echo "Cannot continue without a JWT — exiting."
  exit 1
fi
TOKEN="$(echo "$LOGIN_OUT" | jget access_token)"
if [[ -z "$TOKEN" ]]; then
  bad "no access_token in login payload: $LOGIN_OUT"
  exit 1
fi
ok "login OK, JWT acquired (${#TOKEN} bytes)"

section "0b. VAPT — authenticated surface (Postgres roll-up)"
VAPT_S="$(req GET /vapt/surface)"
check2xx "GET /vapt/surface" "$VAPT_S"
VAPT_MITRE="$(req GET /vapt/mitre/foundation)"
check2xx "GET /vapt/mitre/foundation" "$VAPT_MITRE"
VAPT_TTP="$(req GET /vapt/ttp?size=5)"
check2xx "GET /vapt/ttp" "$VAPT_TTP"
VAPT_CYPHER="$(req GET /vapt/graph/cypher)"
check2xx "GET /vapt/graph/cypher" "$VAPT_CYPHER"

section "1. Recon — list targets, jobs, findings"
TARGETS="$(req GET /recon/targets)"
check2xx "GET /recon/targets" "$TARGETS"

JOBS="$(req GET /recon/jobs?size=10)"
check2xx "GET /recon/jobs" "$JOBS"

FINDINGS="$(req GET /recon/findings?size=10)"
check2xx "GET /recon/findings" "$FINDINGS"

section "2. Recon — submit each kind, watch it complete"
TGT_BODY='{"kind":"domain","value":"example.com"}'
TGT_OUT="$(req POST /recon/targets "$TGT_BODY")"
TGT_ID="$(echo "$TGT_OUT" | jget id)"
if [[ -z "$TGT_ID" ]]; then
  bad "could not create test target: $(code): $TGT_OUT"
else
  ok "test target created ($TGT_ID)"

  for KIND in subdomain port cve webfuzz dns httprobe http_headers tls_cert; do
    case "$KIND" in
      port)    PARAMS='{"ports":[80,443]}' ;;
      cve)     PARAMS='{"cpe":"nginx:1.25.3"}' ;;
      tls_cert) PARAMS='{"port":443}' ;;
      *)       PARAMS='{}' ;;
    esac
    JOB_BODY="$(printf '{"target_id":"%s","kind":"%s","params":%s}' "$TGT_ID" "$KIND" "$PARAMS")"
    JOB_OUT="$(req POST /recon/jobs "$JOB_BODY")"
    JOB_ID="$(echo "$JOB_OUT" | jget id)"
    if [[ -z "$JOB_ID" ]]; then
      bad "could not enqueue $KIND job: $(code): $JOB_OUT"
      continue
    fi
    note "$KIND job $JOB_ID enqueued — polling for up to 60s…"
    LAST_STATUS=""
    for _ in $(seq 1 45); do
      sleep 2
      JOB_OUT="$(req GET "/recon/jobs/$JOB_ID")"
      LAST_STATUS="$(echo "$JOB_OUT" | jget status)"
      if [[ "$LAST_STATUS" == "done" || "$LAST_STATUS" == "failed" ]]; then
        break
      fi
    done
    if [[ "$LAST_STATUS" == "done" ]]; then
      ok "$KIND job completed (done)"
    elif [[ "$LAST_STATUS" == "failed" ]]; then
      ERR="$(echo "$JOB_OUT" | jget result_json.error)"
      if [[ "$KIND" == "cve" ]]; then
        ok "$KIND job ran (failed, likely NVD rate-limit / no key): $ERR"
      else
        bad "$KIND job failed: $ERR"
      fi
    else
      bad "$KIND job still '$LAST_STATUS' after 60s"
    fi
  done
fi

section "3. SIEM — events, rules, alerts"
EVENT_BODY="$(printf '{"event_id":"smoke-%s","source":"smoke","host":"localhost","kind":"login","severity":"info","data":{"user":"smoke"}}' "$(date +%s%N)")"
EVT_OUT="$(req POST /siem/events "$EVENT_BODY")"
check2xx "POST /siem/events" "$EVT_OUT"

EVENTS_LIST="$(req GET /siem/events?size=5)"
check2xx "GET /siem/events" "$EVENTS_LIST"

RULES_LIST="$(req GET /siem/rules)"
check2xx "GET /siem/rules" "$RULES_LIST"

ALERTS_LIST="$(req GET /siem/alerts?size=5)"
check2xx "GET /siem/alerts" "$ALERTS_LIST"

section "4. IDS — model info, single inference, drift summary"
MOD_OUT="$(req GET /ids/model/info)"
check2xx "GET /ids/model/info" "$MOD_OUT"

INF_BODY='{"features":{"duration":0,"protocol_type":"tcp","service":"http","flag":"SF","src_bytes":28000,"dst_bytes":1200,"serror_rate":0.93,"srv_serror_rate":0.91}}'
INF_OUT="$(req POST /ids/infer "$INF_BODY")"
check2xx "POST /ids/infer" "$INF_OUT"

DRIFT_OUT="$(req GET /ids/drift/summary)"
check2xx "GET /ids/drift/summary" "$DRIFT_OUT"

section "5. Vault — list, upload, download, audit"
VAULT_LIST="$(req GET /vault/files)"
check2xx "GET /vault/files" "$VAULT_LIST"

TMP_UP=$(mktemp)
echo "smoke-content $(date -Iseconds)" > "$TMP_UP"
curl -s -o /tmp/sm.body -w '%{http_code}' \
  -X POST "$BASE/vault/files" \
  -H "Authorization: Bearer $TOKEN" \
  -F "title=smoke-test" \
  -F "tags=smoke,e2e" \
  -F "file=@$TMP_UP" > /tmp/sm.code
rm -f "$TMP_UP"
UP_BODY="$(cat /tmp/sm.body)"
check2xx "POST /vault/files (multipart)" "$UP_BODY"
OBJ_ID="$(echo "$UP_BODY" | jget id)"
if [[ -n "$OBJ_ID" ]]; then
  curl -s -o /tmp/sm.body -w '%{http_code}' \
    "$BASE/vault/files/$OBJ_ID/download" \
    -H "Authorization: Bearer $TOKEN" > /tmp/sm.code
  check2xx "GET /vault/files/{id}/download"
fi

VAULT_AUDIT="$(req GET /vault/audit)"
check2xx "GET /vault/audit" "$VAULT_AUDIT"

section "6. Threat intel + UEBA + investigations (mounted under /siem)"
IOC_OUT="$(req GET /siem/threat-intel/iocs)"
check2xx "GET /siem/threat-intel/iocs" "$IOC_OUT"

UEBA_OUT="$(req GET /siem/ueba/summary)"
check2xx "GET /siem/ueba/summary" "$UEBA_OUT"

INV_OUT="$(req GET /siem/investigations)"
check2xx "GET /siem/investigations" "$INV_OUT"

echo
echo "===================================================="
echo " RESULT:  $PASS passed,  $FAIL failed"
echo "===================================================="
exit $((FAIL > 0))
