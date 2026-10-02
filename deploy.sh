#!/usr/bin/env bash
# ====================================================================================
# SOC Buddy - Azure Infrastructure Deployment Script for Azure Cloud Shell
# ====================================================================================
# Deploys Azure resources using an ARM template, builds the container image in ACR,
# configures Managed Identity, creates the Azure Bot app registration and resource,
# sets up FIC for Agent Blueprint & Azure Bot, and grants required permissions for
# Work IQ Mail MCP, Azure, Microsoft Graph Security, and Agent 365 Observability.
# ====================================================================================

set -euo pipefail
exec > >(tee -a "deploy_$(date +%F_%T).log") 2>&1

# Text formatting
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
BOLD='\033[1m'
NC='\033[0m' # No Color

log_info() { echo -e "${BLUE}[INFO]${NC} $1"; }
log_success() { echo -e "${GREEN}[SUCCESS]${NC} $1"; }
log_warn() { echo -e "${YELLOW}[WARNING]${NC} $1"; }
log_error() { echo -e "${RED}[ERROR]${NC} $1" >&2; }
log_step() { echo -e "\n${CYAN}${BOLD}==>${NC} ${BOLD}$1${NC}"; }

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CONFIG_FILE="$SCRIPT_DIR/a365.generated.config.json"
TEMPLATE_FILE="$SCRIPT_DIR/azuredeploy.json"

# ------------------------------------------------------------------------------
# 1. Environment & Prerequisite Checks
# ------------------------------------------------------------------------------
log_step "Checking Azure Cloud Shell prerequisites..."

command -v az >/dev/null || { log_error "Azure CLI is required."; exit 1; }
command -v python3 >/dev/null || { log_error "python3 is required."; exit 1; }
az account show >/dev/null 2>&1 || { log_error "Run 'az login' first."; exit 1; }
[ -f "$CONFIG_FILE" ] || { log_error "Missing $CONFIG_FILE. Run 'a365 setup all' first."; exit 1; }
[ -f "$TEMPLATE_FILE" ] || { log_error "Missing $TEMPLATE_FILE."; exit 1; }

required_variables=( APP_NAME LOCATION )
for variable in "${required_variables[@]}"; do
  [ -n "${!variable:-}" ] || { log_error "Set the $variable environment variable."; exit 1; }
done

if [[ ! "$APP_NAME" =~ ^[a-z][a-z0-9-]{0,30}[a-z0-9]$ ]] || [[ "$APP_NAME" == *"--"* ]]; then
  log_error "APP_NAME must be 2-32 lowercase letters, digits, or single hyphens." && exit 1
fi

TENANT_ID=$(az account show --query tenantId -o tsv)
SUB_NAME=$(az account show --query name -o tsv)
SUB_ID=$(az account show --query id -o tsv)
RG="rg-${APP_NAME}"
FOUNDRY_MODEL="${FOUNDRY_MODEL:-gpt-5.6-luna}"

read_config() {
  python3 -c "import json; print(json.load(open('$CONFIG_FILE'))['$1'])"
}

BLUEPRINT_CLIENT_ID=$(read_config agentBlueprintId)
AGENTIC_INSTANCE_ID=$(read_config agenticAppId)
[ -n "$BLUEPRINT_CLIENT_ID" ] || { log_error "agentBlueprintId is missing from $CONFIG_FILE."; exit 1; }
[ -n "$AGENTIC_INSTANCE_ID" ] || { log_error "agenticAppId is missing from $CONFIG_FILE."; exit 1; }

log_info "Tenant ID:           ${BOLD}${TENANT_ID}${NC}"
log_info "Subscription:        ${BOLD}${SUB_NAME}${NC} (${SUB_ID})"
log_info "Azure Region:        ${BOLD}${LOCATION}${NC}"
log_info "Application Name:    ${BOLD}${APP_NAME}${NC}"
log_info "Resource Group:      ${BOLD}${RG}${NC}"
log_info "Foundry Model:       ${BOLD}${FOUNDRY_MODEL}${NC}"
log_info "Blueprint Client ID: ${BOLD}${BLUEPRINT_CLIENT_ID}${NC}"
log_info "Agent Instance ID:   ${BOLD}${AGENTIC_INSTANCE_ID}${NC}"

for provider in Microsoft.App Microsoft.OperationalInsights Microsoft.ContainerRegistry Microsoft.CognitiveServices Microsoft.BotService; do
  if [ "$(az provider show -n "$provider" --query registrationState -o tsv 2>/dev/null || true)" != "Registered" ]; then
    az provider register -n "$provider" --wait --output none
  fi
done

# Sentinel MCP is deprecated
# TRIAGE_MCP_SP_ID="7b7b3966-1961-47b5-b080-43ca5482e21c"
# if ! az ad sp show --id "$TRIAGE_MCP_SP_ID" &>/dev/null; then
#   az ad sp create --id "$TRIAGE_MCP_SP_ID" 2>/dev/null
# fi

# ------------------------------------------------------------------------------
# 2. Setup Azure Bot identity
# ------------------------------------------------------------------------------
# Create or reuse single-tenant Entra application for Azure Bot.
log_step "Setting up Azure Bot identity..."

CHECK_AZURE_BOT_CLIENT_ID=$(az ad app list --query "[?displayName == '${APP_NAME}'].appId" -o tsv)

if [ -n "$CHECK_AZURE_BOT_CLIENT_ID" ]; then
  AZURE_BOT_CLIENT_ID="$CHECK_AZURE_BOT_CLIENT_ID"
  log_info "Reusing existing Azure Bot application."
else
  AZURE_BOT_CLIENT_ID=$(az ad app create \
    --display-name "$APP_NAME" \
    --sign-in-audience "AzureADMyOrg" \
    --query "appId" -o tsv)
  while [ -z "$(az ad app show --id "$AZURE_BOT_CLIENT_ID" --query "appId" -o tsv 2>/dev/null)" ]; do
    log_info "Waiting for Azure Bot application to be available..."
    sleep 1
  done
fi

CHECK_AZURE_BOT_SP_ID=$(az ad sp show --id "$AZURE_BOT_CLIENT_ID" --query "id" -o tsv 2>/dev/null || true)

if [ -n "$CHECK_AZURE_BOT_SP_ID" ]; then
  AZURE_BOT_SP_ID="$CHECK_AZURE_BOT_SP_ID"
  log_info "Reusing existing Azure Bot service principal."
else
  AZURE_BOT_SP_ID=$(az ad sp create --id "$AZURE_BOT_CLIENT_ID" --query "id" -o tsv)
fi

log_info "Azure Bot Client ID: ${BOLD}${AZURE_BOT_CLIENT_ID}${NC}"
log_info "Azure Bot SP ID:     ${BOLD}${AZURE_BOT_SP_ID}${NC}"

# ------------------------------------------------------------------------------
# 3. Deploy Infrastructure via ARM Template
# ------------------------------------------------------------------------------

log_step "Deploying Azure Infrastructure via ARM Template..."

if ! az group show -n "$RG" &>/dev/null; then
  az group create -n "$RG" -l "$LOCATION" --output none
fi

FOUNDRY_MODEL_VERSION=$(az cognitiveservices model list -l "$LOCATION" \
  --query "[?model.name=='${FOUNDRY_MODEL}' && kind=='AIServices'].model.version | sort(@) | [-1]" -o tsv)
[ -n "$FOUNDRY_MODEL_VERSION" ] || { log_error "Model $FOUNDRY_MODEL is unavailable in $LOCATION."; exit 1; }

DEPLOYMENT_OUTPUT=$(az deployment group create \
  --name "deploy-${APP_NAME}-$(date +%s)" \
  --resource-group "$RG" \
  --template-file "$TEMPLATE_FILE" \
  --parameters \
    appName="$APP_NAME" \
    location="$LOCATION" \
    blueprintClientId="$BLUEPRINT_CLIENT_ID" \
    agenticInstanceId="$AGENTIC_INSTANCE_ID" \
    tenantId="$TENANT_ID" \
    azureBotClientId="$AZURE_BOT_CLIENT_ID" \
    foundryModelName="$FOUNDRY_MODEL" \
    foundryModelVersion="$FOUNDRY_MODEL_VERSION" \
  --query "properties.outputs" -o json)

log_success "ARM Template deployment completed."

output_value() {
  python3 -c "import json,sys; print(json.load(sys.stdin)['$1']['value'])" <<< "$DEPLOYMENT_OUTPUT"
}
ACR_NAME=$(output_value acrName)
UAMI_PRINCIPAL_ID=$(output_value uamiPrincipalId)
APP_FQDN=$(output_value containerAppFqdn)
FOUNDRY_PROJECT_ENDPOINT=$(output_value foundryEndpoint)

# ------------------------------------------------------------------------------
# 4. Build Container Image in ACR & Update Container App
# ------------------------------------------------------------------------------
log_step "Building container image in ACR ($ACR_NAME)..."
log_info "Running 'az acr build' from context: $SCRIPT_DIR"
az acr build -r "$ACR_NAME" -t "${APP_NAME}:latest" "$SCRIPT_DIR"

log_info "Updating Container App '$APP_NAME' with built image..."
az containerapp update -n "$APP_NAME" -g "$RG" \
    --image "${ACR_NAME}.azurecr.io/${APP_NAME}:latest" --output none
log_success "Container App updated with '${APP_NAME}:latest'."

# ------------------------------------------------------------------------------
# 5. Setup Federated Identity Credentials (FIC)
# ------------------------------------------------------------------------------
log_step "Configuring Federated Identity Credentials (FIC) for Blueprint & Teams Bot..."

FIC_NAME="containerapp-uami-fic"

# Check if FIC already exists on Blueprint
EXISTING_BP_FIC=$(az ad app federated-credential list --id "$BLUEPRINT_CLIENT_ID" \
  --query "[?name=='${FIC_NAME}'].name" -o tsv 2>/dev/null || true)

if [ -z "$EXISTING_BP_FIC" ]; then
  log_info "Adding Federated Identity Credential to Agent Blueprint ($BLUEPRINT_CLIENT_ID)..."
  az ad app federated-credential create --id "$BLUEPRINT_CLIENT_ID" \
    --parameters "{
        \"name\": \"${FIC_NAME}\",
        \"issuer\": \"https://login.microsoftonline.com/${TENANT_ID}/v2.0\",
        \"subject\": \"${UAMI_PRINCIPAL_ID}\",
        \"audiences\": [\"api://AzureADTokenExchange\"]
    }" --output none
  log_success "FIC added to Blueprint."
else
    log_info "FIC '$FIC_NAME' already configured on Agent Blueprint."
fi

# Configure FIC, Web Redirect URI, and Blueprint API permission on Teams Bot App
log_info "Configuring Teams Bot application ($AZURE_BOT_CLIENT_ID)..."

# 1. Federated Identity Credential
EXISTING_TB_FIC=$(az ad app federated-credential list --id "$AZURE_BOT_CLIENT_ID" \
  --query "[?name=='${FIC_NAME}'].name" -o tsv 2>/dev/null || true)
if [ -z "$EXISTING_TB_FIC" ]; then
  az ad app federated-credential create --id "$AZURE_BOT_CLIENT_ID" \
    --parameters "{
      \"name\": \"${FIC_NAME}\",
      \"issuer\": \"https://login.microsoftonline.com/${TENANT_ID}/v2.0\",
      \"subject\": \"${UAMI_PRINCIPAL_ID}\",
      \"audiences\": [\"api://AzureADTokenExchange\"]
    }" --output none
  log_success "FIC added to Teams Bot App."
else
  log_info "FIC '$FIC_NAME' already configured on Teams Bot App."
fi

# 2. Configure Web Redirect URI
log_info "Configuring Web Redirect URI on Teams Bot application ($AZURE_BOT_CLIENT_ID)..."
mapfile -t CURRENT_REDIRECT_URIS < <(
  az ad app show --id "$AZURE_BOT_CLIENT_ID" --query "web.redirectUris[]" -o tsv
)

OAUTH_REDIRECT_URI="https://${APP_FQDN}/auth/callback"
REDIRECT_URI_EXISTS=false
for redirect_uri in "${CURRENT_REDIRECT_URIS[@]}"; do
  if [ "$redirect_uri" = "$OAUTH_REDIRECT_URI" ]; then
    REDIRECT_URI_EXISTS=true
    break
  fi
done

if [ "$REDIRECT_URI_EXISTS" = false ]; then
  CURRENT_REDIRECT_URIS+=("$OAUTH_REDIRECT_URI")
  az ad app update \
    --id "$AZURE_BOT_CLIENT_ID" \
    --web-redirect-uris "${CURRENT_REDIRECT_URIS[@]}" \
    --output none
fi
log_success "Web Redirect URI set to: $OAUTH_REDIRECT_URI"

# 3. Grant Agent Blueprint access permission ('access_agent_as_user')
log_info "Granting Agent Blueprint access permission ('access_agent_as_user') to Teams Bot..."
SCOPE_ID=$(az ad app show --id "$BLUEPRINT_CLIENT_ID" 
  --query "api.oauth2PermissionScopes[?value=='access_agent_as_user'].id | [0]" -o tsv)

if [ -z "$SCOPE_ID" ]; then
  log_error "Scope 'access_agent_as_user' was not found on Blueprint application '$BLUEPRINT_CLIENT_ID'."
  exit 1
fi

BOT_REQUIRED_RESOURCE_ACCESS=$(az ad app show --id "$AZURE_BOT_CLIENT_ID" --query "requiredResourceAccess" -o json)

if ! python3 -c '
import json, sys

resource_app_id, scope_id = sys.argv[1:3]
permissions = json.load(sys.stdin)
found = any(
  item.get("resourceAppId") == resource_app_id
  and any(access.get("id") == scope_id for access in item.get("resourceAccess", []))
  for item in permissions
)
raise SystemExit(0 if found else 1)
' "$BLUEPRINT_CLIENT_ID" "$SCOPE_ID" <<< "$BOT_REQUIRED_RESOURCE_ACCESS"; then
  az ad app permission add \
    --id "$AZURE_BOT_CLIENT_ID" \
    --api "$BLUEPRINT_CLIENT_ID" \
    --api-permissions "${SCOPE_ID}=Scope"
fi
log_success "Blueprint access permission ('access_agent_as_user') configured on Teams Bot."

# ------------------------------------------------------------------------------
# 6. Configure Inheritable and Required API Permissions & Grant Admin Consent
# ------------------------------------------------------------------------------
log_step "Configuring permissions and granting admin consent..."

# Permission Definitions:
# 1. Work IQ Mail MCP:       App 16b1878d-62c7-4009-aa25-68989d63bbad, Obj 93aac09f-5f9b-4b4c-aa45-c623a1b69342, DelegatedRoleId fa91a9e8-6808-4167-a950-8f1fe525b270, Scope Tools.ListInvoke.All
# 2. Azure Tools:            App 797f4846-ba00-4fd7-ba43-dac1f8f63013, Obj 71e36942-1dcc-468d-bb7f-6ca533a87559, DelegatedRoleId 41094075-9dad-400e-a0bd-54e686782033, Scope user_impersonation
# 3. Microsoft Graph:        App 00000003-0000-0000-c000-000000000000, Obj aaad2076-26ab-4905-b1eb-090f627b17d7, DelegatedRoleId 128ca929-1a19-45e6-a3b8-435ec44a36ba, Scope SecurityIncident.ReadWrite.All
#                            App 00000003-0000-0000-c000-000000000000, Obj aaad2076-26ab-4905-b1eb-090f627b17d7, DelegatedRoleId b152eca8-ea73-4a48-8c98-1a6742673d99, Scope ThreatHunting.Read.All
# 4. Agent365 Observability: App 9b975845-388f-4429-889e-eab1ef63949c, Obj a3af7c4d-8203-45c5-a467-ea084e2bbcfa, AppRoleId 8f71190c-00c8-461d-a63b-f74abde9ba52, Role Agent365.Observability.OtelWrite

# Deprecated Sentinel MCP Permissions:
# 1. Data Exploration: App 4500ebfb-89b6-4b14-a480-7f749797bfcd, Obj eaff9684-612c-4add-aa10-035fd3bfe3d1, DelegatedRoleId 991a963a-4203-4dbc-acf2-254a258f76f2, Scope SentinelPlatform.DelegatedAccess
# 2. Triage:           App 7b7b3966-1961-47b5-b080-43ca5482e21c, Obj 8dd500d0-c3aa-4380-96d1-09b4b6233eff, DelegatedRoleId 69b8d760-4df6-4017-a3e6-1a8049cbce42, Scope MCP.Read.All

# Step 6A: Allow agent identities created from the Blueprint to inherit permissions
INHERITABLE_PERMISSIONS_ENDPOINT="https://graph.microsoft.com/v1.0/applications/${BLUEPRINT_CLIENT_ID}/microsoft.graph.agentIdentityBlueprint/inheritablePermissions"
for resource_app_id in "16b1878d-62c7-4009-aa25-68989d63bbad" "797f4846-ba00-4fd7-ba43-dac1f8f63013" "00000003-0000-0000-c000-000000000000" "9b975845-388f-4429-889e-eab1ef63949c"; do
  existing_resource_app_id=$(az rest --method get --url "$INHERITABLE_PERMISSIONS_ENDPOINT" \
    --query "value[?resourceAppId=='${resource_app_id}'].resourceAppId | [0]" --output tsv)
  if [ "$existing_resource_app_id" != "$resource_app_id" ]; then
    az rest --method post --url "$INHERITABLE_PERMISSIONS_ENDPOINT" \
      --headers "Content-Type=application/json" \
      --body "{\"resourceAppId\":\"${resource_app_id}\",\"inheritableScopes\":{\"@odata.type\":\"microsoft.graph.allAllowedScopes\"}}" \
      --output none
  fi
done
log_success "Inheritable permissions configured on Blueprint."

# Step 6B: Add required application and delegated permissions
TARGET_ACCESS='[
  {
    "resourceAppId": "16b1878d-62c7-4009-aa25-68989d63bbad",
    "resourceAccess": [{"id": "fa91a9e8-6808-4167-a950-8f1fe525b270", "type": "Scope"}]
  },
  {
    "resourceAppId": "797f4846-ba00-4fd7-ba43-dac1f8f63013",
    "resourceAccess": [{"id": "41094075-9dad-400e-a0bd-54e686782033", "type": "Scope"}]
  },
  {
    "resourceAppId": "00000003-0000-0000-c000-000000000000",
    "resourceAccess": [
      {"id": "128ca929-1a19-45e6-a3b8-435ec44a36ba", "type": "Scope"},
      {"id": "b152eca8-ea73-4a48-8c98-1a6742673d99", "type": "Scope"}
    ]
  },
  {
    "resourceAppId": "9b975845-388f-4429-889e-eab1ef63949c",
    "resourceAccess": [{"id": "8f71190c-00c8-461d-a63b-f74abde9ba52", "type": "Role"}]
  }
]'
BLUEPRINT_APP_ENDPOINT="https://graph.microsoft.com/v1.0/applications/${BLUEPRINT_CLIENT_ID}"
az rest --method patch --url "$BLUEPRINT_APP_ENDPOINT" --headers "Content-Type=application/json" --body "{\"requiredResourceAccess\": $TARGET_ACCESS}"
log_success "Required resource access configured on Blueprint."

# Step 6C: Attempt tenant-wide admin consent
ADMIN_CONSENT_SCOPES="16b1878d-62c7-4009-aa25-68989d63bbad/Tools.ListInvoke.All https://management.azure.com/user_impersonation https://graph.microsoft.com/SecurityIncident.ReadWrite.All https://graph.microsoft.com/ThreatHunting.Read.All api://9b975845-388f-4429-889e-eab1ef63949c/Agent365.Observability.OtelWrite"
ADMIN_CONSENT_REDIRECT_URI="https://entra.microsoft.com/TokenAuthorize"
log_info "Attempting admin consent on Blueprint..."
ADMIN_CONSENT_REQUIRED=false
if ADMIN_CONSENT_OUTPUT=$(az ad app permission admin-consent --id "$BLUEPRINT_CLIENT_ID" 2>&1); then
  log_success "Tenant-wide admin consent granted."
elif grep -Eqi "insufficient|privilege|authorization|authorized|forbidden|global administrator" <<< "$ADMIN_CONSENT_OUTPUT"; then
  ADMIN_CONSENT_REQUIRED=true
  ADMIN_CONSENT_STATE=$(python3 -c "import secrets; print(secrets.token_hex(16))")
  ADMIN_CONSENT_URL=$(python3 -c '
import sys
from urllib.parse import quote, urlencode

tenant_id, client_id, scopes, redirect_uri, state = sys.argv[1:]
query = urlencode(
  {
    "client_id": client_id,
    "scope": scopes,
    "redirect_uri": redirect_uri,
    "state": state,
  },
  quote_via=quote,
)
print(f"https://login.microsoftonline.com/{tenant_id}/v2.0/adminconsent?{query}")
' "$TENANT_ID" "$BLUEPRINT_CLIENT_ID" "$ADMIN_CONSENT_SCOPES" "$ADMIN_CONSENT_REDIRECT_URI" "$ADMIN_CONSENT_STATE")
  log_warn "The signed-in account cannot grant tenant-wide admin consent."
  log_warn "Ask a tenant administrator to grant consent out of band using this URL:"
  echo -e "${YELLOW}${BOLD}${ADMIN_CONSENT_URL}${NC}"
else
  log_error "Failed to grant admin consent: $ADMIN_CONSENT_OUTPUT"
  exit 1
fi

# ------------------------------------------------------------------------------
# 7. Completion & Next Steps Summary
# ------------------------------------------------------------------------------
log_step "Deployment Complete!"

echo -e "${GREEN}${BOLD}========================================================================${NC}"
echo -e "${GREEN}${BOLD}                  SOC BUDDY DEPLOYED SUCCESSFULLY                       ${NC}"
echo -e "${GREEN}${BOLD}========================================================================${NC}"
echo -e "Messaging Endpoint:   ${CYAN}${BOLD}https://${APP_FQDN}/api/messages${NC}"
echo -e "OAuth Redirect URI:   ${CYAN}${BOLD}https://${APP_FQDN}/auth/callback${NC}"
echo -e "Azure Bot Client ID:  ${BOLD}${AZURE_BOT_CLIENT_ID}${NC}"
echo -e "UAMI Principal ID:    ${BOLD}${UAMI_PRINCIPAL_ID}${NC}"
echo -e "ACR Name:             ${BOLD}${ACR_NAME}${NC}"
echo -e "Foundry Endpoint:     ${BOLD}${FOUNDRY_PROJECT_ENDPOINT}${NC}"
echo -e "========================================================================"
echo -e "${YELLOW}${BOLD}POST-DEPLOYMENT ACTION REQUIRED:${NC}"
echo -e "1. ${BOLD}Publish / Activate Agent Manifest in Microsoft 365 Admin Center:${NC}"
echo -e "   - Run 'a365 publish' to produce manifest.zip"
echo -e "   - Upload in M365 Admin Center (Settings > Integrated apps / Agents)"
if [ "$ADMIN_CONSENT_REQUIRED" = true ]; then
  echo -e "2. ${BOLD}Admin Consent Required - share this consent URL with your Global Administrator:${NC}"
  echo -e "    - ${YELLOW}${ADMIN_CONSENT_URL}${NC}"
fi
echo -e "========================================================================"
