#!/usr/bin/env bash
# ====================================================================================
# SOC Buddy - Azure Infrastructure Deployment Script for Azure Cloud Shell
# ====================================================================================
# Deploys Azure resources using an ARM template, builds the container image in ACR,
# configures Managed Identity, creates the Azure Bot app registration and resource,
# sets up FIC for Agent Blueprint & Azure Bot, and grants delegated permissions for
# Work IQ Mail MCP, Azure, and Microsoft Graph Security Incidents and Threat Hunting.
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

# ------------------------------------------------------------------------------
# 1. Environment & Prerequisite Checks
# ------------------------------------------------------------------------------
log_step "Checking Azure Cloud Shell prerequisites..."

if ! command -v az &> /dev/null; then
    log_error "Azure CLI ('az') is not installed or not in PATH."
    exit 1
fi

if ! command -v python3 &> /dev/null; then
    log_error "python3 is required to parse configuration files."
    exit 1
fi

# Ensure user is logged into Azure CLI
SUB_ID=$(az account show --query id -o tsv 2>/dev/null || true)
if [ -z "$SUB_ID" ]; then
    log_error "Not logged into Azure CLI. Please run 'az login' first."
    exit 1
fi
TENANT_ID=$(az account show --query tenantId -o tsv)
SUB_NAME=$(az account show --query name -o tsv)

log_info "Tenant ID:    ${BOLD}${TENANT_ID}${NC}"
log_info "Subscription: ${BOLD}${SUB_NAME}${NC} (${SUB_ID})"

# Ensure Azure Resource Providers are registered
register_provider_if_needed() {
    local provider=$1
    local state
    state=$(az provider show -n "$provider" --query "registrationState" -o tsv 2>/dev/null || echo "NotRegistered")
    if [ "$state" != "Registered" ]; then
        log_info "Registering resource provider '$provider' (currently: $state)..."
        az provider register -n "$provider" --wait &>/dev/null || az provider register -n "$provider" &>/dev/null
    else
        log_info "Resource provider '$provider' is registered."
    fi
}

log_step "Verifying subscription resource provider registrations..."
register_provider_if_needed "Microsoft.App"
register_provider_if_needed "Microsoft.OperationalInsights"
register_provider_if_needed "Microsoft.ContainerRegistry"
register_provider_if_needed "Microsoft.CognitiveServices"
register_provider_if_needed "Microsoft.BotService"

# Sentinel MCP is deprecated
# Ensure Sentinel Triage MCP Service Principal exists
# log_step "Verifying required Service Principals..."
# TRIAGE_MCP_SP_ID="7b7b3966-1961-47b5-b080-43ca5482e21c"
# if az ad sp show --id "$TRIAGE_MCP_SP_ID" &>/dev/null; then
#     log_info "Service Principal for Sentinel Triage MCP ($TRIAGE_MCP_SP_ID) already exists."
# else
#     log_info "Creating Service Principal for Sentinel Triage MCP ($TRIAGE_MCP_SP_ID)..."
#     if SP_OUTPUT=$(az ad sp create --id "$TRIAGE_MCP_SP_ID" 2>&1); then
#         log_success "Service Principal for Sentinel Triage MCP created successfully."
#     elif echo "$SP_OUTPUT" | grep -qi "already in use"; then
#         log_info "Service Principal for Sentinel Triage MCP already exists."
#     else
#         log_warn "Could not create Service Principal for Sentinel Triage MCP: $SP_OUTPUT"
#     fi
# fi

# ------------------------------------------------------------------------------
# 2. Validate Prerequisites & Environment Variables
# ------------------------------------------------------------------------------
log_step "Validating required files and environment variables..."

CONFIG_FILE="$SCRIPT_DIR/a365.generated.config.json"
TEMPLATE_FILE="$SCRIPT_DIR/azuredeploy.json"

# Check presence of a365.generated.config.json
if [ ! -f "$CONFIG_FILE" ]; then
    log_error "Configuration file not found: $CONFIG_FILE"
    log_error "Please run 'a365 setup all' first or place a365.generated.config.json in the script directory."
    exit 1
fi

# Check presence of azuredeploy.json
if [ ! -f "$TEMPLATE_FILE" ]; then
    log_error "ARM template not found: $TEMPLATE_FILE"
    exit 1
fi

# Check required environment variables
MISSING_VARS=()
if [ -z "${APP_NAME:-}" ]; then
    MISSING_VARS+=("APP_NAME")
fi
if [ -z "${LOCATION:-}" ]; then
    MISSING_VARS+=("LOCATION")
fi

if [ ${#MISSING_VARS[@]} -ne 0 ]; then
    log_error "Missing required environment variable(s): ${MISSING_VARS[*]}"
    log_error "Please export them before running deploy.sh, for example:"
    log_error "  export APP_NAME=\"<your-app-name>\""
    log_error "  export LOCATION=\"<azure-region>\""
    log_error "  export FOUNDRY_MODEL=\"gpt-5.6-luna\"  # optional, defaults to gpt-5.6-luna"
    exit 1
fi

RG="rg-${APP_NAME}"
FOUNDRY_MODEL="${FOUNDRY_MODEL:-gpt-5.6-luna}"

if [[ ! "$APP_NAME" =~ ^[a-z][a-z0-9-]{0,30}[a-z0-9]$ ]] || [[ "$APP_NAME" == *"--"* ]]; then
    log_error "The application name '$APP_NAME' is invalid."
    log_error "Use 2-32 lowercase letters, digits, or single hyphens; start with a letter and end with a letter or digit."
    exit 1
fi

log_info "Application Name:   ${BOLD}${APP_NAME}${NC}"
log_info "Azure Region:       ${BOLD}${LOCATION}${NC}"
log_info "Resource Group:     ${BOLD}${RG}${NC}"
log_info "Foundry Model:      ${BOLD}${FOUNDRY_MODEL}${NC}"

# Parse a365.generated.config.json
log_info "Parsing configuration from: $CONFIG_FILE"

BLUEPRINT_CLIENT_ID=$(python3 -c "
import json
print(json.load(open('$CONFIG_FILE'))['agentBlueprintId'])" 2>/dev/null || true)

AGENTIC_INSTANCE_ID=$(python3 -c "
import json
print(json.load(open('$CONFIG_FILE'))['agenticAppId'])" 2>/dev/null || true)

if [ -z "$BLUEPRINT_CLIENT_ID" ]; then
    log_error "agentBlueprintId not found in $CONFIG_FILE."
    exit 1
fi

if [ -z "$AGENTIC_INSTANCE_ID" ]; then
    log_error "agenticAppId (Agent Identity) not found in $CONFIG_FILE."
    exit 1
fi

log_info "Blueprint Client ID: ${BOLD}${BLUEPRINT_CLIENT_ID}${NC}"
log_info "Agent Instance ID:   ${BOLD}${AGENTIC_INSTANCE_ID}${NC}"
log_info "Tenant ID:           ${BOLD}${TENANT_ID}${NC}"

# Ensure resource group exists
if ! az group show -n "$RG" &>/dev/null; then
    log_info "Creating Resource Group '$RG' in '$LOCATION'..."
    az group create -n "$RG" -l "$LOCATION" --output none
else
    log_info "Using existing Resource Group '$RG'."
fi

# Query model version dynamically for the requested model in the given location
log_info "Resolving model version for '${FOUNDRY_MODEL}' in '${LOCATION}'..."
FOUNDRY_MODEL_VERSION=$(az cognitiveservices model list -l "$LOCATION" \
    --query "[?model.name=='${FOUNDRY_MODEL}' && kind=='AIServices'].model.version | sort(@) | [-1]" \
    -o tsv 2>/dev/null || true)

if [ -z "$FOUNDRY_MODEL_VERSION" ]; then
    log_error "Could not resolve a version for model '${FOUNDRY_MODEL}' in region '${LOCATION}'."
    log_error "Check that '${FOUNDRY_MODEL}' is supported in '${LOCATION}' for AIServices."
    exit 1
fi
log_info "Resolved model version: ${BOLD}${FOUNDRY_MODEL_VERSION}${NC}"

# ------------------------------------------------------------------------------
# 3. Setup Azure Bot identity
# ------------------------------------------------------------------------------
# Create or reuse single-tenant Entra application for Azure Bot.
log_step "Creating Azure Bot identity..."

CHECK_AZURE_BOT_CLIENT_ID=$(az ad app list --query "[?displayName == '${APP_NAME}'].appId" -o tsv)

if [ -n "$CHECK_AZURE_BOT_CLIENT_ID" ]; then
    AZURE_BOT_CLIENT_ID="$CHECK_AZURE_BOT_CLIENT_ID"
    log_info "Reusing existing Azure Bot application."
else
    AZURE_BOT_CLIENT_ID=$(az ad app create \
        --display-name "$APP_NAME" \
        --sign-in-audience "AzureADMyOrg" \
        --query "appId" -o tsv)
    while ! az ad app show --id "$AZURE_BOT_CLIENT_ID" &>/dev/null; do
        log_info "Waiting for Azure Bot application to be available..."
        sleep 1
    done
fi

CHECK_AZURE_BOT_SP_ID=$(az ad sp show --id $AZURE_BOT_CLIENT_ID --query "id" -o tsv 2>/dev/null)

if [ -n "$CHECK_AZURE_BOT_SP_ID" ]; then
    AZURE_BOT_SP_ID="$CHECK_AZURE_BOT_SP_ID"
    log_info "Reusing existing Azure Bot service principal."
else
    AZURE_BOT_SP_ID=$(az ad sp create \
        --id "$AZURE_BOT_CLIENT_ID" \
        --query "id" -o tsv)
fi

log_info "Azure Bot Client ID: ${BOLD}${AZURE_BOT_CLIENT_ID}${NC}"
log_info "Azure Bot SP ID:     ${BOLD}${AZURE_BOT_SP_ID}${NC}"

# ------------------------------------------------------------------------------
# 4. Deploy Infrastructure via ARM Template
# ------------------------------------------------------------------------------

log_step "Deploying Azure Infrastructure via ARM Template..."
log_info "Provisioning Cognitive Services, ACR, Log Analytics, CAE, UAMI, RBAC roles, Container App, Azure Bot, and Teams channel..."

DEPLOYMENT_NAME="deploy-${APP_NAME}-$(date +%s)"

DEPLOYMENT_OUTPUT=$(az deployment group create \
    --name "$DEPLOYMENT_NAME" \
    --resource-group "$RG" \
    --template-file "$TEMPLATE_FILE" \
    --parameters \
        appName="$APP_NAME" \
        location="$LOCATION" \
        blueprintClientId="$BLUEPRINT_CLIENT_ID" \
        agenticInstanceId="$AGENTIC_INSTANCE_ID" \
        tenantId="$TENANT_ID" \
        teamsBotClientId="$AZURE_BOT_CLIENT_ID" \
        foundryModelName="$FOUNDRY_MODEL" \
        foundryModelVersion="$FOUNDRY_MODEL_VERSION" \
    --query "properties.outputs" -o json)

log_success "ARM Template deployment completed."

# Extract deployment outputs
ACR_NAME=$(python3 -c "import json, sys; print(json.load(sys.stdin)['acrName']['value'])" <<< "$DEPLOYMENT_OUTPUT")
UAMI_ID=$(python3 -c "import json, sys; print(json.load(sys.stdin)['uamiPrincipalId']['value'])" <<< "$DEPLOYMENT_OUTPUT")
UAMI_CLIENT_ID=$(python3 -c "import json, sys; print(json.load(sys.stdin)['uamiClientId']['value'])" <<< "$DEPLOYMENT_OUTPUT")
MESSAGING_ENDPOINT=$(python3 -c "import json, sys; print(json.load(sys.stdin)['messagingEndpoint']['value'])" <<< "$DEPLOYMENT_OUTPUT")
OAUTH_REDIRECT_URI=$(python3 -c "import json, sys; print(json.load(sys.stdin)['oauthRedirectUri']['value'])" <<< "$DEPLOYMENT_OUTPUT")
FOUNDRY_PROJECT_ENDPOINT=$(python3 -c "import json, sys; print(json.load(sys.stdin)['foundryEndpoint']['value'])" <<< "$DEPLOYMENT_OUTPUT")

log_info "ACR Name:            ${BOLD}${ACR_NAME}${NC}"
log_info "UAMI Principal ID:   ${BOLD}${UAMI_ID}${NC}"
log_info "UAMI Client ID:      ${BOLD}${UAMI_CLIENT_ID}${NC}"
log_info "Messaging Endpoint:  ${BOLD}${MESSAGING_ENDPOINT}${NC}"
log_info "OAuth Redirect URI:  ${BOLD}${OAUTH_REDIRECT_URI}${NC}"

# ------------------------------------------------------------------------------
# 5. Build Container Image in ACR & Update Container App
# ------------------------------------------------------------------------------
log_step "Building container image in ACR ($ACR_NAME)..."
log_info "Running 'az acr build' from context: $SCRIPT_DIR"
az acr build -r "$ACR_NAME" -t "${APP_NAME}:latest" "$SCRIPT_DIR"

log_info "Updating Container App '$APP_NAME' with built image..."
az containerapp update -n "$APP_NAME" -g "$RG" \
    --image "${ACR_NAME}.azurecr.io/${APP_NAME}:latest" --output none
log_success "Container App updated with '${APP_NAME}:latest'."

# ------------------------------------------------------------------------------
# 6. Setup Federated Identity Credentials (FIC)
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
            \"subject\": \"${UAMI_ID}\",
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
            \"subject\": \"${UAMI_ID}\",
            \"audiences\": [\"api://AzureADTokenExchange\"]
        }" --output none
    log_success "FIC added to Teams Bot App."
else
    log_info "FIC '$FIC_NAME' already configured on Teams Bot App."
fi

# 2. Configure Web Redirect URI
log_info "Configuring Web Redirect URI on Teams Bot application ($AZURE_BOT_CLIENT_ID)..."
mapfile -t CURRENT_REDIRECT_URIS < <(
    az ad app show \
        --id "$AZURE_BOT_CLIENT_ID" \
        --query "web.redirectUris[]" \
        -o tsv
)

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
SCOPE_ID=$(az ad app show \
    --id "$BLUEPRINT_CLIENT_ID" \
    --query "api.oauth2PermissionScopes[?value=='access_agent_as_user'].id | [0]" \
    -o tsv)

if [ -z "$SCOPE_ID" ]; then
    log_error "Scope 'access_agent_as_user' was not found on Blueprint application '$BLUEPRINT_CLIENT_ID'."
    exit 1
fi

BOT_REQUIRED_RESOURCE_ACCESS=$(az ad app show \
    --id "$AZURE_BOT_CLIENT_ID" \
    --query "requiredResourceAccess" \
    -o json)

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
# 7. Configure Inheritable and Required API Permissions & Grant Admin Consent
# ------------------------------------------------------------------------------
log_step "Granting MCP Server and Microsoft Graph Delegated Permissions..."

# Permission Definitions:
# 1. Work IQ Mail MCP:              App 16b1878d-62c7-4009-aa25-68989d63bbad, SPN 93aac09f-5f9b-4b4c-aa45-c623a1b69342, DelegatedRoleId fa91a9e8-6808-4167-a950-8f1fe525b270, Scope Tools.ListInvoke.All
# 2. Azure Tools:                   App 797f4846-ba00-4fd7-ba43-dac1f8f63013, SPN 71e36942-1dcc-468d-bb7f-6ca533a87559, DelegatedRoleId 41094075-9dad-400e-a0bd-54e686782033, Scope user_impersonation
# 3. Microsoft Graph:               App 00000003-0000-0000-c000-000000000000, SPN aaad2076-26ab-4905-b1eb-090f627b17d7, DelegatedRoleId 128ca929-1a19-45e6-a3b8-435ec44a36ba, Scope SecurityIncident.ReadWrite.All
#                                   App 00000003-0000-0000-c000-000000000000, SPN aaad2076-26ab-4905-b1eb-090f627b17d7, DelegatedRoleId b152eca8-ea73-4a48-8c98-1a6742673d99, Scope ThreatHunting.Read.All

# Deprecated Sentinel MCP Permissions:
# 1. Sentinel MCP Data Exploration: App 4500ebfb-89b6-4b14-a480-7f749797bfcd, SPN eaff9684-612c-4add-aa10-035fd3bfe3d1, DelegatedRoleId 991a963a-4203-4dbc-acf2-254a258f76f2, Scope SentinelPlatform.DelegatedAccess
# 2. Sentinel MCP Triage:           App 7b7b3966-1961-47b5-b080-43ca5482e21c, SPN 8dd500d0-c3aa-4380-96d1-09b4b6233eff, DelegatedRoleId 69b8d760-4df6-4017-a3e6-1a8049cbce42, Scope MCP.Read.All

# Step 7A: Allow agent identities created from the Blueprint to inherit delegated permissions
BLUEPRINT_OBJECT_ID=$(az ad app show --id "$BLUEPRINT_CLIENT_ID" --query id -o tsv)
INHERITABLE_PERMISSIONS_ENDPOINT="https://graph.microsoft.com/v1.0/applications/${BLUEPRINT_OBJECT_ID}/microsoft.graph.agentIdentityBlueprint/inheritablePermissions"

ensure_inheritable_permission() {
    local resource_app_id=$1
    local existing_resource_app_id

    existing_resource_app_id=$(az rest \
        --method get \
        --url "$INHERITABLE_PERMISSIONS_ENDPOINT" \
        --query "value[?resourceAppId=='${resource_app_id}'].resourceAppId | [0]" \
        --output tsv)

    if [ "$existing_resource_app_id" = "$resource_app_id" ]; then
        log_info "Resource $resource_app_id is already inheritable from the Blueprint."
        return
    fi

    log_info "Adding resource $resource_app_id as an inheritable Blueprint permission..."
    az rest --method post \
        --url "$INHERITABLE_PERMISSIONS_ENDPOINT" \
        --headers "Content-Type=application/json" \
        --body "{\"resourceAppId\":\"${resource_app_id}\",\"inheritableScopes\":{\"@odata.type\":\"microsoft.graph.allAllowedScopes\"}}" \
        --output none
}

# Work IQ and Microsoft Graph inheritable permissions should already be handled separately by a365 CLI.
ensure_inheritable_permission "16b1878d-62c7-4009-aa25-68989d63bbad"
ensure_inheritable_permission "797f4846-ba00-4fd7-ba43-dac1f8f63013"
ensure_inheritable_permission "00000003-0000-0000-c000-000000000000"

log_success "Inheritable permissions configured on Blueprint."

# Step 8B: Declare delegated permissions on the Blueprint App Registration
ensure_delegated_permission() {
    local resource_app_id=$1
    local scope_id=$2
    local scope_name=$3
    local existing_scope_id

    existing_scope_id=$(az ad app permission list \
        --id "$BLUEPRINT_CLIENT_ID" \
        --query "[?resourceAppId=='${resource_app_id}'].resourceAccess[] | [?id=='${scope_id}'].id | [0]" \
        --output tsv)

    if [ "$existing_scope_id" = "$scope_id" ]; then
        log_info "Delegated permission '$scope_name' is already declared on the Blueprint."
        return
    fi

    log_info "Declaring delegated permission '$scope_name' on the Blueprint..."
    az ad app permission add \
        --id "$BLUEPRINT_CLIENT_ID" \
        --api "$resource_app_id" \
        --api-permissions "${scope_id}=Scope" \
        --output none
}

ensure_delegated_permission \
    "16b1878d-62c7-4009-aa25-68989d63bbad" \
    "fa91a9e8-6808-4167-a950-8f1fe525b270" \
    "Tools.ListInvoke.All"
ensure_delegated_permission \
    "797f4846-ba00-4fd7-ba43-dac1f8f63013" \
    "41094075-9dad-400e-a0bd-54e686782033" \
    "user_impersonation"
ensure_delegated_permission \
    "00000003-0000-0000-c000-000000000000" \
    "128ca929-1a19-45e6-a3b8-435ec44a36ba" \
    "SecurityIncident.ReadWrite.All"
ensure_delegated_permission \
    "00000003-0000-0000-c000-000000000000" \
    "b152eca8-ea73-4a48-8c98-1a6742673d99" \
    "ThreatHunting.Read.All"

log_success "Blueprint delegated permissions declared."

# Step 8C: Attempt tenant-wide admin consent
log_info "Attempting admin consent on Blueprint Application..."
ADMIN_CONSENT_REQUIRED=false
if ADMIN_CONSENT_OUTPUT=$(az ad app permission admin-consent --id "$BLUEPRINT_CLIENT_ID" 2>&1); then
    log_success "Tenant-wide admin consent granted."
elif grep -Eqi "insufficient|privilege|authorization|authorized|forbidden|global administrator" <<< "$ADMIN_CONSENT_OUTPUT"; then
    ADMIN_CONSENT_REQUIRED=true
    ADMIN_CONSENT_URL="https://login.microsoftonline.com/${TENANT_ID}/adminconsent?client_id=${BLUEPRINT_CLIENT_ID}"
    log_warn "The signed-in account cannot grant tenant-wide admin consent."
    log_warn "Ask a tenant administrator to grant consent out of band using this URL:"
    echo -e "${YELLOW}${BOLD}${ADMIN_CONSENT_URL}${NC}"
else
    log_error "Failed to grant admin consent: $ADMIN_CONSENT_OUTPUT"
    exit 1
fi

# ------------------------------------------------------------------------------
# 8. Completion & Next Steps Summary
# ------------------------------------------------------------------------------
log_step "Deployment Complete!"

echo -e "${GREEN}${BOLD}========================================================================${NC}"
echo -e "${GREEN}${BOLD}                  SOC BUDDY DEPLOYED SUCCESSFULLY                       ${NC}"
echo -e "${GREEN}${BOLD}========================================================================${NC}"
echo -e "Application Name:       ${BOLD}${APP_NAME}${NC}"
echo -e "Resource Group:         ${BOLD}${RG}${NC}"
echo -e "Location:               ${BOLD}${LOCATION}${NC}"
echo -e "Messaging Endpoint:     ${CYAN}${BOLD}${MESSAGING_ENDPOINT}${NC}"
echo -e "OAuth Redirect URI:     ${CYAN}${BOLD}${OAUTH_REDIRECT_URI}${NC}"
echo -e "Blueprint Client ID:    ${BOLD}${BLUEPRINT_CLIENT_ID}${NC}"
echo -e "Azure Bot Client ID:    ${BOLD}${AZURE_BOT_CLIENT_ID}${NC}"
echo -e "UAMI Principal ID:      ${BOLD}${UAMI_ID}${NC}"
echo -e "ACR Name:               ${BOLD}${ACR_NAME}${NC}"
echo -e "AI Foundry Endpoint:    ${BOLD}${FOUNDRY_PROJECT_ENDPOINT}${NC}"
echo -e "========================================================================"
echo -e "${GREEN}${BOLD}AUTOMATICALLY CONFIGURED:${NC}"
echo -e "1. Azure Bot resource '${APP_NAME}' created."
echo -e "2. Microsoft Teams channel enabled."
echo -e "3. Messaging endpoint set to: ${CYAN}${MESSAGING_ENDPOINT}${NC}"
echo -e "4. OAuth redirect URI set to: ${CYAN}${OAUTH_REDIRECT_URI}${NC}"
echo -e "5. Blueprint access permission added to Bot App (${AZURE_BOT_CLIENT_ID})."
if [ "$ADMIN_CONSENT_REQUIRED" = true ]; then
    echo -e "6. Blueprint delegated API permissions declared; admin consent is pending."
else
    echo -e "6. Blueprint delegated API permissions declared and admin consent granted."
fi
echo -e "========================================================================"
echo -e "${YELLOW}${BOLD}POST-DEPLOYMENT ACTION REQUIRED:${NC}"
echo -e "1. ${BOLD}Publish / Activate Agent Manifest in Microsoft 365 Admin Center:${NC}"
echo -e "   - Run 'a365 publish' to produce manifest.zip"
echo -e "   - Upload in M365 Admin Center (Settings > Integrated apps / Agents)"
if [ "$ADMIN_CONSENT_REQUIRED" = true ]; then
    echo -e "2. ${BOLD}Ask a tenant administrator to grant API consent:${NC}"
    echo -e "   - ${YELLOW}${ADMIN_CONSENT_URL}${NC}"
fi
echo -e "========================================================================"
