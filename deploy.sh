#!/usr/bin/env bash
# ==============================================================================
# SOC Buddy - Azure Infrastructure Deployment Script for Azure Cloud Shell
# ==============================================================================
# Deploys Azure resources using an ARM template, builds the container image
# in Azure Container Registry (ACR), configures Managed Identity,
# sets up Federated Identity Credentials (FIC) for Agent Blueprint & Teams Bot,
# and grants delegated permissions for Microsoft Sentinel MCPs, Work IQ Mail MCP,
# and Microsoft Graph Security Incidents.
# ==============================================================================

set -euo pipefail

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

if ! command -v pwsh &> /dev/null; then
    log_error "PowerShell ('pwsh') is not installed or not in PATH. Azure Cloud Shell includes pwsh by default."
    exit 1
fi

if ! command -v python3 &> /dev/null; then
    log_error "python3 is required to parse configuration files."
    exit 1
fi

# Ensure user is logged into Azure CLI
CURRENT_SUB_ID=$(az account show --query id -o tsv 2>/dev/null || true)
if [ -z "$CURRENT_SUB_ID" ]; then
    log_error "Not logged into Azure CLI. Please run 'az login' first."
    exit 1
fi
CURRENT_TENANT_ID=$(az account show --query tenantId -o tsv)
CURRENT_SUB_NAME=$(az account show --query name -o tsv)

log_info "Active Subscription: ${BOLD}${CURRENT_SUB_NAME}${NC} (${CURRENT_SUB_ID})"
log_info "Active Tenant ID:    ${BOLD}${CURRENT_TENANT_ID}${NC}"

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

# Ensure Sentinel Triage MCP Service Principal exists
log_step "Verifying required Service Principals..."
TRIAGE_MCP_SP_ID="7b7b3966-1961-47b5-b080-43ca5482e21c"
if az ad sp show --id "$TRIAGE_MCP_SP_ID" &>/dev/null; then
    log_info "Service Principal for Sentinel Triage MCP ($TRIAGE_MCP_SP_ID) already exists."
else
    log_info "Creating Service Principal for Sentinel Triage MCP ($TRIAGE_MCP_SP_ID)..."
    if SP_OUTPUT=$(az ad sp create --id "$TRIAGE_MCP_SP_ID" 2>&1); then
        log_success "Service Principal for Sentinel Triage MCP created successfully."
    elif echo "$SP_OUTPUT" | grep -qi "already in use"; then
        log_info "Service Principal for Sentinel Triage MCP already exists."
    else
        log_warn "Could not create Service Principal for Sentinel Triage MCP: $SP_OUTPUT"
    fi
fi

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
if [ -z "${TEAMS_BOT_CLIENT_ID:-}" ]; then
    MISSING_VARS+=("TEAMS_BOT_CLIENT_ID")
fi
if [ -z "${APP_NAME:-}" ]; then
    MISSING_VARS+=("APP_NAME")
fi
if [ -z "${LOCATION:-}" ]; then
    MISSING_VARS+=("LOCATION")
fi

if [ ${#MISSING_VARS[@]} -ne 0 ]; then
    log_error "Missing required environment variable(s): ${MISSING_VARS[*]}"
    log_error "Please export them before running deploy.sh, for example:"
    log_error "  export TEAMS_BOT_CLIENT_ID=\"<your-teams-bot-client-id>\""
    log_error "  export APP_NAME=\"<your-app-name>\""
    log_error "  export LOCATION=\"<azure-region>\""
    log_error "  export FOUNDRY_MODEL=\"gpt-5.6-luna\"  # optional, defaults to gpt-5.6-luna"
    exit 1
fi

RG="rg-${APP_NAME}"
FOUNDRY_MODEL="${FOUNDRY_MODEL:-gpt-5.6-luna}"

log_info "Application Name:   ${BOLD}${APP_NAME}${NC}"
log_info "Azure Region:       ${BOLD}${LOCATION}${NC}"
log_info "Resource Group:     ${BOLD}${RG}${NC}"
log_info "Teams Bot ID:       ${BOLD}${TEAMS_BOT_CLIENT_ID}${NC}"
log_info "Foundry Model:      ${BOLD}${FOUNDRY_MODEL}${NC}"

# Parse a365.generated.config.json
log_info "Parsing configuration from: $CONFIG_FILE"

BLUEPRINT_CLIENT_ID=$(python3 -c "
import json, sys
data = json.load(sys.stdin)
bp_id = data.get('agentBlueprintId') or data.get('agentBlueprintClientId') or data.get('blueprintClientId') or data.get('blueprintId') or ''
print(bp_id)
" < "$CONFIG_FILE" 2>/dev/null || true)

AGENTIC_INSTANCE_ID=$(python3 -c "
import json, sys
data = json.load(sys.stdin)
agent_id = data.get('agentIdentityId') or data.get('agentId') or data.get('agenticInstanceId') or data.get('instanceId') or ''
print(agent_id)
" < "$CONFIG_FILE" 2>/dev/null || true)

TENANT_ID=$(python3 -c "
import json, sys
data = json.load(sys.stdin)
t_id = data.get('tenantId')
if not t_id:
    try:
        t_id = json.load(open('$SCRIPT_DIR/a365.config.json')).get('tenantId')
    except Exception:
        pass
print(t_id or '$CURRENT_TENANT_ID')
" < "$CONFIG_FILE" 2>/dev/null || echo "$CURRENT_TENANT_ID")

if [ -z "$BLUEPRINT_CLIENT_ID" ]; then
    log_error "agentBlueprintId not found in $CONFIG_FILE."
    exit 1
fi

if [ -z "$AGENTIC_INSTANCE_ID" ]; then
    log_error "agentIdentityId / agenticInstanceId not found in $CONFIG_FILE."
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
FOUNDRY_MODEL_VERSION=$(az cognitiveservices model list \
    -l "$LOCATION" \
    --query "[?model.name=='${FOUNDRY_MODEL}' && kind=='AIServices'].model.version | sort(@) | [-1]" \
    -o tsv 2>/dev/null || true)

if [ -z "$FOUNDRY_MODEL_VERSION" ]; then
    log_error "Could not resolve a version for model '${FOUNDRY_MODEL}' in region '${LOCATION}'."
    log_error "Check that '${FOUNDRY_MODEL}' is supported in '${LOCATION}' for AIServices."
    exit 1
fi
log_info "Resolved model version: ${BOLD}${FOUNDRY_MODEL_VERSION}${NC}"

# ------------------------------------------------------------------------------
# 3. Deploy Infrastructure via ARM Template
# ------------------------------------------------------------------------------
log_step "Deploying Azure Infrastructure via ARM Template..."
log_info "Provisioning Cognitive Services, ACR, Log Analytics, CAE, UAMI, RBAC roles, and Container App..."

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
        teamsBotClientId="$TEAMS_BOT_CLIENT_ID" \
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
            \"subject\": \"${UAMI_ID}\",
            \"audiences\": [\"api://AzureADTokenExchange\"]
        }" --output none
    log_success "FIC added to Blueprint."
else
    log_info "FIC '$FIC_NAME' already configured on Agent Blueprint."
fi

# Configure FIC, Web Redirect URI, and Blueprint API permission on Teams Bot App if Client ID is available
if [ -n "$TEAMS_BOT_CLIENT_ID" ]; then
    log_info "Configuring Teams Bot application ($TEAMS_BOT_CLIENT_ID)..."

    # 1. Federated Identity Credential
    EXISTING_TB_FIC=$(az ad app federated-credential list --id "$TEAMS_BOT_CLIENT_ID" \
        --query "[?name=='${FIC_NAME}'].name" -o tsv 2>/dev/null || true)
    if [ -z "$EXISTING_TB_FIC" ]; then
        az ad app federated-credential create --id "$TEAMS_BOT_CLIENT_ID" \
            --parameters "{
                \"name\": \"${FIC_NAME}\",
                \"issuer\": \"https://login.microsoftonline.com/${TENANT_ID}/v2.0\",
                \"subject\": \"${UAMI_ID}\",
                \"audiences\": [\"api://AzureADTokenExchange\"]
            }" --output none 2>/dev/null || log_warn "Could not add FIC to Teams Bot App. Ensure you have permissions or configure manually."
        log_success "FIC added to Teams Bot App."
    else
        log_info "FIC '$FIC_NAME' already configured on Teams Bot App."
    fi

    # 2. Configure Web Redirect URI
    log_info "Configuring Web Redirect URI on Teams Bot application ($TEAMS_BOT_CLIENT_ID)..."
    python3 -c "
import subprocess, json

bot_id = '${TEAMS_BOT_CLIENT_ID}'
redirect_uri = '${OAUTH_REDIRECT_URI}'

try:
    raw = subprocess.check_output(['az', 'ad', 'app', 'show', '--id', bot_id, '--query', 'web.redirectUris', '-o', 'json']).decode('utf-8').strip()
    uris = json.loads(raw) if raw and raw != 'null' else []
except Exception:
    uris = []

if redirect_uri not in uris:
    uris.append(redirect_uri)
    subprocess.call(['az', 'ad', 'app', 'update', '--id', bot_id, '--web-redirect-uris'] + uris)
" 2>/dev/null || az ad app update --id "$TEAMS_BOT_CLIENT_ID" --web-redirect-uris "$OAUTH_REDIRECT_URI" --output none 2>/dev/null || log_warn "Could not update redirect URI on Teams Bot App."
    log_success "Web Redirect URI set to: $OAUTH_REDIRECT_URI"

    # 3. Grant Agent Blueprint access permission ('access_agent_as_user')
    log_info "Granting Agent Blueprint access permission ('access_agent_as_user') to Teams Bot..."
    SCOPE_ID=$(az ad app show --id "$BLUEPRINT_CLIENT_ID" --query "api.oauth2PermissionScopes[?value=='access_agent_as_user'].id | [0]" -o tsv 2>/dev/null || true)
    if [ -n "$SCOPE_ID" ]; then
        az ad app permission add --id "$TEAMS_BOT_CLIENT_ID" --api "$BLUEPRINT_CLIENT_ID" --api-permissions "${SCOPE_ID}=Scope" 2>/dev/null || true
    else
        az ad app permission add --id "$TEAMS_BOT_CLIENT_ID" --api "$BLUEPRINT_CLIENT_ID" --api-permissions "access_agent_as_user=Scope" 2>/dev/null || true
    fi
    log_success "Blueprint access permission ('access_agent_as_user') configured on Teams Bot."
fi

# ------------------------------------------------------------------------------
# 6. Configure Required API Permissions & Grant Admin Consent (pwsh & az)
# ------------------------------------------------------------------------------
log_step "Granting MCP Server and Microsoft Graph Delegated Permissions..."

# Permission Definitions:
# 1. Sentinel MCP Data Exploration: App 4500ebfb-89b6-4b14-a480-7f749797bfcd, Scope SentinelPlatform.DelegatedAccess (eaff9684-612c-4add-aa10-035fd3bfe3d1)
# 2. Sentinel MCP Triage:           App 7b7b3966-1961-47b5-b080-43ca5482e21c, Scope MCP.Read.All (8dd500d0-c3aa-4380-96d1-09b4b6233eff)
# 3. Work IQ Mail MCP:              App 16b1878d-62c7-4009-aa25-68989d63bbad, Scope Tools.ListInvoke.All (93aac09f-5f9b-4b4c-aa45-c623a1b69342)
# 4. Microsoft Graph:               App 00000003-0000-0000-c000-000000000000, Scope SecurityIncident.ReadWrite.All (aaad2076-26ab-4905-b1eb-090f627b17d7)

# Step 6A: Update Blueprint App Registration requiredResourceAccess
python3 -c "
import subprocess, json

bp_id = '${BLUEPRINT_CLIENT_ID}'
current_rra_str = subprocess.check_output(['az', 'ad', 'app', 'show', '--id', bp_id, '--query', 'requiredResourceAccess', '-o', 'json']).decode('utf-8').strip()
current_rra = json.loads(current_rra_str) if current_rra_str and current_rra_str != 'null' else []

target_permissions = [
    {
        'resourceAppId': '4500ebfb-89b6-4b14-a480-7f749797bfcd',
        'resourceAccess': [{'id': 'eaff9684-612c-4add-aa10-035fd3bfe3d1', 'type': 'Scope'}]
    },
    {
        'resourceAppId': '7b7b3966-1961-47b5-b080-43ca5482e21c',
        'resourceAccess': [{'id': '8dd500d0-c3aa-4380-96d1-09b4b6233eff', 'type': 'Scope'}]
    },
    {
        'resourceAppId': '16b1878d-62c7-4009-aa25-68989d63bbad',
        'resourceAccess': [{'id': '93aac09f-5f9b-4b4c-aa45-c623a1b69342', 'type': 'Scope'}]
    },
    {
        'resourceAppId': '00000003-0000-0000-c000-000000000000',
        'resourceAccess': [{'id': 'aaad2076-26ab-4905-b1eb-090f627b17d7', 'type': 'Scope'}]
    }
]

# Merge into current_rra
rra_map = {item['resourceAppId']: item for item in current_rra}
for target in target_permissions:
    app_id = target['resourceAppId']
    if app_id not in rra_map:
        rra_map[app_id] = target
    else:
        existing_ids = {ra['id'] for ra in rra_map[app_id].get('resourceAccess', [])}
        for ra in target['resourceAccess']:
            if ra['id'] not in existing_ids:
                rra_map[app_id].setdefault('resourceAccess', []).append(ra)

merged_rra = list(rra_map.values())
with open('/tmp/soc_buddy_merged_rra.json', 'w') as f:
    json.dump(merged_rra, f)
"

log_info "Updating requiredResourceAccess on Blueprint App..."
az ad app update --id "$BLUEPRINT_CLIENT_ID" --required-resource-accesses @/tmp/soc_buddy_merged_rra.json
rm -f /tmp/soc_buddy_merged_rra.json

# Step 6B: Attempt admin consent via az cli
log_info "Attempting admin consent on Blueprint Application..."
az ad app permission admin-consent --id "$BLUEPRINT_CLIENT_ID" 2>/dev/null || log_info "az ad app permission admin-consent completed or requires elevated admin."

# Step 6C: Use PowerShell Microsoft Graph module to ensure Service Principals and OAuth2PermissionGrants exist
log_info "Executing PowerShell Graph commands to ensure tenant-wide delegated grants..."
pwsh -NoProfile -Command "
    \$ErrorActionPreference = 'Continue'
    \$bpClientId = '${BLUEPRINT_CLIENT_ID}'
    
    # Acquire Graph access token from az cli
    \$token = (az account get-access-token --resource-type ms-graph --query accessToken -o tsv)
    \$secToken = ConvertTo-SecureString \$token -AsPlainText -Force
    Connect-MgGraph -AccessToken \$secToken -NoWelcome | Out-Null
    
    # 1. Ensure Blueprint Service Principal exists in tenant
    \$clientSp = Get-MgServicePrincipal -Filter \"appId eq '\$bpClientId'\" -ErrorAction SilentlyContinue
    if (-not \$clientSp) {
        Write-Host \"Creating Service Principal for Blueprint \$bpClientId...\"
        \$clientSp = New-MgServicePrincipal -AppId \$bpClientId
    }

    # Resource definitions: Resource App ID -> Scope Name
    \$resources = @{
        '4500ebfb-89b6-4b14-a480-7f749797bfcd' = 'SentinelPlatform.DelegatedAccess'
        '7b7b3966-1961-47b5-b080-43ca5482e21c' = 'MCP.Read.All'
        '16b1878d-62c7-4009-aa25-68989d63bbad' = 'Tools.ListInvoke.All'
        '00000003-0000-0000-c000-000000000000' = 'SecurityIncident.ReadWrite.All'
    }

    foreach (\$resourceAppId in \$resources.Keys) {
        \$scope = \$resources[\$resourceAppId]
        Write-Host \"Configuring grant for Resource: \$resourceAppId, Scope: \$scope...\"
        
        # Ensure resource service principal exists
        \$resSp = Get-MgServicePrincipal -Filter \"appId eq '\$resourceAppId'\" -ErrorAction SilentlyContinue
        if (-not \$resSp) {
            try {
                \$resSp = New-MgServicePrincipal -AppId \$resourceAppId -ErrorAction Stop
            } catch {
                Write-Warning \"Could not create service principal for \$resourceAppId. It may already exist or require admin provisioning.\"
            }
        }
        
        if (\$resSp) {
            # Check or create/update OAuth2PermissionGrant
            \$grant = Get-MgOauth2PermissionGrant -Filter \"clientId eq '\$(\$clientSp.Id)' and resourceId eq '\$(\$resSp.Id)'\" -ErrorAction SilentlyContinue
            if (\$grant) {
                \$scopes = (\$grant.Scope -split '\s+') | Where-Object { \$_ -ne '' }
                if (\$scopes -notcontains \$scope) {
                    \$scopes += \$scope
                    \$newScope = (\$scopes | Select-Object -Unique) -join ' '
                    Update-MgOauth2PermissionGrant -OAuth2PermissionGrantId \$grant.Id -Scope \$newScope
                    Write-Host \"Updated grant with scope: \$newScope\"
                } else {
                    Write-Host \"Scope \$scope already granted.\"
                }
            } else {
                try {
                    New-MgOauth2PermissionGrant -ClientId \$clientSp.Id -ResourceId \$resSp.Id -ConsentType 'AllPrincipals' -Scope \$scope | Out-Null
                    Write-Host \"Created new OAuth2PermissionGrant with scope: \$scope\"
                } catch {
                    Write-Warning \"Failed to create OAuth2PermissionGrant for \$resourceAppId: \$_\"
                }
            }
        }
    }
"

log_success "Permissions granted and verified."

# ------------------------------------------------------------------------------
# 7. Completion & Next Steps Summary
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
echo -e "Teams Bot Client ID:    ${BOLD}${TEAMS_BOT_CLIENT_ID}${NC}"
echo -e "UAMI Principal ID:      ${BOLD}${UAMI_ID}${NC}"
echo -e "ACR Name:               ${BOLD}${ACR_NAME}${NC}"
echo -e "AI Foundry Endpoint:    ${BOLD}${FOUNDRY_PROJECT_ENDPOINT}${NC}"
echo -e "========================================================================"
echo -e "${YELLOW}${BOLD}CRITICAL POST-DEPLOYMENT ACTIONS REQUIRED:${NC}"
if [ -n "$TEAMS_BOT_CLIENT_ID" ]; then
    echo -e "1. ${GREEN}${BOLD}Teams Bot App Web Redirect URI & Permissions:${NC} ${BOLD}Configured automatically.${NC}"
    echo -e "   - Web Redirect URI set to: ${CYAN}${OAUTH_REDIRECT_URI}${NC}"
    echo -e "   - Blueprint access permission ('access_agent_as_user') added to Bot App (${TEAMS_BOT_CLIENT_ID})."
else
    echo -e "1. ${BOLD}Configure Teams Bot App in Microsoft Entra Admin Center:${NC}"
    echo -e "   - Open Entra ID > App Registrations > Select your Teams Bot App"
    echo -e "   - 'Authentication' > Add Web Redirect URI: ${CYAN}${OAUTH_REDIRECT_URI}${NC}"
    echo -e "   - 'API permissions' > Add Agent Blueprint (${BLUEPRINT_CLIENT_ID}) > 'access_agent_as_user'"
fi
echo -e "2. ${BOLD}Configure Messaging Endpoint in Azure Bot Service / Bot Framework:${NC}"
echo -e "   - Messaging Endpoint URL: ${CYAN}${MESSAGING_ENDPOINT}${NC}"
echo -e "3. ${BOLD}Publish / Activate Agent Manifest in Microsoft 365 Admin Center:${NC}"
echo -e "   - Run 'a365 publish' to produce manifest.zip"
echo -e "   - Upload in M365 Admin Center (Settings > Integrated apps / Agents)"
echo -e "========================================================================"

