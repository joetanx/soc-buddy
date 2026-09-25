import sys, logging, asyncio, json, re
from os import environ
from datetime import UTC, datetime, timedelta
from typing import Annotated, Optional, Any
from pydantic import Field
from enum import Enum

import msal
from aiohttp.web import Application, Request, Response, run_app
from azure.identity import ManagedIdentityCredential
from langchain.agents.middleware import AgentState, before_model
from langchain_core.messages import trim_messages
from langchain.chat_models import init_chat_model
from langchain.agents import create_agent
from langchain.tools import BaseTool, tool
from langchain_mcp_adapters.client import MultiServerMCPClient
from langgraph.checkpoint.memory import InMemorySaver
from langchain_azure_ai.tools.builtin import WebSearchTool
from microsoft_agents.activity import Activity, Attachment, load_configuration_from_env
from microsoft_agents.authentication.msal import MsalConnectionManager
from microsoft_agents.hosting.aiohttp import (
    CloudAdapter,
    jwt_authorization_decorator,
    start_agent_process,
)
from microsoft_agents.hosting.core import (
    AgentApplication,
    Authorization,
    MemoryStorage,
    TurnContext,
    TurnState,
)
from microsoft.opentelemetry import use_microsoft_opentelemetry
from microsoft.opentelemetry.a365.core import BaggageBuilder
from microsoft.opentelemetry.a365.hosting.scope_helpers.populate_baggage import populate

# for parsing graph security models
from kiota_serialization_json.json_serialization_writer import JsonSerializationWriter
from kiota_abstractions.serialization import Parsable

# base graph client dependencies
from azure.core.credentials import AccessToken
from msgraph import GraphServiceClient

# comments for incident are actually of AlertComment type
from msgraph.generated.models.security.alert_comment import AlertComment

# to synthesize query parameters for list incidents and list alerts
from kiota_abstractions.base_request_configuration import RequestConfiguration
from msgraph.generated.security.incidents.incidents_request_builder import IncidentsRequestBuilder

# to synthesize request body for run hunting query
from msgraph.generated.security.microsoft_graph_security_run_hunting_query.run_hunting_query_post_request_body import RunHuntingQueryPostRequestBody

# comments for incident are actually of AlertComment type
from msgraph.generated.models.security.alert_comment import AlertComment

# use for updating incident
from msgraph.generated.models.security.incident import Incident
from msgraph.generated.models.security.incident_status import IncidentStatus
from msgraph.generated.models.security.alert_classification import AlertClassification
from msgraph.generated.models.security.alert_determination import AlertDetermination

# Azure SDK imports
from azure.mgmt.loganalytics import LogAnalyticsManagementClient
from azure.mgmt.resourcegraph import ResourceGraphClient
from azure.mgmt.resourcegraph.models import QueryRequest

# Initialize logging
logging.basicConfig(level=logging.INFO, handlers=[logging.StreamHandler(sys.stdout)])

# Initialize Microsoft 365 Agents SDK configurations and agent application.
agents_sdk_config = load_configuration_from_env(environ)
storage = MemoryStorage()
connection_manager = MsalConnectionManager(**agents_sdk_config)
adapter = CloudAdapter(connection_manager=connection_manager)
authorization = Authorization(storage, connection_manager)
agent_app = AgentApplication[TurnState](
    storage=storage,
    adapter=adapter,
    authorization=authorization,
)

tenant_id = agents_sdk_config['CONNECTIONS']['SERVICE_CONNECTION']['SETTINGS']['TENANTID']

# Initialize global MSAL token cache.
msal_token_cache = msal.SerializableTokenCache()

def parse_msal_response(msal_response: dict[str, Any]) -> str:
    access_token = msal_response.get("access_token")
    if access_token:
        return access_token
    raise RuntimeError(f"MSAL token acquisition failed: {msal_response}")


# Token acquisition methods for agent ID.
agent_id = environ['AGENTIC_INSTANCE_ID']
agent_id_token_provider = connection_manager.get_connection("AGENTIC")
REFRESH_BUFFER_SECONDS = int(environ.get("TOKEN_REFRESH_BUFFER_SECONDS", "300"))

async def get_agent_id_msal_app() -> msal.ConfidentialClientApplication:
    # Create agent ID MSAL client app with agent blueprint assertion.
    agentbp_token = await agent_id_token_provider.get_agentic_application_token(
        tenant_id=tenant_id,
        agent_app_instance_id=agent_id,
    )
    return msal.ConfidentialClientApplication(
        client_id=agent_id,
        client_credential={'client_assertion': lambda: agentbp_token},
        authority=f"https://login.microsoftonline.com/{tenant_id}",
        token_cache=msal_token_cache,
    )

async def get_observability_token() -> str:
    # Get agent ID s2s observability token.
    return parse_msal_response(
        (await get_agent_id_msal_app()).acquire_token_for_client(
            scopes=["api://9b975845-388f-4429-889e-eab1ef63949c/.default"]
        )
    )


# Token acquisition methods for Teams bot.
teams_bot_id = agents_sdk_config['CONNECTIONS']['SERVICE_CONNECTION']['SETTINGS']['CLIENTID']
def get_teams_bot_msal_app() -> msal.ConfidentialClientApplication:
    # Create Teams bot MSAL client app with UAMI assertion.
    uami_token = ManagedIdentityCredential(client_id=environ["UAMI_CLIENT_ID"]).get_token(
        "api://AzureADTokenExchange/.default"
    ).token
    return msal.ConfidentialClientApplication(
        client_id=teams_bot_id,
        client_credential={'client_assertion': lambda: uami_token},
        authority=f"https://login.microsoftonline.com/{tenant_id}",
        token_cache=msal_token_cache,
    )


# Human authorization code flow handlers.
auth_requests: dict[str, tuple[Any, Activity]] = {}
agentbp_scope = f"api://{agents_sdk_config['CONNECTIONS']['AGENTIC']['SETTINGS']['CLIENTID']}/access_agent_as_user"

class AuthenticationRequired(Exception):
    pass

async def trigger_auth_code_flow(continuation_activity: Activity,) -> str:
    # Trigger Teams bot authorization code flow for human user authentication.
    flow = get_teams_bot_msal_app().initiate_auth_code_flow(
        scopes=[agentbp_scope],
        redirect_uri=environ["OAUTH_REDIRECT_URI"],
        response_mode="form_post",
    )
    auth_requests[flow["state"]] = (flow, continuation_activity)
    return flow["auth_uri"]

async def redeem_auth_code(
    state: str | None,
    auth_response: dict[str, str],
) -> Activity:
    # Check if authorization request exists for given state.
    auth_request = auth_requests.get(state)
    if auth_request is None:
        raise AuthenticationRequired("Authorization flow not found or expired.")
    flow, continuation_activity = auth_request
    # Redeem authorization code for access and refresh tokens, native msal client handles caching them in msal_token_cache.
    parse_msal_response(get_teams_bot_msal_app().acquire_token_by_auth_code_flow(flow, auth_response))
    # Clear authorization request from cache after redemption.
    auth_requests.pop(state, None)
    # Return continuation activity to proceed with bot conversation.
    return continuation_activity

async def get_obo_token(user_id: str, scopes: list[str]) -> str:
    account = next(
        # Find account matching given user_id using generator expression.
        (
            item
            for item in get_teams_bot_msal_app().get_accounts()
            if item.get("local_account_id") == user_id
        ),
        None,
    )
    if not account:
        raise AuthenticationRequired("User account not found for silent token acquisition.")
    user_assertion = parse_msal_response(
        get_teams_bot_msal_app().acquire_token_silent_with_error(
            # Get access token in cache or use refresh token in cache to get access token.
            [agentbp_scope],
            account=account
        )
    )
    return parse_msal_response(
        (await get_agent_id_msal_app()).acquire_token_on_behalf_of(
            # Get OBO token with user assertion.
            user_assertion=user_assertion,
            scopes=scopes
        )
    )


def authentication_card(auth_url: str) -> Activity:
    # Teams authentication card for user sign-in.
    return Activity(
        type="message",
        attachments=[
            Attachment(
                contentType="application/vnd.microsoft.card.adaptive",
                content={
                    "$schema": "http://adaptivecards.io/schemas/adaptive-card.json",
                    "type": "AdaptiveCard",
                    "version": "1.5",
                    "body": [
                        {
                            "type": "TextBlock",
                            "text": "Authentication required",
                            "weight": "Bolder",
                            "size": "Medium",
                        },
                        {
                            "type": "TextBlock",
                            "text": "Sign in to allow the agent to access the requested services on your behalf.",
                            "wrap": True,
                        },
                    ],
                    "actions": [
                        {
                            "type": "Action.OpenUrl",
                            "title": "Sign in",
                            "url": auth_url,
                        }
                    ],
                },
            )
        ],
    )


# Instantiate the in-memory checkpointer for persisting conversation history.
checkpointer = InMemorySaver()

@before_model
def trim_conversation_history(state: AgentState, runtime) -> dict:
    # Simple history trimming strategy to keep the conversation within token limits.
    return {
        "messages": trim_messages(
            state["messages"],
            strategy="last",
            token_counter="approximate",
            max_tokens=128_000,
            start_on="human",
            include_system=True,
        )
    }

def get_thread_id(context: TurnContext) -> str:
    # Return a stable checkpoint namespace for the current conversation.
    activity = context.activity
    conversation = getattr(activity, "conversation", None)
    conversation_id = getattr(conversation, "id", None) or getattr(activity, "conversation_id", None)
    if conversation_id:
        return str(conversation_id)

    sender = getattr(activity, "from_property", None)
    sender_id = getattr(sender, "id", None)
    return str(sender_id or getattr(activity, "id", "default"))


# Token wrapper for synchronous Azure management SDK clients.
class AzureAccessTokenProvider:
    def __init__(self, token: str):
        self.token = token

    def get_token(self, *scopes, **kwargs) -> AccessToken:
        return AccessToken(self.token, expires_on=int( (datetime.now().astimezone() + timedelta(hours=1)).timestamp()))


# Construct tools that wrap Azure Resource Manager API calls.
async def get_azure_tools(user_id: str) -> list[BaseTool]:
    azure_token = await get_obo_token(user_id, ["https://management.azure.com/.default"])

    @tool
    async def list_workspaces() -> str:
        """List Microsoft Sentinel-enabled Log Analytics workspaces accessible to the current user."""
        query = """
        resources
        | where type =~ "microsoft.operationsmanagement/solutions" and name contains "SecurityInsights"
        | project workspaceName = extract(@"^SecurityInsights\\((.+)\\)$", 1, name)
        | join kind=inner (
            resources
            | where type =~ "microsoft.operationalinsights/workspaces"
        ) on $left.workspaceName == $right.name
        | project subscriptionId, resourceGroup, name, workspaceId = properties.customerId
        """.strip()
        resource_graph_client = ResourceGraphClient(
            credential=AzureAccessTokenProvider(azure_token)
        )
        response = resource_graph_client.resources(QueryRequest(query=query))
        return json.dumps(response.data, default=str)

    @tool
    async def list_tables_in_workspace(
        subscription_id: Annotated[str, Field(description="Azure subscription ID returned by list_workspaces")],
        resource_group_name: Annotated[str, Field(description="Resource group containing the workspace")],
        workspace_name: Annotated[str, Field(description="Log Analytics workspace name")],
    ) -> str:
        """List the names of all tables in a Log Analytics workspace."""
        log_analytics_client = LogAnalyticsManagementClient(
            credential=AzureAccessTokenProvider(azure_token),
            subscription_id=subscription_id,
        )
        tables = log_analytics_client.tables.list_by_workspace(
            resource_group_name=resource_group_name,
            workspace_name=workspace_name,
        )
        return json.dumps([table.name for table in tables])

    return [
        list_workspaces,
        list_tables_in_workspace,
    ]


# Token wrapper for Microsoft Graph SDK.
class GraphAccessTokenProvider:
    def __init__(self, token: str):
        self.token = token

    # The SDK calls get_token to retrieve the active Bearer token
    def get_token(self, *scopes, **kwargs) -> AccessToken:
        # Provide token string and an arbitrary future expiration timestamp (in seconds)
        return AccessToken(self.token, expires_on=int((datetime.now().astimezone() + timedelta(hours=1)).timestamp()))

# Helper functions for JSON serialization and KQL query construction.
def _response_json(value: Parsable | list[Parsable]) -> str:
    writer = JsonSerializationWriter()
    writer.write_any_value(None, value)
    return writer.get_serialized_content().decode("utf-8")

def _parse_enum(enum_type: type[Enum], value: str) -> Enum:
    normalized = value.strip().lower()
    for member in enum_type:
        if member.name.lower() == normalized or str(member.value).lower() == normalized:
            return member
    choices = ", ".join(str(member.value) for member in enum_type)
    raise ValueError(f"Invalid {enum_type.__name__} '{value}'. Expected one of: {choices}")

def _kql_values(values: list[str], entity_type: str) -> list[str]:
    normalized_values = list(dict.fromkeys(value.strip() for value in values if value.strip()))
    if not normalized_values:
        raise ValueError(f"Provide at least one {entity_type}.")
    return normalized_values

def _kql_string_list(values: list[str], entity_type: str) -> str:
    return ", ".join(json.dumps(value) for value in _kql_values(values, entity_type))

def _kql_search_regex(values: list[str], entity_type: str) -> str:
    escaped_values = "|".join(re.escape(value) for value in _kql_values(values, entity_type))
    return json.dumps(f"(?i)(?:{escaped_values})")

# Construct tools that wrap Microsoft Graph API calls for use with LangChain.
async def get_graph_tools(user_id: str) -> list[BaseTool]:
    
    graph_token = await get_obo_token(user_id, ["https://graph.microsoft.com/.default"])
    graph_client = GraphServiceClient(
        GraphAccessTokenProvider(graph_token)
    )

    @tool
    async def get_incident_with_alerts(
        incident_id: Annotated[str, Field(description="Incident ID")]
    ) -> str:
        """Get one Microsoft security incident and its associated alerts."""
        attempts = int(environ.get("INCIDENT_FETCH_ATTEMPTS", "5"))
        delay = int(environ.get("INCIDENT_FETCH_DELAY_SECONDS", "15"))
        query_params = IncidentsRequestBuilder.IncidentsRequestBuilderGetQueryParameters(
            filter = f"id eq '{incident_id}'",
            expand = ["alerts"],
        )
        request_configuration = RequestConfiguration(
            query_parameters = query_params,
        )
        for attempt in range(1, attempts + 1):
            # List incident with filter for incident ID and expand alerts
            # A single-item list of `msgraph.generated.models.security.incident.Incident` is returned when filtering for an incident ID
            incident = await graph_client.security.incidents.get(request_configuration = request_configuration)
            # If the incident is not found, wait and retry, up to the maximum number of attempts
            if not incident.value:
                if attempt == attempts:
                    raise LookupError(
                        f"Incident {incident_id} was not found after {attempts} attempts"
                    )
                wait_seconds = min(delay * (2 ** (attempt - 1)), 60)
                await asyncio.sleep(wait_seconds)
                continue
            return _response_json(incident.value[0])

    async def _run_hunting_query(
        query: str,
        timespan: Optional[str] = None,
        workspace_id: Optional[str] = None,
    ) -> str:
        request_body = RunHuntingQueryPostRequestBody(query=query)
        if timespan is not None:
            request_body.additional_data["timespan"] = timespan
        if workspace_id is not None:
            request_body.additional_data["workspaceId"] = workspace_id
        response = await graph_client.security.microsoft_graph_security_run_hunting_query.post(request_body)
        return _response_json(response.results)

    @tool
    async def get_table_schema(
        table_name: Annotated[str, Field(description="Log Analytics table name")],
        workspace_id: Annotated[Optional[str], Field(description="Log Analytics workspace GUID, defaults to primary workspace.")] = None,
    ) -> str:
        """Get a Log Analytics table schema by running the KQL getschema operator."""
        return await _run_hunting_query(query=f"{table_name} | getschema", timespan=None, workspace_id=workspace_id)

    @tool
    async def run_hunting_query(
        query: Annotated[str, Field(description="Custom KQL threat-hunting query. Use the dedicated blast-radius tools instead when searching incident user, host, or IP address entities.")],
        timespan: Annotated[Optional[str], Field(description="ISO 8601 duration in format `P[n]Y[n]M[n]DT[n]H[n]M[n]S`, defaults to `P7D`.")] = "P7D",
        workspace_id: Annotated[Optional[str], Field(description="Log Analytics workspace GUID, defaults to primary workspace.")] = None,
    ) -> str:
        """Run custom KQL not covered by a dedicated search tool."""
        return await _run_hunting_query(query=query, timespan=timespan, workspace_id=workspace_id)

    @tool
    async def search_threat_intelligence(
        indicators: Annotated[list[str], Field(description="List of indicator observables (IP addresses, domain names, URLs, hashes) to check against Microsoft Threat Intelligence.")],
        timespan: Annotated[Optional[str], Field(description="ISO 8601 duration in format `P[n]Y[n]M[n]DT[n]H[n]M[n]S`, defaults to `P7D`.")] = "P7D",
        workspace_id: Annotated[Optional[str], Field(description="Log Analytics workspace GUID, defaults to primary workspace.")] = None,
    ) -> str:
        """Search ThreatIntelIndicators table for indicators matches."""
        query = (
            "ThreatIntelIndicators\n"
            f"| where ObservableValue in~ ({_kql_string_list(indicators, 'indicator')})\n"
            "| project Modified, SourceSystem, ObservableKey, ObservableValue, IsActive, Confidence\n"
            "| summarize arg_max(Modified, *) by ObservableValue"
        )
        return await _run_hunting_query(query=query, timespan=timespan, workspace_id=workspace_id)

    @tool
    async def search_user_blast_radius(
        users: Annotated[list[str], Field(description="User names, account names, or identities observed in an incident")],
        timespan: Annotated[Optional[str], Field(description="ISO 8601 duration in format `P[n]Y[n]M[n]DT[n]H[n]M[n]S`, defaults to `P3D`.")] = "P3D",
        workspace_id: Annotated[Optional[str], Field(description="Log Analytics workspace GUID, defaults to primary workspace.")] = None,
    ) -> str:
        """Search SigninLogs, SecurityEvents and Syslog tables for occurrences of user entities in Entra, Windows and Linux events."""
        search_users = _kql_search_regex(users, "user")
        query = (
            "union withsource=SourceTable\n"
            "    (SigninLogs\n"
            f"    | where Identity matches regex {search_users}),\n"
            "    (SecurityEvent\n"
            f"    | where Account matches regex {search_users}\n"
            "    | project-rename IPAddress = IpAddress),\n"
            "    (Syslog\n"
            f"    | where SyslogMessage matches regex {search_users})\n"
            "| order by TimeGenerated desc"
        )
        return await _run_hunting_query(query=query, timespan=timespan, workspace_id=workspace_id)

    @tool
    async def search_host_blast_radius(
        hosts: Annotated[list[str], Field(description="Host or computer names observed in an incident")],
        timespan: Annotated[Optional[str], Field(description="ISO 8601 duration in format `P[n]Y[n]M[n]DT[n]H[n]M[n]S`, defaults to `P3D`.")] = "P3D",
        workspace_id: Annotated[Optional[str], Field(description="Log Analytics workspace GUID, defaults to primary workspace.")] = None,
    ) -> str:
        """Search SecurityEvents and Syslog tables for occurrences of host entities in Windows and Linux events."""
        search_hosts = _kql_search_regex(hosts, "host")
        query = (
            "union withsource=SourceTable\n"
            "    (SecurityEvent\n"
            f"    | where Computer matches regex {search_hosts}\n"
            "    | project-rename IPAddress = IpAddress),\n"
            "    (Syslog\n"
            f"    | where HostName matches regex {search_hosts})\n"
            "| order by TimeGenerated desc"
        )
        return await _run_hunting_query(query=query, timespan=timespan, workspace_id=workspace_id)

    @tool
    async def search_ip_blast_radius(
        ip_addresses: Annotated[list[str], Field(description="IP addresses observed in an incident")],
        timespan: Annotated[Optional[str], Field(description="ISO 8601 duration in format `P[n]Y[n]M[n]DT[n]H[n]M[n]S`, defaults to `P3D`.")] = "P3D",
        workspace_id: Annotated[Optional[str], Field(description="Log Analytics workspace GUID, defaults to primary workspace.")] = None,
    ) -> str:
        """Search SigninLogs, SecurityEvents and Syslog tables for occurrences of IP address entities in Entra, Windows and Linux events."""
        search_ip_list = _kql_string_list(ip_addresses, "IP address")
        search_ip_regex = _kql_search_regex(ip_addresses, "IP address")
        query = (
            "union withsource=SourceTable\n"
            "    (SigninLogs\n"
            f"    | where IPAddress in~ ({search_ip_list})),\n"
            "    (SecurityEvent\n"
            f"    | where IpAddress in~ ({search_ip_list})\n"
            "    | project-rename IPAddress = IpAddress),\n"
            "    (Syslog\n"
            f"    | where SyslogMessage matches regex {search_ip_regex})\n"
            "| order by TimeGenerated desc"
        )
        return await _run_hunting_query(query=query, timespan=timespan, workspace_id=workspace_id)

    @tool
    async def add_incident_comment(
        incident_id: Annotated[str, Field(description="Incident ID")],
        comment: Annotated[str, Field(description="Comment to be added")]
    ) -> str:
        """Add a comment to a Microsoft security incident."""
        request_body = AlertComment(odata_type=None, comment=comment)
        url = f"https://graph.microsoft.com/v1.0/security/incidents/{incident_id}/comments"
        await graph_client.security.incidents.with_url(url).post(request_body)
        return f"Comment added to incident {incident_id}."

    @tool
    async def update_incident(
        incident_id: Annotated[str, Field(description="Incident ID")],
        status: Annotated[Optional[str], Field(description="Incident status; options: active, inProgress, resolved, redirected")] = None,
        assigned_to: Annotated[Optional[str], Field(description="User/group to be assigned to")] = None,
        classification: Annotated[Optional[str], Field(description="Classification of the incident; options: falsePositive, truePositive, informationalExpectedActivity")] = None,
        determination: Annotated[Optional[str], Field(description="Details to incident classification; options: unknown, apt, malware, securityPersonnel, securityTesting, unwantedSoftware, other, multiStagedAttack, compromisedAccount, phishing, maliciousUserActivity, notMalicious, notEnoughDataToValidate, confirmedUserActivity, lineOfBusinessApplication")] = None,
        custom_tags: Annotated[Optional[list[str]], Field(description="Custom tags for the incident")] = None,
        resolving_comment: Annotated[Optional[str], Field(description="Comment to explain the resolution of the incident and the classification choice")] = None,
    ) -> str:
        """Update fields on a Microsoft security incident, omitted fields remain unchanged."""
        updates: dict[str, Any] = {}
        if status is not None:
            updates["status"] = _parse_enum(IncidentStatus, status)
        if assigned_to is not None:
            updates["assigned_to"] = assigned_to
        if classification is not None:
            updates["classification"] = _parse_enum(AlertClassification, classification)
        if determination is not None:
            updates["determination"] = _parse_enum(AlertDetermination, determination)
        if custom_tags is not None:
            updates["custom_tags"] = custom_tags
        if resolving_comment is not None:
            updates["resolving_comment"] = resolving_comment
        if not updates:
            raise ValueError("Provide at least one incident field to update.")

        response = await graph_client.security.incidents.by_incident_id(incident_id).patch(Incident(**updates))
        return _response_json(response) if response else f"Incident {incident_id} updated."

    return [
        get_incident_with_alerts,
        get_table_schema,
        run_hunting_query,
        search_threat_intelligence,
        search_user_blast_radius,
        search_host_blast_radius,
        search_ip_blast_radius,
        add_incident_comment,
        update_incident,
    ]

# MCP server tools

MCP_SERVERS = {
    # Sentinel MCP servers are deprecated.
    # "sentinel-mcp-data-exploration": (
    #     "https://sentinel.microsoft.com/mcp/data-exploration",
    #     ["4500ebfb-89b6-4b14-a480-7f749797bfcd/SentinelPlatform.DelegatedAccess"],
    # ),
    # "sentinel-mcp-defender-triage": (
    #     "https://sentinel.microsoft.com/mcp/triage",
    #     ["7b7b3966-1961-47b5-b080-43ca5482e21c/MCP.Read.All"],
    # ),
    "work-iq-mail": (
        "https://agent365.svc.cloud.microsoft/agents/servers/mcp_MailTools",
        ["16b1878d-62c7-4009-aa25-68989d63bbad/Tools.ListInvoke.All"],
    ),
}

async def get_mcp_tools(user_id: str) -> list[BaseTool]:
    # Iterate over the configured MCP servers and acquire OBO tokens for each.
    servers = {}
    for name, (url, scopes) in MCP_SERVERS.items():
        token = await get_obo_token(user_id, scopes)
        # If OBO token acquisition fails, respective exceptions will be raised (handles failures and fresh conversations).
        servers[name] = {
            "transport": "streamable_http",
            "url": url,
            "headers": {"Authorization": f"Bearer {token}"},
        }
    client = MultiServerMCPClient(servers)
    return await client.get_tools()

# Agent setup.
@tool
def current_utc_time() -> str:
    """Return the current UTC date and time."""
    return datetime.now(UTC).isoformat()

def setup_agent(tools: list[BaseTool]):
    # Create and configure a LangChain agent with the specified tools.
    agent = create_agent(
        model=init_chat_model(
            f"azure_ai:{environ['FOUNDRY_MODEL']}",
            project_endpoint=environ['FOUNDRY_PROJECT_ENDPOINT'],
            credential=ManagedIdentityCredential(client_id=environ['UAMI_CLIENT_ID']),
        ),
        tools=tools,
        system_prompt=environ.get("AGENT_PROMPT", "You are a security operations analyst."),
        middleware=[trim_conversation_history],
        checkpointer=checkpointer,
    )
    return agent


def main() -> None:
    # Main function to set up the agent application and routes.

    @agent_app.activity("message")
    async def on_message(context: TurnContext, _: TurnState) -> None:
        # Set BaggageBuilder with some manual attribute mappings because the specific attributes that `populate` uses from TurnContext does not map correctly.
        user_id = getattr(context.activity.from_property, "aad_object_id", None)
        builder = (
            BaggageBuilder()
            .tenant_id(tenant_id)
            .agent_blueprint_id(agents_sdk_config["CONNECTIONS"]["AGENTIC"]["SETTINGS"]["CLIENTID"])
            .agent_id(agent_id)
            .agentic_user_id(user_id)
        )
        populate(builder, context)
        with builder.build():
            text = (context.activity.text or "").strip()
            if not text:
                return
            # Set up the agent with the necessary tools.
            if not user_id:
                await context.send_activity(
                    "Your Teams identity could not be determined for authentication."
                )
                return
            try:
                mcp_tools = await get_mcp_tools(user_id)
                azure_tools = await get_azure_tools(user_id)
                graph_tools = await get_graph_tools(user_id)
            except AuthenticationRequired:
                # Send authentication card to trigger auth code flow if user_id not in accounts.
                auth_url = await trigger_auth_code_flow(
                    context.activity.get_conversation_reference().get_continuation_activity()
                )
                await context.send_activity(authentication_card(auth_url))
                return
            agent = setup_agent([current_utc_time, WebSearchTool(), *mcp_tools, *azure_tools, *graph_tools])
            # Invoke the agent with the user's message and the current thread ID.
            result = await agent.ainvoke(
                {"messages": [{"role": "user", "content": text}]},
                config={"configurable": {"thread_id": get_thread_id(context)}},
            )
            # Send the agent's response back to the user.
            await context.send_activity(result["messages"][-1].text)

    @jwt_authorization_decorator
    async def entry_point(request: Request) -> Response:
        # Message entry point, jwt_authorization_decorator adds incoming JWT validation.
        return await start_agent_process(request, agent_app, adapter)

    async def auth_callback(request: Request) -> Response:
        auth_response = dict(
            # Retrieve authentication response redirected from Entra.
            await request.post() if request.method == "POST" else request.query
        )
        # Redeem the authorization code for access and refresh tokens.
        continuation_activity = await redeem_auth_code(
            state=auth_response.get("state"),
            auth_response=auth_response,
        )
        async def notify_success(context: TurnContext) -> None:
            await context.send_activity(
                "Authentication is complete. Retry your previous message."
            )
        await adapter.continue_conversation(
            agent_id,
            continuation_activity,
            notify_success,
        )
        body = f"<h1>Authentication complete</h1><p>Signed in as {continuation_activity.from_property.name}. Return to Teams and retry your message.</p>"
        return Response(text=body, content_type="text/html")

    app = Application()
    app.router.add_post("/api/messages", entry_point)
    app.router.add_get("/api/messages", lambda _: Response(status=200))
    app.router.add_get("/auth/callback", auth_callback)
    app.router.add_post("/auth/callback", auth_callback)
    app["agent_configuration"] = connection_manager.get_default_connection_configuration()

    use_microsoft_opentelemetry(
        enable_a365=True,
        a365_token_resolver=lambda agent_id, tenant_id: asyncio.run(get_observability_token()),
        a365_use_s2s_endpoint=True,
        a365_enable_observability_exporter=True,
        instrumentation_options={
            # Disable OpenAI and MAF instrumentations because they are enabled by default and causes module not found errors since they are not installed.
            "openai_agents": {"enabled": False},
            "agent_framework": {"enabled": False},
        },
    )

    run_app(
        app,
        host=environ.get("HOST", "0.0.0.0"),
        port=int(environ.get("PORT", "3978"))
    )


if __name__ == "__main__":
    main()
