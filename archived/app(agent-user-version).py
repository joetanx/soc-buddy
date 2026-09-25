# Archived version using agent user and Sentinel MCP.
# Sentinel MCP is deprecated, rework needed if agent user version is to be used.
import sys, logging, asyncio, jwt, time
from os import environ
from datetime import UTC, datetime

from aiohttp.web import Application, Request, Response, json_response, run_app
from aiohttp.web_middlewares import middleware as web_middleware
from azure.identity import ManagedIdentityCredential
from langchain.agents.middleware import AgentState, before_model
from langchain_core.messages import trim_messages
from langchain.chat_models import init_chat_model
from langchain.agents import create_agent
from langchain.tools import BaseTool, tool
from langchain_mcp_adapters.client import MultiServerMCPClient
from langgraph.checkpoint.memory import InMemorySaver
from langchain_azure_ai.tools.builtin import WebSearchTool
from microsoft_agents.activity import load_configuration_from_env
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
from microsoft.opentelemetry.a365.runtime import get_observability_authentication_scope


# Initialize logging
logging.basicConfig(level=logging.INFO, handlers=[logging.StreamHandler(sys.stdout)])
logger = logging.getLogger(__name__)


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


# Initialize agent user and token provider for token acquisition.
agent_user: str | None = None
token_provider = connection_manager.get_default_connection()
token_cache: dict[tuple[str | None, str | None, str | None, tuple[str] | None], str] = {}
REFRESH_BUFFER_SECONDS = int(environ.get("TOKEN_REFRESH_BUFFER_SECONDS", "300"))


def register_agent_user(agentic_user_id: str) -> None:
    # Set global agent user; app is intended to use with only one agentic user.
    # Used in on_message handler with agentic_user_id from context.
    global agent_user
    agent_user = agentic_user_id


async def get_token(
    agent_id: str,
    tenant_id: str,
    scopes: list[str] | None = None,
) -> str:
    # Retrieve a token, handling caching and refreshing transparently.
    if scopes is None:
        # If no scopes are provided, use the observability scope.
        # use_microsoft_opentelemetry sends only tenant_id and agent_id.
        scopes = get_observability_authentication_scope()
    cache_key = (tenant_id, agent_id, agent_user, tuple(scopes))
    cached_token = token_cache.get(cache_key)
    if cached_token:
        # Check if there is a cached token and it's not near expiration
        exp_claim = jwt.decode(cached_token, options={"verify_signature": False}).get("exp")
        if exp_claim - int(time.time()) > REFRESH_BUFFER_SECONDS:
            return cached_token
    # Reach here means no cached token or token near expiration, exchange for new token
    new_token = await token_provider.get_agentic_user_token(
        tenant_id=tenant_id,
        agent_app_instance_id=agent_id,
        agentic_user_id=agent_user,
        scopes=scopes,
    )
    token_cache[cache_key] = new_token
    return new_token


@tool
def current_utc_time() -> str:
    """Return the current UTC date and time."""
    return datetime.now(UTC).isoformat()


async def setup_tools(agent_id: str, tenant_id: str):
    # Staging MCP server tools
    MCP_SERVERS = {
        "sentinel-mcp-data-exploration": (
            "https://sentinel.microsoft.com/mcp/data-exploration",
            ["4500ebfb-89b6-4b14-a480-7f749797bfcd/SentinelPlatform.DelegatedAccess"],
        ),
        "sentinel-mcp-defender-triage": (
            "https://sentinel.microsoft.com/mcp/triage",
            ["7b7b3966-1961-47b5-b080-43ca5482e21c/MCP.Read.All"],
        ),
        "work-iq-mail": (
            "https://agent365.svc.cloud.microsoft/agents/servers/mcp_MailTools",
            ["16b1878d-62c7-4009-aa25-68989d63bbad/Tools.ListInvoke.All"],
        ),
    }
    servers = {}
    for name, (url, scopes) in MCP_SERVERS.items():
        token = await get_token(agent_id, tenant_id, scopes)
        servers[name] = {
            "transport": "streamable_http",
            "url": url,
            "headers": {"Authorization": f"Bearer {token}"},
        }
    client = MultiServerMCPClient(servers)
    return await client.get_tools()


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
            max_tokens=12_000,
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


def setup_agent(tools: list[BaseTool]):
    # Create and configure a LangChain agent with the specified tools.
    agent = create_agent(
        model=init_chat_model(
            f"azure_ai:{environ['FOUNDRY_MODEL']}",
            project_endpoint=environ['FOUNDRY_PROJECT_ENDPOINT'],
            credential=ManagedIdentityCredential(client_id=environ['UAMI_CLIENT_ID']),
        ),
        tools=tools,
        system_prompt=environ.get("AGENT_PROMPT", "You are a helpful assistant."),
        middleware=[trim_conversation_history],
        checkpointer=checkpointer,
    )
    return agent


def main() -> None:
    # Main function to set up the agent application and routes.

    @agent_app.activity("message")
    async def on_message(context: TurnContext, _: TurnState) -> None:
        # Extract tenant, agent, and user information from the incoming activity.
        tenant_id = getattr(context.activity.recipient, "tenant_id", None)
        agent_id = getattr(context.activity.recipient, "agentic_app_id", None)
        agent_user = getattr(context.activity.recipient, "agentic_user_id", None)
        register_agent_user(agent_user)
        # Set up the baggage context for the current request.
        with BaggageBuilder().tenant_id(tenant_id).agent_id(agent_id).agentic_user_id(agent_user).build():
            text = (context.activity.text or "").strip()
            if not text:
                return
            # Set up the agent with the necessary tools.
            agent = setup_agent([current_utc_time, WebSearchTool(), *await setup_tools(agent_id, tenant_id)])
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

    app = Application()
    app.router.add_post("/api/messages", entry_point)
    app.router.add_get("/api/messages", lambda _: Response(status=200))
    app["agent_configuration"] = connection_manager.get_default_connection_configuration()

    use_microsoft_opentelemetry(
        enable_a365=True,
        a365_token_resolver=lambda agent_id, tenant_id: asyncio.run(get_token(agent_id, tenant_id)),
        instrumentation_options={
            "openai": {"enabled": False},
            "openai_agents": {"enabled": False},
            "langchain": {"enabled": True},
            "semantic_kernel": {"enabled": False},
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
