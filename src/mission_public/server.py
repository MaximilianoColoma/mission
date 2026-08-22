"""FastMCP exposure for the exact frozen Mission public tool set."""

from __future__ import annotations

from contextvars import ContextVar
from inspect import signature
import json
from pathlib import Path
from typing import Any

from fastmcp import Context, FastMCP
from fastmcp.server.middleware import Middleware, MiddlewareContext
from fastmcp.tools import Tool
from pydantic import PrivateAttr

from .auth import (MissionInMemoryTransport, bind_transport_credential,
                   register_transport_target, resolve_request_credential)
from .service import MissionService

_TOOLS = (
    "auftrag_create", "auftrag_list", "auftrag_get", "auftrag_assign",
    "auftrag_reassign_replace", "auftrag_start", "auftrag_checkpoint",
    "auftrag_block", "auftrag_resume", "auftrag_close", "auftrag_cancel",
    "auftrag_get_changelog", "get_instance_activity",
)
_RAW_TOOL_ARGS: ContextVar[dict[str, Any] | None] = ContextVar(
    "mission_raw_tool_args", default=None
)
_REQUEST_SCHEMAS = json.loads(
    Path(__file__).with_name("request-schemas.json").read_text(encoding="utf-8")
)


class _DispatchTool(Tool):
    _service: MissionService = PrivateAttr()

    def __init__(self, name: str, service: MissionService):
        super().__init__(
            name=name,
            description="Mission public-core operation.",
            parameters=_REQUEST_SCHEMAS[name],
        )
        self._service = service

    async def run(self, arguments: dict[str, Any]):
        return self.convert_result(self._service.invoke(self.name, arguments))


def create_server(*, db_path: str | Path, credential_provider: Any,
                  principal_directory: Any, identity_context=None,
                  adapters_enabled: bool = False,
                  fault_injector: Any = None) -> FastMCP:
    """Create an adapter-free in-process Mission MCP server."""
    if adapters_enabled:
        raise ValueError("Public-core adapters are not supported")
    service = MissionService(db_path, credential_provider, principal_directory, identity_context, fault_injector)
    mcp = FastMCP("Mission")
    register_transport_target(mcp)

    class RequestAuthenticationMiddleware(Middleware):
        """Resolve authority while the raw MCP request is still available."""

        async def on_call_tool(self, context: MiddlewareContext, call_next: Any) -> Any:
            message = context.message
            fastmcp_context = context.fastmcp_context
            request_context = (
                fastmcp_context.request_context if fastmcp_context is not None else None
            )
            meta = getattr(request_context, "meta", None)
            credential = resolve_request_credential(
                mcp,
                meta,
                getattr(message, "name", None),
                getattr(message, "arguments", None) or {},
            )
            raw_token = _RAW_TOOL_ARGS.set(dict(getattr(message, "arguments", None) or {}))
            try:
                with bind_transport_credential(credential):
                    return await call_next(context)
            finally:
                _RAW_TOOL_ARGS.reset(raw_token)

    mcp.add_middleware(RequestAuthenticationMiddleware())

    # Forward declared wire parameters only.  ``locals()`` of a closure also
    # exposes free variables, so an allowlist - not a denylist - is what keeps
    # non-wire names out of the service call.
    declared = {
        tool: (set(signature(getattr(service, tool)).parameters) - {"principal", "correlation_id"}) | {"identity_envelope"}
        for tool in _TOOLS
    }

    def dispatch(tool: str, args: dict[str, Any], ctx: Context) -> dict:
        source = _RAW_TOOL_ARGS.get() or args
        clean = {key: value for key, value in source.items() if key in declared[tool]}
        return service.invoke(tool, clean)

    @mcp.tool
    def auftrag_create(caller_instance_id: str, id: str, title: str, project: str,
                       steps: str, request_id: str, description: str = "",
                       exit_kpis: str = "", constraints: str = "", rollback: str = "",
                       decision_ref: str = "", based_on: str = "", priority: str = "normal",
                       assigned_to: str = "", duration_planned: int | None = None,
                       predecessor_id: str = "", tags: str = "", context_policy: str = "",
                       identity_envelope: dict[str, Any] | None = None,
                       ctx: Context = None) -> dict:
        return dispatch("auftrag_create", locals(), ctx)

    @mcp.tool
    def auftrag_list(caller_instance_id: str, status: str = "", project: str = "",
                     assigned_to: str = "", limit: int = 50, offset: int = 0,
                     identity_envelope: dict[str, Any] | None = None,
                     ctx: Context = None) -> dict:
        return dispatch("auftrag_list", locals(), ctx)

    @mcp.tool
    def auftrag_get(auftrag_id: str, caller_instance_id: str,
                    identity_envelope: dict[str, Any] | None = None, ctx: Context = None) -> dict:
        return dispatch("auftrag_get", locals(), ctx)

    @mcp.tool
    def auftrag_assign(caller_instance_id: str, auftrag_id: str, assigned_to: str,
                       request_id: str, identity_envelope: dict[str, Any] | None = None,
                       ctx: Context = None) -> dict:
        return dispatch("auftrag_assign", locals(), ctx)

    @mcp.tool
    def auftrag_reassign_replace(caller_instance_id: str, auftrag_id: str,
                                  new_auftrag_id: str, new_assigned_to: str,
                                  request_id: str, reason: str = "",
                                  context_policy: str = "", identity_envelope: dict[str, Any] | None = None,
                                  ctx: Context = None) -> dict:
        return dispatch("auftrag_reassign_replace", locals(), ctx)

    @mcp.tool
    def auftrag_start(caller_instance_id: str, auftrag_id: str, request_id: str,
                      identity_envelope: dict[str, Any] | None = None, ctx: Context = None) -> dict:
        return dispatch("auftrag_start", locals(), ctx)

    @mcp.tool
    def auftrag_checkpoint(caller_instance_id: str, auftrag_id: str, step_id: str,
                           status: str, request_id: str, checkpoint_data: str = "",
                           error_message: str = "", duration_actual: int | None = None,
                           identity_envelope: dict[str, Any] | None = None,
                           ctx: Context = None) -> dict:
        return dispatch("auftrag_checkpoint", locals(), ctx)

    @mcp.tool
    def auftrag_block(caller_instance_id: str, auftrag_id: str, reason: str,
                      request_id: str, step_id: str = "",
                      block_type: str = "unclassified", identity_envelope: dict[str, Any] | None = None,
                      ctx: Context = None) -> dict:
        return dispatch("auftrag_block", locals(), ctx)

    @mcp.tool
    def auftrag_resume(caller_instance_id: str, auftrag_id: str, resolution: str,
                       request_id: str, identity_envelope: dict[str, Any] | None = None,
                       ctx: Context = None) -> dict:
        return dispatch("auftrag_resume", locals(), ctx)

    @mcp.tool
    def auftrag_close(caller_instance_id: str, auftrag_id: str, result: str,
                      request_id: str, summary: str = "", kpi_results: str = "",
                      duration_actual: int | None = None, execution_quality: float | None = None,
                      decision_quality: float | None = None, root_cause: str = "",
                      root_cause_category: str = "", kpis_verified: str = "",
                      existing_outcome_id: str = "", identity_envelope: dict[str, Any] | None = None,
                      ctx: Context = None) -> dict:
        return dispatch("auftrag_close", locals(), ctx)

    @mcp.tool
    def auftrag_cancel(caller_instance_id: str, auftrag_id: str, request_id: str,
                       reason: str = "", identity_envelope: dict[str, Any] | None = None,
                       ctx: Context = None) -> dict:
        return dispatch("auftrag_cancel", locals(), ctx)

    @mcp.tool
    def auftrag_get_changelog(caller_instance_id: str, auftrag_id: str = "",
                               instance_id: str = "", project: str = "", period: str = "30d",
                               action: str = "", limit: int = 50, offset: int = 0,
                               identity_envelope: dict[str, Any] | None = None,
                               ctx: Context = None) -> dict:
        return dispatch("auftrag_get_changelog", locals(), ctx)

    @mcp.tool
    def get_instance_activity(auftrag_id: str, caller_instance_id: str,
                              limit: int = 50, offset: int = 0,
                              identity_envelope: dict[str, Any] | None = None,
                              ctx: Context = None) -> dict:
        return dispatch("get_instance_activity", locals(), ctx)

    # Replace annotation-derived schemas with the exact, fully dereferenced
    # normative wire projection.  The dispatch implementation remains the same
    # and middleware still authenticates the exact raw request.
    for name in _TOOLS:
        mcp.local_provider.remove_tool(name)
        mcp.add_tool(_DispatchTool(name, service))

    return MissionInMemoryTransport(mcp)
