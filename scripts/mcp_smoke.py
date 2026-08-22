from __future__ import annotations
import asyncio
from pathlib import Path
from tempfile import TemporaryDirectory
from fastmcp import Client
from mission_public.server import create_server

class Provider:
    issuer = "fresh-install-smoke"
    audience = "mission"
    def resolve(self, raw_credential):
        raise RuntimeError("smoke never authenticates")

class Directory:
    def resolve(self, principal):
        raise RuntimeError("smoke never resolves principals")

async def main():
    with TemporaryDirectory() as temp:
        server = create_server(
            db_path=Path(temp) / "mission.db",
            credential_provider=Provider(),
            principal_directory=Directory(),
            adapters_enabled=False,
        )
        async with Client(server) as client:
            tools = await client.list_tools()
        names = sorted(tool.name for tool in tools)
        assert len(names) == 13, names
        print(f"MCP_FIRST_RUN_PASS product=mission tools={len(names)}")

asyncio.run(main())
