"""GHR-004 preimplementation RED: advertised MCP inputs exactly equal normative wire requests."""
from __future__ import annotations

import json
from pathlib import Path

import pytest
from fastmcp import Client


@pytest.mark.anyio
async def test_advertised_request_schemas_exactly_match_wire_contract(server):
    wire = json.loads((Path(__file__).resolve().parents[1] / "spec" / "wire-contract.json").read_text())
    definitions = wire["definitions"]
    def resolve(value):
        if isinstance(value, dict):
            if set(value) == {"$ref"} and value["$ref"].startswith("#/definitions/"):
                return resolve(definitions[value["$ref"].split("/")[-1]])
            return {key: resolve(item) for key, item in value.items()}
        if isinstance(value, list):
            return [resolve(item) for item in value]
        return value
    expected = {name: resolve(body["request"]) for name, body in wire["tools"].items()}
    async with Client(server) as client:
        actual = {tool.name: tool.inputSchema for tool in await client.list_tools()}
    assert actual == expected


def test_every_response_variant_is_closed_and_coherent():
    wire = json.loads((Path(__file__).resolve().parents[1] / "spec" / "wire-contract.json").read_text())
    for name, body in wire["tools"].items():
        response = body["response"]
        assert response["additionalProperties"] is False, name
        properties = set(response["properties"])
        assert set(response["required"]) <= properties, name
        for variant, shape in response["variants"].items():
            assert set(shape["required"]) <= properties, (name, variant)
            if variant == "success":
                assert shape["status_const"] == "ok"
            else:
                assert shape["status_const"] == "error"
                assert {"code", "message"} <= set(shape["required"])
