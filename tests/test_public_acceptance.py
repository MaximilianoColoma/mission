from __future__ import annotations
import json
import sqlite3
from pathlib import Path

import pytest
from fastmcp import Client

from mission_public.auth import bind_transport_credential
from mission_public.server import create_server
from conftest import FaultInjector, prepare_call


def payload(result):
    assert result.content
    return json.loads(result.content[0].text)


def assert_wire_response(name, body):
    wire = json.loads((Path(__file__).resolve().parents[1] / "spec" / "wire-contract.json").read_text())
    schema = wire["tools"][name]["response"]
    assert set(body) <= set(schema["properties"]), (name, set(body) - set(schema["properties"]))
    variant = schema["variants"]["success" if body.get("status") == "ok" else "error"]
    assert set(variant["required"]) <= set(body), (name, set(variant["required"]) - set(body))
    assert body["status"] == variant["status_const"]


async def call(client,token,name,args,raise_on_error=False):
    args = prepare_call(token, name, args)
    with bind_transport_credential(token):
        body = payload(await client.call_tool(name,args,raise_on_error=raise_on_error))
    assert_wire_response(name, body)
    return body


async def seed_assigned(client,provider,aid="A-DEMO-001",worker="worker-a"):
    planner=provider.issue("planner-a","planner")
    await call(client,planner,"auftrag_create",{"caller_instance_id":"planner-a","id":aid,"title":"Synthetic delivery","project":"demo","steps":json.dumps([{"id":"S1","name":"Produce receipt"}]),"exit_kpis":json.dumps({"required":["receipt"]}),"request_id":f"{aid}-create"})
    await call(client,planner,"auftrag_assign",{"caller_instance_id":"planner-a","auftrag_id":aid,"assigned_to":worker,"request_id":f"{aid}-assign"})
    return planner


@pytest.mark.anyio
async def test_idempotency_hashes_finite_exact_raw_input_not_default_projection(server, provider):
    token = provider.issue("planner-a", "planner")
    base = {
        "caller_instance_id": "planner-a", "id": "A-RAW-IDEMPOTENCY",
        "title": "Raw", "project": "demo",
        "steps": json.dumps([{"id": "S1", "name": "Prove"}]),
        "request_id": "raw-default-conflict",
    }
    async with Client(server) as client:
        first = await call(client, token, "auftrag_create", base)
        explicit_default = await call(
            client, token, "auftrag_create", {**base, "description": ""}, False
        )
    assert first["status"] == "ok"
    assert explicit_default["code"] == "CONFLICT"


@pytest.mark.anyio
async def test_complete_lifecycle_over_mcp(server,provider):
    async with Client(server) as client:
        await seed_assigned(client,provider)
        worker=provider.issue("worker-a","worker")
        started=await call(client,worker,"auftrag_start",{"caller_instance_id":"worker-a","auftrag_id":"A-DEMO-001","request_id":"start-1"})
        checkpoint=await call(client,worker,"auftrag_checkpoint",{"caller_instance_id":"worker-a","auftrag_id":"A-DEMO-001","step_id":"S1","status":"pass","checkpoint_data":json.dumps({"evidence":["synthetic"]}),"request_id":"cp-1"})
        closed=await call(client,worker,"auftrag_close",{"caller_instance_id":"worker-a","auftrag_id":"A-DEMO-001","result":"success","summary":"Synthetic completion","kpi_results":json.dumps({"receipt":{"met":True,"value":1,"evidence":"synthetic"}}),"request_id":"close-1"})
        got=await call(client,worker,"auftrag_get",{"auftrag_id":"A-DEMO-001","caller_instance_id":"worker-a"})
    assert started["next_state"]=="active" and checkpoint["next_state"]=="validating" and closed["next_state"]=="done"
    assert got["auftrag"]["status"]=="done"


@pytest.mark.anyio
@pytest.mark.parametrize("case",["missing","missing_claim","expired","revoked","indeterminate","future_issued","boundary_future","wrong_issuer","wrong_audience","unknown_role","provider_failure"])
async def test_credentials_fail_closed_for_mcp(server,provider,case):
    token=None
    if case!="missing":
        kwargs={}
        if case=="expired": kwargs["expires_delta"]=-1
        if case=="revoked": kwargs["revocation_status"]="revoked"
        if case=="indeterminate": kwargs["revocation_status"]="unknown"
        if case=="future_issued": kwargs["issued_offset"]=3600
        if case=="boundary_future": kwargs["issued_offset"]=31
        if case=="wrong_issuer": kwargs["issuer"]="wrong-issuer"
        if case=="wrong_audience": kwargs["audience"]="wrong-audience"
        if case=="missing_claim": kwargs["drop_field"]="audience"
        role="invented" if case=="unknown_role" else "planner"
        token=provider.issue("planner-a",role,**kwargs)
    if case=="provider_failure": provider.lookup_failure=True
    async with Client(server) as client:
        result=payload(await client.call_tool("auftrag_list",{"caller_instance_id":"planner-a","limit":1},raise_on_error=False)) if token is None else await call(client,token,"auftrag_list",{"caller_instance_id":"planner-a","limit":1},False)
    assert result["code"]=="AUTHENTICATION_REQUIRED"


@pytest.mark.anyio
async def test_identity_and_object_relations_are_enforced(server,provider):
    async with Client(server) as client:
        await seed_assigned(client,provider)
        assigned=provider.issue("worker-a","worker")
        foreign=provider.issue("worker-b","worker")
        planner=provider.issue("planner-b","planner")
        mismatch=await call(client,assigned,"auftrag_get",{"auftrag_id":"SECRET-ID","caller_instance_id":"other"},False)
        foreign_start=await call(client,foreign,"auftrag_start",{"caller_instance_id":"worker-b","auftrag_id":"A-DEMO-001","request_id":"foreign-start"},False)
        noncreator_cancel=await call(client,planner,"auftrag_cancel",{"caller_instance_id":"planner-b","auftrag_id":"A-DEMO-001","request_id":"foreign-cancel"},False)
    assert mismatch["code"]=="IDENTITY_MISMATCH" and "SECRET-ID" not in json.dumps(mismatch)
    assert foreign_start["code"]=="NOT_FOUND"
    assert noncreator_cancel["code"]=="NOT_FOUND"


@pytest.mark.anyio
async def test_admin_bypasses_relation_but_not_fsm(server,provider):
    async with Client(server) as client:
        await seed_assigned(client,provider)
        admin=provider.issue("admin-a","admin")
        started=await call(client,admin,"auftrag_start",{"caller_instance_id":"admin-a","auftrag_id":"A-DEMO-001","request_id":"admin-start"})
        illegal=await call(client,admin,"auftrag_cancel",{"caller_instance_id":"admin-a","auftrag_id":"A-DEMO-001","reason":"too late","request_id":"admin-cancel"},False)
    assert started["status"]=="ok" and illegal["code"]=="INVALID_TRANSITION"


@pytest.mark.anyio
async def test_block_resume_restores_validating_and_terminal_is_immutable(server,provider):
    async with Client(server) as client:
        await seed_assigned(client,provider)
        worker=provider.issue("worker-a","worker")
        await call(client,worker,"auftrag_start",{"caller_instance_id":"worker-a","auftrag_id":"A-DEMO-001","request_id":"s"})
        await call(client,worker,"auftrag_checkpoint",{"caller_instance_id":"worker-a","auftrag_id":"A-DEMO-001","step_id":"S1","status":"pass","request_id":"c"})
        blocked=await call(client,worker,"auftrag_block",{"caller_instance_id":"worker-a","auftrag_id":"A-DEMO-001","reason":"Synthetic block","request_id":"b"})
        resumed=await call(client,worker,"auftrag_resume",{"caller_instance_id":"worker-a","auftrag_id":"A-DEMO-001","resolution":"resolved","request_id":"r"})
        await call(client,worker,"auftrag_close",{"caller_instance_id":"worker-a","auftrag_id":"A-DEMO-001","result":"success","kpi_results":json.dumps({"receipt":{"met":True,"value":1,"evidence":"synthetic"}}),"request_id":"cl"})
        terminal=await call(client,worker,"auftrag_block",{"caller_instance_id":"worker-a","auftrag_id":"A-DEMO-001","reason":"impossible","request_id":"after"},False)
    assert blocked["previous_state"]=="validating" and resumed["next_state"]=="validating"
    assert terminal["code"]=="INVALID_TRANSITION"


@pytest.mark.anyio
async def test_checkpoint_fail_wrong_step_and_idempotent_replay(server,provider):
    async with Client(server) as client:
        await seed_assigned(client,provider)
        worker=provider.issue("worker-a","worker")
        await call(client,worker,"auftrag_start",{"caller_instance_id":"worker-a","auftrag_id":"A-DEMO-001","request_id":"s"})
        wrong=await call(client,worker,"auftrag_checkpoint",{"caller_instance_id":"worker-a","auftrag_id":"A-DEMO-001","step_id":"S9","status":"pass","request_id":"wrong"},False)
        args={"caller_instance_id":"worker-a","auftrag_id":"A-DEMO-001","step_id":"S1","status":"pass","request_id":"same-cp"}
        first=await call(client,worker,"auftrag_checkpoint",args)
        second=await call(client,worker,"auftrag_checkpoint",args)
        conflict=await call(client,worker,"auftrag_checkpoint",{**args,"status":"fail"},False)
    assert wrong["code"]=="INVALID_TRANSITION" and first==second and conflict["code"]=="CONFLICT"


@pytest.mark.anyio
async def test_reassign_preserves_predecessor_and_requires_eligible_assignee(server,provider):
    async with Client(server) as client:
        await seed_assigned(client,provider)
        planner=provider.issue("planner-a","planner")
        bad=await call(client,planner,"auftrag_reassign_replace",{"caller_instance_id":"planner-a","auftrag_id":"A-DEMO-001","new_auftrag_id":"A-DEMO-002","new_assigned_to":"missing-worker","request_id":"re-bad"},False)
        good=await call(client,planner,"auftrag_reassign_replace",{"caller_instance_id":"planner-a","auftrag_id":"A-DEMO-001","new_auftrag_id":"A-DEMO-002","new_assigned_to":"worker-b","reason":"Synthetic handoff","request_id":"re-good"})
        old=await call(client,planner,"auftrag_get",{"auftrag_id":"A-DEMO-001","caller_instance_id":"planner-a"})
        new=await call(client,planner,"auftrag_get",{"auftrag_id":"A-DEMO-002","caller_instance_id":"planner-a"})
        old_start=await call(client,provider.issue("worker-a","worker"),"auftrag_start",{"caller_instance_id":"worker-a","auftrag_id":"A-DEMO-001","request_id":"old-start"},False)
        changelog=await call(client,planner,"auftrag_get_changelog",{"auftrag_id":"A-DEMO-001","caller_instance_id":"planner-a","limit":50})
    assert bad["code"]=="INVALID_INPUT"
    assert good["predecessor_id"]=="A-DEMO-001" and old["auftrag"]["status"]=="cancelled" and new["auftrag"]["assigned_to"]==provider.ensure_identity("worker-b")
    assert new["auftrag"]["predecessor_id"]=="A-DEMO-001" and old_start["code"]=="INVALID_TRANSITION"
    assert any(e["action"]=="reassign_replace" and e["next_state"]=="cancelled" for e in changelog["items"])


@pytest.mark.anyio
async def test_privacy_activity_and_error_envelopes(server,provider):
    planner=provider.issue("planner-a","planner")
    async with Client(server) as client:
        await call(client,planner,"auftrag_create",{"caller_instance_id":"planner-a","id":"A-DEMO-PII","title":"Contact person@example.com","project":"demo","steps":json.dumps([{"id":"S1","name":"Email person@example.com"}]),"description":"person@example.com","request_id":"pii-create"})
        got=await call(client,planner,"auftrag_get",{"auftrag_id":"A-DEMO-PII","caller_instance_id":"planner-a"})
        activity=await call(client,planner,"get_instance_activity",{"auftrag_id":"A-DEMO-PII","caller_instance_id":"planner-a","limit":50})
        invalid=await call(client,planner,"auftrag_create",{"caller_instance_id":"planner-a","id":"bad id","title":"SECRET-VALUE","project":"demo","steps":"[]","request_id":"pii-bad"},False)
    assert "person@example.com" not in json.dumps(got) and "[REDACTED:EMAIL]" in json.dumps(got)
    required={"actor_subject_id","action","occurred_at","auftrag_id","result_code"}
    assert activity["items"] and all(set(item)==required for item in activity["items"])
    assert "SECRET-VALUE" not in json.dumps(invalid) and "correlation_id" in invalid


@pytest.mark.anyio
async def test_audit_failure_rolls_back_create(provider,directory,tmp_path):
    db_path=tmp_path/"atomic.db"; server=create_server(db_path=db_path,credential_provider=provider,principal_directory=directory,identity_context=provider.context,adapters_enabled=False,fault_injector=FaultInjector("before_audit_insert")); token=provider.issue("planner-a","planner")
    async with Client(server) as client:
        result=await call(client,token,"auftrag_create",{"caller_instance_id":"planner-a","id":"A-ROLLBACK-001","title":"Rollback","project":"demo","steps":json.dumps([{"id":"S1","name":"No commit"}]),"request_id":"atomic"},False)
    assert result["code"]=="INTERNAL_ERROR"
    with sqlite3.connect(db_path) as db: assert db.execute("SELECT COUNT(*) FROM auftraege WHERE id='A-ROLLBACK-001'").fetchone()[0]==0


@pytest.mark.anyio
async def test_assignee_eligibility_variants_and_auditor_read_only(server,provider,directory):
    directory.add("disabled",active=False); directory.add("wrong-tenant",tenant="other"); directory.add("planner-only",roles=("planner",))
    planner=provider.issue("planner-a","planner"); auditor=provider.issue("auditor-a","auditor")
    async with Client(server) as client:
        await call(client,planner,"auftrag_create",{"caller_instance_id":"planner-a","id":"A-ELIG-001","title":"Eligibility","project":"demo","steps":json.dumps([{"id":"S1","name":"Check"}]),"request_id":"elig-create"})
        for i,target in enumerate(("disabled","wrong-tenant","planner-only")):
            denied=await call(client,planner,"auftrag_assign",{"caller_instance_id":"planner-a","auftrag_id":"A-ELIG-001","assigned_to":target,"request_id":f"elig-{i}"},False)
            assert denied["code"]=="INVALID_INPUT"
        visible=await call(client,auditor,"auftrag_get",{"caller_instance_id":"auditor-a","auftrag_id":"A-ELIG-001"})
        mutate=await call(client,auditor,"auftrag_cancel",{"caller_instance_id":"auditor-a","auftrag_id":"A-ELIG-001","request_id":"audit-mutate"},False)
    assert visible["auftrag"]["id"]=="A-ELIG-001" and mutate["code"]=="PERMISSION_DENIED"


@pytest.mark.anyio
async def test_all_declared_free_text_is_redacted_at_rest(provider,directory,tmp_path):
    db_path=tmp_path/"pii-at-rest.db"; server=create_server(db_path=db_path,credential_provider=provider,principal_directory=directory,identity_context=provider.context,adapters_enabled=False); planner=provider.issue("planner-a","planner"); worker=provider.issue("worker-a","worker"); pii="person@example.com"
    async with Client(server) as client:
        await call(client,planner,"auftrag_create",{"caller_instance_id":"planner-a","id":"A-PII-001","title":pii,"project":"demo","steps":json.dumps([{"id":"S1","name":pii,"optional":False}]),"description":pii,"constraints":pii,"rollback":pii,"tags":pii,"request_id":"pii-create"})
        await call(client,planner,"auftrag_assign",{"caller_instance_id":"planner-a","auftrag_id":"A-PII-001","assigned_to":"worker-a","request_id":"pii-assign"})
        await call(client,worker,"auftrag_start",{"caller_instance_id":"worker-a","auftrag_id":"A-PII-001","request_id":"pii-start"})
        await call(client,worker,"auftrag_block",{"caller_instance_id":"worker-a","auftrag_id":"A-PII-001","reason":pii,"request_id":"pii-block"})
        await call(client,worker,"auftrag_resume",{"caller_instance_id":"worker-a","auftrag_id":"A-PII-001","resolution":pii,"request_id":"pii-resume"})
        await call(client,worker,"auftrag_checkpoint",{"caller_instance_id":"worker-a","auftrag_id":"A-PII-001","step_id":"S1","status":"fail","checkpoint_data":json.dumps({"note":pii}),"error_message":pii,"request_id":"pii-cp"})
    with sqlite3.connect(db_path) as db:
        dump=" ".join(str(v) for table in ("auftraege","steps","blocks","changelog") for row in db.execute(f"SELECT * FROM {table}") for v in row)
    assert pii not in dump and "[REDACTED:EMAIL]" in dump


@pytest.mark.anyio
async def test_audit_schema_is_complete_append_only(provider,directory,tmp_path):
    db_path=tmp_path/"audit-shape.db"; server=create_server(db_path=db_path,credential_provider=provider,principal_directory=directory,identity_context=provider.context,adapters_enabled=False); planner=provider.issue("planner-a","planner")
    async with Client(server) as client:
        await call(client,planner,"auftrag_create",{"caller_instance_id":"planner-a","id":"A-AUDIT-001","title":"Audit","project":"demo","steps":json.dumps([{"id":"S1","name":"Check"}]),"request_id":"audit-create"})
    required={"event_id","occurred_at","correlation_id","request_id","principal_subject_id","asserted_subject_id","client_id","role","auftrag_id_or_redacted","action","previous_state","next_state","reason_code","result_code"}
    with sqlite3.connect(db_path) as db:
        assert required <= {row[1] for row in db.execute("PRAGMA table_info(changelog)")}
        with pytest.raises(sqlite3.DatabaseError): db.execute("DELETE FROM changelog")
        with pytest.raises(sqlite3.DatabaseError): db.execute("UPDATE changelog SET result_code='X'")


@pytest.mark.anyio
async def test_wire_bounds_and_create_assignment_bypass_are_rejected(server,provider):
    planner=provider.issue("planner-a","planner")
    async with Client(server) as client:
        bound=await call(client,planner,"auftrag_list",{"caller_instance_id":"planner-a","limit":101},False)
        bypass=await call(client,planner,"auftrag_create",{"caller_instance_id":"planner-a","id":"A-BYPASS-001","title":"Bypass","project":"demo","steps":json.dumps([{"id":"S1","name":"No"}]),"assigned_to":"worker-a","predecessor_id":"A-OLD","request_id":"bypass"},False)
    assert bound["code"]=="INVALID_INPUT" and bypass["code"]=="INVALID_INPUT"


@pytest.mark.anyio
async def test_optional_skip_required_skip_and_close_result_mapping(server,provider):
    planner=provider.issue("planner-a","planner"); worker=provider.issue("worker-a","worker")
    async with Client(server) as client:
        await call(client,planner,"auftrag_create",{"caller_instance_id":"planner-a","id":"A-MAP-001","title":"Map","project":"demo","steps":json.dumps([{"id":"R","name":"Required","optional":False},{"id":"O","name":"Optional","optional":True}]),"exit_kpis":json.dumps({"required":["receipt"]}),"request_id":"map-create"})
        await call(client,planner,"auftrag_assign",{"caller_instance_id":"planner-a","auftrag_id":"A-MAP-001","assigned_to":"worker-a","request_id":"map-assign"})
        await call(client,worker,"auftrag_start",{"caller_instance_id":"worker-a","auftrag_id":"A-MAP-001","request_id":"map-start"})
        required_skip=await call(client,worker,"auftrag_checkpoint",{"caller_instance_id":"worker-a","auftrag_id":"A-MAP-001","step_id":"R","status":"skipped","request_id":"skip-required"},False)
        await call(client,worker,"auftrag_checkpoint",{"caller_instance_id":"worker-a","auftrag_id":"A-MAP-001","step_id":"R","status":"pass","request_id":"pass-required"})
        optional_skip=await call(client,worker,"auftrag_checkpoint",{"caller_instance_id":"worker-a","auftrag_id":"A-MAP-001","step_id":"O","status":"skipped","request_id":"skip-optional"})
        partial=await call(client,worker,"auftrag_close",{"caller_instance_id":"worker-a","auftrag_id":"A-MAP-001","result":"partial","kpi_results":json.dumps({"receipt":{"met":True,"value":1}}),"request_id":"partial-close"})
        await seed_assigned(client,provider,"A-FAIL-001")
        await call(client,worker,"auftrag_start",{"caller_instance_id":"worker-a","auftrag_id":"A-FAIL-001","request_id":"fail-start"})
        checkpoint_fail=await call(client,worker,"auftrag_checkpoint",{"caller_instance_id":"worker-a","auftrag_id":"A-FAIL-001","step_id":"S1","status":"fail","error_message":"synthetic","request_id":"fail-cp"})
    assert required_skip["code"]=="INVALID_TRANSITION" and optional_skip["next_state"]=="validating"
    assert partial["next_state"]=="done" and checkpoint_fail["next_state"]=="failed"


@pytest.mark.anyio
async def test_fail_close_requires_root_cause_and_tamper_blocks_writes(provider,directory,tmp_path):
    db_path=tmp_path/"tamper.db"; first=create_server(db_path=db_path,credential_provider=provider,principal_directory=directory,identity_context=provider.context,adapters_enabled=False); planner=provider.issue("planner-a","planner"); worker=provider.issue("worker-a","worker")
    async with Client(first) as client:
        await seed_assigned(client,provider,"A-CLOSE-FAIL")
        await call(client,worker,"auftrag_start",{"caller_instance_id":"worker-a","auftrag_id":"A-CLOSE-FAIL","request_id":"cf-start"})
        await call(client,worker,"auftrag_checkpoint",{"caller_instance_id":"worker-a","auftrag_id":"A-CLOSE-FAIL","step_id":"S1","status":"pass","request_id":"cf-cp"})
        missing=await call(client,worker,"auftrag_close",{"caller_instance_id":"worker-a","auftrag_id":"A-CLOSE-FAIL","result":"fail","kpi_results":json.dumps({"receipt":{"met":False,"value":0}}),"request_id":"cf-missing"},False)
        failed=await call(client,worker,"auftrag_close",{"caller_instance_id":"worker-a","auftrag_id":"A-CLOSE-FAIL","result":"fail","root_cause":"synthetic","kpi_results":json.dumps({"receipt":{"met":False,"value":0}}),"request_id":"cf-ok"})
    assert missing["code"]=="INVALID_INPUT" and failed["next_state"]=="failed"
    with sqlite3.connect(db_path) as db: db.execute("DROP TRIGGER changelog_no_delete")
    restarted=create_server(db_path=db_path,credential_provider=provider,principal_directory=directory,identity_context=provider.context,adapters_enabled=False)
    async with Client(restarted) as client:
        denied=await call(client,planner,"auftrag_create",{"caller_instance_id":"planner-a","id":"A-AFTER-TAMPER","title":"No","project":"demo","steps":json.dumps([{"id":"S1","name":"No"}]),"request_id":"after-tamper"},False)
    assert denied["code"]=="INTERNAL_ERROR"


@pytest.mark.anyio
async def test_decoded_payload_schemas_and_empty_request_id(server,provider):
    planner=provider.issue("planner-a","planner")
    async with Client(server) as client:
        empty=await call(client,planner,"auftrag_create",{"caller_instance_id":"planner-a","id":"A-EMPTY-ID","title":"No","project":"demo","steps":json.dumps([{"id":"S1","name":"No"}]),"request_id":""},False)
        malformed=await call(client,planner,"auftrag_create",{"caller_instance_id":"planner-a","id":"A-BAD-NESTED","title":"No","project":"demo","steps":json.dumps([{"id":"S1","name":"No","extra":"x"}]),"exit_kpis":json.dumps({"unknown":[]}),"request_id":"bad-nested"},False)
    assert empty["code"]=="INVALID_INPUT" and malformed["code"]=="INVALID_INPUT"


@pytest.mark.anyio
async def test_frozen_public_tool_names(server):
    expected={"auftrag_create","auftrag_list","auftrag_get","auftrag_assign","auftrag_reassign_replace","auftrag_start","auftrag_checkpoint","auftrag_block","auftrag_resume","auftrag_close","auftrag_cancel","auftrag_get_changelog","get_instance_activity"}
    async with Client(server) as client: tools=await client.list_tools()
    assert {tool.name for tool in tools}==expected
