"""Preimplementation acceptance for the public product story and executable proof."""
from pathlib import Path
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[1]


def test_readme_leads_with_problem_flow_and_honest_vision():
    text = (ROOT / "README.md").read_text()
    assert "AI agents can act. Mission makes them coordinate." in text
    assert "## See the system move" in text
    assert "```mermaid" in text
    assert "## Run the real demo" in text
    assert "## What this enables" in text
    assert "## Dream functions" in text
    assert "enabled patterns, not bundled orchestration" in text
    assert "Mission does not verify external evidence" in text
    assert "verified receipt" not in text.lower()
    assert "## Built now — and not yet" in text
    assert "not deployed" in text.lower()


def test_product_plan_and_proof_brief_exist():
    roadmap = (ROOT / "ROADMAP.md").read_text()
    proof = (ROOT / "docs" / "proof-brief.md").read_text()
    assert "v0.1.0 — shipped" in roadmap
    assert "Next proof" in roadmap
    assert "Not promised" in roadmap
    assert "Evidence class: real" in proof


def test_real_demo_executes_mission_restart_lifecycle():
    demo = ROOT / "examples" / "coordinated_autonomy_demo.py"
    result = subprocess.run([sys.executable, str(demo)], cwd=ROOT, text=True, capture_output=True, timeout=60)
    assert result.returncode == 0, result.stdout + result.stderr
    assert "MISSION_DEMO_PASS state=done restart=pass auditor_read=pass kpi_gate=caller_declared history=create,assign,start,checkpoint,close" in result.stdout
