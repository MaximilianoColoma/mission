# Product proof brief — Mission README

**Audience:** developers building multi-agent systems, autonomous coding teams, agent platform maintainers, and technical founders.

**Claim:** Mission turns agent intentions into persistent, role-bound work state that survives interruption and closes only through declared lifecycle, required-step, and caller-declared KPI-key rules.

**Observable proof:** create and assign a real Auftrag over MCP, start and checkpoint it with signed synthetic planner/worker identities, recreate the server, read the restored validating state, let a signed auditor inspect history read-only, then close after the worker supplies the required caller-declared KPI key.

**Source truth:** real Mission v0.1.0 public-core behavior and contract. Mission validates lifecycle and caller-declared KPI structure; it does not externally verify evidence. No agent spawning, cloud orchestration, production federation, or automatic Witness bridge is claimed.

**Destination:** GitHub README as product landing page; source-checkout terminal demo as primary proof; Mermaid sequence as supporting explanation.

**Evidence class: real.** The terminal demonstration executes the actual MCP server, identity checks, lifecycle FSM, SQLite persistence, restart, close gate, and changelog. Credentials and data are synthetic.

**Desired action:** recognize the coordination failure, see the state transition, run the demo, then inspect the roadmap or contract.

**Constraints:** no fabricated users, integrations, productivity metrics, hosted runtime, or autonomous scheduler. Dream functions must be labeled as enabled patterns rather than shipped orchestration.
