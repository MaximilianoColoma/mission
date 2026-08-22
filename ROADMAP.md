# Mission product roadmap

Mission is the persistent work-state layer for coordinated agent autonomy. The roadmap advances by **observable coordination proofs**, not a calendar.

## v0.1.0 — shipped

- Apache-2.0 public core and reproducible release artifacts
- 13 MCP tools for create, assign, start, checkpoint, block, resume, replace, close and audit
- planner, worker, auditor and admin roles with default-deny identity binding
- explicit lifecycle and immutable terminal states
- restart-safe SQLite persistence and append-only changelog
- real local restart/lifecycle demo and public fresh-install verification

## Next proof — one real multi-agent mission survives a model handoff

**Claim to prove:** a planner can assign bounded work, a builder can checkpoint evidence, and a different runtime can resume without a human reconstructing state.

Exit evidence:

1. public install completes from scratch;
2. planner creates steps, constraints and exit KPIs;
3. verified worker advances the Auftrag;
4. runtime/model changes after a checkpoint while retaining the same assigned identity;
5. the new runtime reads the exact active state and finishes lawfully;
6. auditor reconstructs the lifecycle from changelog alone;
7. owner routing/reconstruction work is measured.

## Next product layer — coordinated suite

Build only after the external handoff proof:

- explicit Mission KPI declaration export and Witness evidence-verification/linking contract;
- client recipes for common MCP agent runtimes;
- bounded wake-up/recovery adapter interface;
- deployment profile with SLO, backup/restore and rollback evidence;
- operator quickstart completed by a fresh user in under 15 minutes.

## Later proof gates

### Multi-host coordination

Federated assignment without privilege union. Exit: two hosts recover from disconnect/retry without duplicate execution or identity ambiguity.

### Policy-aware model routing

Select builders by capability, cost and risk while Mission retains the same work token. Exit: model replacement preserves constraints, attribution and completed-effect boundaries.

### Multi-tenant service

Tenant isolation, principal lifecycle and support operations. Exit: cross-tenant authorization, deletion and recovery tests pass.

### Sustainable SaaS

Usage metering, seats, billing and managed operations only after repeat users prove that Mission reduces coordination and recovery burden.

## Not promised

- no bundled model runner, scheduler or agent-spawn engine in v0.1.0;
- no automatic Telegram, webhook, trigger-file or Witness side effects;
- no production federation or hosted control plane;
- no release dates before the preceding proof gate passes;
- no productivity, scale or customer-outcome claim without measured external use.

Every stage requires prewritten acceptance, a distinct validator and readback from the actual target environment.
