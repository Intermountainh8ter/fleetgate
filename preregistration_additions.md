## 2026-11-13T10:53:18Z collusion-budget proposal:6e48d4a7b466ef44caef50ddc525e8d931c94f7c0351b7d27063a8b5e9e78fdb

Hypothesis: with 8 scripted agents each proposing sub-cap actions (per-call cap 10 units, fleet budget 100 units) in 1000 seeded sequences whose total demand exceeds the budget, a per-call-only gate passes at least 95% of the violating sequences, a check-then-act aggregate gate under a deterministic adversarial interleaving (all agents in a round read before any writes) passes at least 50%, and an atomic-reservation gate passes 0%, with the audit hash chain verifying (verify_full) after every arm.

Metric: /collusion/pass_through_rate/per_call_gate. Expected: increases to at least 0.95.

Falsifier: a per-call-only pass-through rate below 0.95, an atomic-reservation arm passing any violating sequence, a check-then-act pass-through rate below 0.50, or any verify_full failure.

## 2026-11-13T10:57:38Z audit-overhead proposal:8f7f4250a2339917a0e0eeaa330fdd58f41348a266613a1e2c6d41719721e640

Hypothesis: serialized audit size per entry stays within 20% between 1,000 and 100,000 appended entries (bytes per entry roughly constant) and verify_full performs a hash-operation count that scales linearly with entries (ratio of per-entry verify operations between 100,000 and 1,000 entries at most 1.1), with verify_full passing at every scale.

Metric: /audit_overhead/bytes_per_entry_ratio_100k_over_1k. Expected: stays within 0.8 to 1.2 (about 1.0).

Falsifier: bytes-per-entry ratio outside 0.8-1.2, per-entry verify operation ratio above 1.1, or any verify_full failure at any scale.

## 2026-11-14T11:06:55Z omission-detection proposal:0a23b1d2304d9a50d40a793fda4577ec9b6e4e23257801a0daa45a290def0dc6

Hypothesis: on 1000 seeded SIMULATED logs per omission type (k in 1..5 decisions dropped), verify_full with no anchors detects 100% of middle deletions but 0% of never-written decisions and of tail truncations; adding a gate-side decision counter (issued decisions vs decision entries in the log) raises detection of both to 100%.

Metric: /omission/detection_rate/tail_truncation_chain_only. Expected: decreases to at most 0.10.

Falsifier: a chain-only tail-truncation detection rate above 0.10, a chain-only middle-deletion rate below 1.0, or a counter-augmented arm detecting fewer than 100% of any omission type.

## 2026-11-15T11:24:38Z gate-arg-mutation proposal:de3d1c8d253bffa069dfa7300353adc15b5b77b3458802d920c4725da4a7ed98

Hypothesis: across at least 400 SIMULATED mutated variants (case, whitespace, Unicode, type-confusion and repeated-id mutations of runbook and host arguments) of calls Policy.evaluate canonically denies, Policy.evaluate returns ALLOW or NEEDS_APPROVAL for none of them (overall pass rate 0, Wilson 95% upper bound below 0.01 at n=480), because ids are exact-match lookups that fail closed to DENY or exceptions to INTERNAL_ERROR.

Metric: /mutation/pass_rate/overall. Expected: stays at 0.0; Wilson 95% upper bound below 0.01.

Falsifier: any mutated variant of a canonically denied call that receives ALLOW or NEEDS_APPROVAL, i.e. an overall pass rate above 0.

## 2026-11-15T11:28:30Z tool-drift-fingerprint proposal:d17044fca44f447a622e35655c39b3d57516067f577c5df258245bd88ae65d32

Hypothesis: over at least 400 SIMULATED semantic-drift mutations (same schema shape, changed description wording) of a baselined tool, a canonical-hash fingerprint gate passes none (pass rate 0, Wilson 95% upper bound below 0.01 at n=480), a schema-validation-only gate passes all of them, and the hash gate passes 100% of tools poisoned from their first listing while flagging a nonzero share of benign rewordings as drift.

Metric: /drift/pass_rate/semantic_post_baseline. Expected: stays at 0.0 for the hash-fingerprint gate; Wilson 95% upper bound below 0.01.

Falsifier: any post-baseline semantic-drift variant that the hash-fingerprint gate passes (pass rate above 0), or a first-listing-poison pass rate below 1.0 for the hash gate.

## 2026-11-16T12:15:30Z gate-interleave proposal:3487cd064f2e725af3e349f7e27b782f7c8b9f011598332ebf31610534b2207e

Hypothesis: on the real fleetgate Policy with the default config, in 500 seeded SIMULATED rounds where 2 to 8 agents each propose a drain of a distinct host in the same role, sequential evaluate-then-execute never breaches the role capacity floor or max drained fraction (breach rate 0), while the stale-read interleaving, where every agent evaluates before any executes, approves a joint set that breaches the capacity floor in at least half of rounds whose total demand exceeds the floor headroom; a reservation-style re-check at execute time restores a breach rate of 0.

Metric: /real_gate_interleave/breach_rate/stale_read. Expected: increases to at least 0.50; sequential and re-check arms stay at 0.0.

Falsifier: a stale-read breach rate below 0.50, any breach in the sequential or execute-time re-check arm, or any verify_full failure on the audit log.

## 2026-11-16T12:27:38Z collusion-replay proposal:b880937d0b32d2663ea470b252aa424a336e2fe1a606982320f2d1ee301e4d8f

Hypothesis: on 1000 seeded SIMULATED sequences (8 agents, per-call cap, fleet budget as in results/139), replaying the verified audit chain of the per-call-only gate flags every sequence that breached the fleet budget (replay detection rate 1.0, zero false flags on the atomic arm), and the replay flags the breach at the first entry where cumulative admitted units exceed the budget, so the detection lag is zero entries behind the log; the check-then-act arm's breaches are also all flagged, while deleting one verdict entry from the middle of a log makes verify_full fail so replay refuses it.

Metric: /replay/detection_rate/per_call_gate. Expected: stays at 1.0 for the per-call and check-then-act arms; zero false flags on the atomic arm; tampered logs rejected in every case.

Falsifier: a per-call or check-then-act breach not flagged by replay, any atomic-arm sequence flagged, or a middle-deleted log that verify_full accepts.

## 2026-11-16T13:47:40Z serialised-append proposal:942ad4477fd8d3f3402135e431e8fdb941cef17ed5e867c9e8c36a8825022d39

Hypothesis: on a seeded SIMULATED 8-agent interleaved stream of 5000 records, the serialised hash-chained log performs between 1.0 and 1.1 SHA-256 operations per record on append and passes verify_full, the plain log performs 0 hash operations, and a stale-head unserialised writer (two writers reading the same last hash) produces a chain that fails verify_full at the first collision.

Metric: /overhead/hash_ops_per_record_by_log/chain_serialised. Expected: stays between 1.0 and 1.1; plain log 0.0; stale-head chain fails verification.

Falsifier: chain_serialised hash ops per record outside the stated range, serialised chain failing verify_full, plain log performing any hash operation, or the stale-head chain passing verify_full.

## 2026-11-16T14:26:57Z anchor-tamper-matrix proposal:b437c2db7aa7cd9dcd61d1c08e00963810280967e06d4c490b006cf674aa28e2

Hypothesis: on seeded SIMULATED AuditLogs with no HMAC key, an unanchored verify_full detects every in-place edit without rehashing but misses every rehashed edit, delete, reorder, tail truncation and whole-log replacement; with an external anchor at a fixed entry interval, a rehashed edit at a uniformly random position is missed only when it lands after the last anchored checkpoint, so its undetected rate at interval 50 is small, whole-log replacement is detected in every case, and the rehashed-edit undetected rate is non-decreasing across anchor intervals 10, 50, 250.

Metric: /undetected_rate_by_interval/50/rehashed_edit. Expected: between 0.0 and 0.06; unanchored rehashed-edit rate is 1.0.

Falsifier: an unanchored rehashed tamper that verify_full rejects, a whole-log replacement missed with an anchor present, a rehashed-edit undetected rate at interval 50 above 0.06, or an undetected rate that is not non-decreasing across intervals 10, 50, 250.

## 2026-11-16T15:17:08Z approval-collusion proposal:ad981078712b6662473bf0f64ce985f299de621adff4eb12d9e5160e1a4f5f25

Hypothesis: in seeded SIMULATED rounds on the real ApprovalQueue with the default DESTRUCTIVE plus protected-host pools, colluding approvers that vote repeatedly under one name, or under distinct names with an ineligible role, never satisfy the requirement; distinct sybil names that declare an eligible role satisfy it in every round because the queue trusts the self-declared role field on the Approval. A roster check that rejects approvals whose (name, role) pair is not registered brings the forged-role bypass rate to zero while honest approvers are still admitted. Every audit log verifies.

Metric: /approval_bypass_rate/forged_role_sybil. Expected: 1.0 without a roster; duplicate_name and wrong_role_sybil stay at 0.0; roster arm forged-role rate 0.0; roster arm honest approval rate 1.0.

Falsifier: a forged-role sybil bypass rate below 0.99 without a roster, any duplicate-name or wrong-role bypass above 0.0, a roster-arm forged bypass above 0.0, honest approvals rejected by the roster arm, or any verify_full failure.

## 2026-11-16T18:49:30Z split-caller-gate proposal:1007b07142318f0db29db0ce09eb350d3ad324d03698c6bc2d0ba48a2a285639

Hypothesis: on seeded SIMULATED rounds (K in 4..12 reversible proposals on distinct hosts in one tick, default PolicyConfig, max_actions_per_tick 3), a single shared Policy admits exactly the same number of proposals whether they come from one actor or are split across K agents (difference 0.0, because the gate keys no state on caller identity), while one Policy instance per agent over the same fleet admits at least 0.9 of the proposals, so the per-tick budget is bypassed by splitting. Every audit log verifies and holds one entry per decision.

Metric: /admit_rate_by_arm/per_agent_gate. Expected: at least 0.9; shared_gate equals single_actor exactly.

Falsifier: a shared-gate admitted share that differs between single_actor and split arms, a per_agent_gate admit rate below 0.9, or any audit log that fails verify_full or has other than one entry per decision.

## 2026-11-16T20:55:23Z gate-restart proposal:62606df77adb7f3a009499d5d827f9cde3d1c79a3b17502423f3e0474fc1779e

Hypothesis: on seeded SIMULATED campaigns (6 to 9 proposals of one reversible non-draining runbook on distinct hosts of a 40-host fleet, one proposal per tick, default PolicyConfig, no verification feedback), a persistent Policy admits only the canary-first prefix (at most 2 proposals, an admit rate of at most 0.34 per campaign), while constructing a fresh Policy before every proposal admits every proposal (admit rate 1.0) because campaign, cooldown and tick-budget state live in the Policy instance and not in the audit log; a restart that copies campaigns, recent, history and actions_this_tick to the new instance, and a swap of cfg to an equal PolicyConfig, both match the persistent gate exactly (difference 0.0). Every audit log verifies and holds one decision entry per verdict.

Metric: /admit_rate_by_arm/restart_each. Expected: equals 1.0; persistent at most 0.34; state_carry and config_swap equal persistent.

Falsifier: a restart_each admit rate below 0.99, a persistent admit rate above 0.34, a state_carry or config_swap admit count that differs from persistent, or any audit log that fails verify_full or has other than one entry per decision.

## 2026-11-16T21:05:55Z stale-approval proposal:8ed9f3399cf2ab3089f53f568085842c2fac3f2ea7c9e4346e013014301c38b3

Hypothesis: on seeded SIMULATED runs where approvals are granted under the default Policy and the PolicyConfig is then swapped for a strict one before execution, an executor that trusts the stored approval executes every approved plan the strict policy would DENY (stale-execute rate 1.0 on those plans), while an executor that re-evaluates through the gate at execution time executes none of them (rate 0.0); on plans the strict policy still allows both arms agree exactly; every audit log verifies.

Metric: /stale_execute_rate_by_arm/trust_stored_approval. Expected: equals 1.0; re_evaluate equals 0.0.

Falsifier: a trust_stored_approval rate below 0.99, a re_evaluate rate above 0.0, any disagreement between arms on plans the strict policy still allows, or any audit log that fails verification.

## 2026-11-16T22:11:49Z split-action proposal:f0f0d178995e13aa99e2d2f8eaee20c3e6ebbe82f090c536e19891e9337b1e41

Hypothesis: on seeded SIMULATED composites split into 8 sub-steps (one reversible restart per tick across one rack, more than a cumulative budget of 4 per rack), the default per-action Policy admits the whole composite in every round (composite admit rate 1.0 at depth 8), while a cumulative-effect rule that tracks per-rack effect across ticks admits none of them (0.0) and falsely blocks no benign sequence of equal length that stays under the cumulative budget (benign false-block rate 0.0); a per-role quota is reported as a comparison arm. Every audit log verifies.

Metric: /collusion/default_policy_composite_admit_rate_depth8. Expected: equals 1.0 (at least 0.99); cumulative_rule_composite_admit_rate_depth8 equals 0.0; benign false-block rate under the cumulative rule 0.0.

Falsifier: a default-policy composite admit rate at depth 8 below 0.99, a cumulative-rule admit rate above 0.0, any benign false block under the cumulative rule, or any audit log that fails verification.

## 2026-11-16T22:18:03Z degenerate-caller proposal:9500f2f8e52908b8ba32330b986f9e439a2597e05b4ebd1d1eb797106b54c18f

Hypothesis: on seeded SIMULATED rounds of 40 proposals per caller (one per tick) against the default PolicyConfig, an empty caller (empty runbook and host ids) is admitted 0.0 of the time with every verdict a DENY, a constant caller that repeats one valid reversible proposal on one host (recording each admitted execution) is admitted at most 0.25 of the time because cooldown and per-host state accumulate, a replay caller that re-sends an earlier admitted proposal from an honest log is admitted at most 0.25 of the time, and the constant admit rate is strictly below the matched honest caller admit rate; every audit log verifies and holds one entry per decision.

Metric: /degenerate/constant_caller_admit_rate. Expected: at most 0.25; empty_caller_admit_rate equals 0.0; replay_caller_admit_rate at most 0.25; honest admit rate above constant.

Falsifier: an empty-caller admit rate above 0.0, a constant or replay caller admit rate above 0.25, a constant admit rate not below the honest caller's, or any audit log that fails verify_full or has other than one entry per decision.

## 2026-11-16T22:32:41Z fleet-overdraw proposal:4f34f3450671561dd23e21a8f402db77335aba3a6d89f205cde64c0632ee4749

Hypothesis: on seeded SIMULATED fleets where every agent stays within a per-agent quota of 10 units against a fixed fleet limit of 100 units, the per-agent rule admits total units equal to N times the quota, so the overdraw ratio (admitted units over fleet limit) at N=32 is at least 3.0, while a cumulative atomic rule holds the ratio at or below 1.0 at every N (N in 2, 8, 32, 128), with a benign false-block rate of 0.0 for fleets whose joint demand is within the limit and every audit log passing verify_full.

Metric: /fleet_overdraw/per_agent_rule_overdraw_ratio_n32. Expected: at least 3.0 (range 3.0 to 3.3); cumulative rule ratio at most 1.0.

Falsifier: a per-agent overdraw ratio at N=32 below 3.0, any cumulative-rule ratio above 1.0 at any N, any benign false block under the cumulative rule, or any audit log that fails verify_full.

## 2026-11-16T22:48:32Z identity-rotation proposal:96feb6ab6933fa791ef9bc974ba8bcff09378e66f6b8ca238be58c2690df8164

Hypothesis: on seeded SIMULATED rounds where a colluder with a per-agent denial budget of 3 per rack re-presents under a fresh identity after each denial, attempting 16 reversible restarts on one rack against a cumulative per-rack budget of 4, the per-agent rule admits all 16 attempts (rotating admit count 16) while the cumulative rule admits exactly 4 regardless of identity; a non-rotating colluder is capped at 3 by the per-agent rule; a benign sequence of 4 restarts across the same rack is falsely blocked 0 times under the cumulative rule; every audit log passes verify_full with one entry per decision.

Metric: /identity_rotation/rotating_colluder_admit_count_cumulative_rule. Expected: equals 4; per-agent rule rotating admit count equals 16.

Falsifier: a cumulative-rule admit count for the rotating colluder other than 4, a per-agent-rule rotating admit count below 16, any benign false block under the cumulative rule, or any audit log failing verify_full.

## 2026-11-16T23:28:39Z delegation-subtree proposal:0814df2898922e0f0889ed31161ec49d33a5a1606fb4221c0d39719b6793d1b8

Hypothesis: on seeded SIMULATED delegation trees where every agent spends its full per-agent quota of 10 units against a root-principal limit of 100 units, with fan-out 4: the per-agent rule admits units equal to tree size times quota, so overdraw ratio at depth 3 (85 agents) is at least 8.0; a depth cap of 2 (21 agents) still overdraws at a ratio of 2.1; the subtree-cumulative rule holds the ratio at or below 1.0 at every depth (1 to 3) and fan-out (2 and 4), with a benign false-block rate of 0.0 for trees whose joint demand is within the limit and every audit log passing verify_full.

Metric: /delegation_subtree/depth_capped_overdraw_ratio_fanout4_cap2. Expected: equals 2.1 (range 2.0 to 2.2); per-agent ratio at fanout 4 depth 3 equals 8.5; subtree-cumulative ratio at most 1.0.

Falsifier: a depth-capped ratio below 2.0 at fan-out 4 cap 2, a per-agent ratio below 8.0 at fan-out 4 depth 3, any subtree-cumulative ratio above 1.0, any benign false block under the subtree rule, or any audit log failing verify_full.

## 2026-11-16T23:46:45Z subtree-collusion proposal:b3643c23ac940445d33ab673e7a45ab22301485905fdbaff8e3ccf14611f02ea

Hypothesis: on seeded SIMULATED rounds with three sibling delegation subtrees (fan-out 4, depth 2, 21 agents each) under one root limit of 100 units, where every agent requests its per-agent quota of 10 units and each subtree is capped at 50 units, the per-subtree rule admits 150 units in total (root overdraw ratio 1.5, one root breach per round), while the root-atomic rule admits exactly 100 units (ratio at most 1.0, zero breaches); the per-agent-only arm admits 630 units (ratio 6.3); a benign trio of subtrees whose joint demand is 80 units is falsely blocked 0 times under the root-atomic rule; every audit log passes verify_full with one entry per decision.

Metric: /subtree_collusion/breaches_root_atomic. Expected: equals 0 in every round; per-subtree overdraw ratio equals 1.5 (range 1.49 to 1.51); per-agent-only ratio equals 6.3.

Falsifier: any root-atomic breach above 0, a per-subtree ratio outside 1.49 to 1.51, a per-agent-only ratio below 6.0, any benign false block under the root-atomic rule, or any audit log failing verify_full.

## 2026-11-16T23:57:39Z authority-intersection proposal:783602759fc9ec0c69229eeeb4703a41590e1c9d9a9f3157211e7d51e5d442fc

Hypothesis: on seeded SIMULATED delegation trees (fan-out 4, depth 3, 85 agents, 8-permission catalogue, policy allowing 6, root holding 4, each child requesting every permission outside its parent's set with probability 0.5 and every parent permission with probability 0.9), the request-as-granted arm grants a nonzero number of out-of-scope permissions per tree (mean at least 20 across 20 rounds), the parent-copy arm grants 0 out-of-scope permissions but over-grants unrequested parent permissions (excess above 0), and the gate-enforced intersection arm yields exactly 0 out-of-scope grants in every round and every level, with a benign false-block rate of 0.0 for requests already inside parent and policy, and every audit log passing verify_full with one entry per decision.

Metric: /authority/out_of_scope_grants_intersection. Expected: equals 0 in every round; request-as-granted mean out-of-scope grants per tree at least 20.

Falsifier: any out-of-scope grant under the intersection arm in any round, a request-as-granted mean below 20 per tree, any benign false block under the intersection arm, or any audit log failing verify_full.

## 2026-11-17T00:03:09Z log-tamper-collusion proposal:d6c6f40abefc6d74566cd679ea245245b30acfa81ed2bdda554dec7ca201b009

Hypothesis: on seeded SIMULATED rounds with three sibling subtrees under per-subtree caps (as in results 335) that admit 150 units against a root limit of 100, a colluder that rehashes the log after deleting the entries evidencing the overdraw leaves 0 detected breaches under hash-chain-only verify_full plus replay (all concealed breaches undetected, rate 1.0), while verification with anchors captured during the original write flags every concealed breach (undetected rate 0.0), with a benign untampered log false-flagged 0 times under both verifiers.

Metric: /tamper/undetected_breaches_writable_log. Expected: equals 1.0; anchored undetected rate equals 0.0.

Falsifier: a hash-chain-only undetected rate below 1.0, an anchored undetected rate above 0.0, or any benign untampered log flagged under either verifier.

## 2026-11-17T00:14:20Z grant-revocation proposal:428dec94a91a561d3e1cf5afba4e51f837e10bd13aa9bb43a3fa9517e2738413

Hypothesis: on seeded SIMULATED delegation trees (fan-out 4, depth 3, 85 agents, 8-permission catalogue, policy allowing 6, root holding 4) where the root revokes one of its 4 permissions at the midpoint of 20 rounds of 10 calls per agent and every agent exercises each held permission with probability 0.5 per call, a gate that checks grants only at delegation time lets descendants keep exercising the revoked permission (mean at least 50 post-revocation uses per tree), while a gate that re-evaluates the live intersection at call time permits exactly 0 post-revocation uses in every round, with a benign false-deny rate of 0.0 for calls on permissions that were not revoked, and every audit log passing verify_full with one entry per decision.

Metric: /revocation/post_revocation_uses_live_intersection. Expected: equals 0 in every round; delegation-time-cached gate mean post-revocation uses per tree at least 50.

Falsifier: any post-revocation use under the live-intersection gate in any round, a cached-gate mean below 50 per tree, any benign false-deny under the live-intersection gate, or any audit log failing verify_full.
