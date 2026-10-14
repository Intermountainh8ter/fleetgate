# Glossary

Every abbreviation and piece of jargon used in this repository, in plain words.

## The policy gate

**ALLOW / DENY** — Whether the gate permits a proposed action. Decided by fixed
rules, not by the language model.

**approver** — Who must sign off before a risky action runs. `auto` approves
automatically, `humans` requires a person, `nobody` denies everything, `instant`
approves without delay. Used to measure how much the approval step costs.

**canary** — Trying a change on one machine first and checking it before rolling
out to the rest. Measured here as making no difference to recovery time.

**contained** — A fault that was not fixed, but whose machine was safely drained
so it can do no further harm.

**drain** — Taking a machine out of service gracefully, moving its work
elsewhere first.

**drain_cap** — The maximum share of the fleet that may be drained at once. The
only policy dial in this repo's sweep that measurably changed the outcome.

**destructive_signoffs** — How many approvals a destructive action needs.
Measured as inert: 1, 2 or 3 gave 22.8, 23.0 and 23.3 hours.

**freeze** — A window during which disruptive actions are blocked.

**gate evaluation** — One check of one proposed action against the policy.
104,828 of them were run in the adversarial suite.

**hostile planner** — A deliberately adversarial agent that tries to get unsafe
actions past the gate. It exists to prove the gate holds.

**maintenance window** — A scheduled period when disruptive work is permitted.

**policy** — A JSON file of rules about what may be done, to how much of the
fleet, and with whose approval.

**safety invariant** — A property that must never be violated, whatever happens.
Zero violations is the required result, not a good one.

## Incident terms

**blast radius** — How much of the fleet one action can affect.

**detected / resolved / contained** — A fault that was noticed; fixed; or
neutralised by draining its host without being fixed.

**EWMA — Exponentially Weighted Moving Average** — A running average that gives
recent readings more weight. Used for detecting drift in a signal.

**fault** — One thing that has gone wrong on one machine.

**MTTR — Mean Time To Recovery** — Average time from a fault appearing to being
fixed, in simulated ticks. Lower is better.

**censored MTTR** — MTTR computed when some faults were never fixed within the
run. Those unfinished cases are "censored", and ignoring them would flatter the
result.

**page** — Waking a human on call.

**scenario** — One scripted failure situation, e.g. `cooling_zone_loss`.

**storm** — Several faults arriving at once.

**tick** — One step of simulated time.

**TTD / TTR — Time To Detect / Time To Recovery** — How long until a fault was
noticed, and until it was fixed.

## Infrastructure

**BMC — Baseboard Management Controller** — The small always-on computer inside
a server that lets you power-cycle it remotely.

**DC — Data Centre** — The building full of machines.

**ECC — Error-Correcting Code** — Memory that detects and corrects bit errors.
An "ECC storm" means a stick of RAM is failing.

**firmware** — The low-level software built into hardware.

**IPMI — Intelligent Platform Management Interface** — The standard protocol for
talking to a BMC.

**NTP — Network Time Protocol** — How machines keep their clocks in sync.

**PDU — Power Distribution Unit** — The rack's power strip. One PDU failing
takes out everything plugged into it.

**PSU — Power Supply Unit** — A single machine's power supply.

**rack** — A cabinet of machines sharing power and network. Faults cluster by
rack, which is why "two hosts in the same rack" is a scenario.

**SMART** — The self-reporting health data a disk drive exposes.

**ToR — Top of Rack (switch)** — The network switch serving one rack. If it
dies, the whole rack goes dark.

**validator / worker** — Roles a machine can have. Validators are the ones you
must not take down carelessly.

## Evaluation

**adversarial suite** — 2,460 runs in which a hostile planner actively tries to
break the safety rules.

**Monte Carlo sweep** — Running many random scenarios across a grid of policy
settings to see which settings matter. Here: 288 runs, 36 configurations.

**paired storms** — The same random failure scenario replayed under each policy
setting, so settings are compared on identical events.

**seed** — A fixed starting number that makes a random scenario repeatable.

## Machine learning and systems

**AI / LLM — Large Language Model** — The kind of AI that predicts text. In this
repo it only proposes actions; the gate decides.

**API — Application Programming Interface** — A network interface for sending
requests to a service.

**CLI — Command-Line Interface** — The terminal commands this tool provides.

**FAQ** — Frequently Asked Questions.

**HMAC — Hash-based Message Authentication Code** — A signature proving a
message came from someone holding a shared secret and was not altered.

**JSON** — A structured record format.

**MIT** — The permissive open-source licence this repo uses.

**SDK — Software Development Kit** — A library for building on this tool.

**SHA-256** — A fingerprint of a file: same contents, same fingerprint.

**SSH — Secure Shell** — The standard way to log into a remote machine.
