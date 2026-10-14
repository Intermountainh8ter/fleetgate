# Discord / Slack short post

Paste as is (about 600 characters). Link goes after the last line.

---

built fleetgate: incident-response agents that can only *propose* runbooks from a closed catalogue. a deterministic
default-deny gate returns ALLOW / NEEDS_APPROVAL / DENY with a reason code, destructive stuff needs N-of-M approvers,
everything goes in a hash-chained audit log. it's a simulator (idealised, says so on the first screen), but the safety
claims are fuzzed and the fuzzer is mutation-tested. MIT, zero deps, runs offline. would love feedback on the policy
design, especially from anyone who runs real fleets.
