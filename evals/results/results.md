# fleetgate eval results

```text
THE SIMULATOR IS IDEALISED. Faults are injected step/ramp/intermittent changes on Gaussian noise, a fix clears a
fault after a fixed delay, thresholds were written by the same author as the faults, and humans are a latency
model. These numbers show that the plumbing, the gate and the detectors behave as designed on a model of a
fleet. They are NOT evidence about real BMC/SMART data, real operators, or real outage rates.
```

Generated 2026-10-14T01:22:13Z on Python 3.13.16 (full mode). All runs are seeded; re-running reproduces these numbers.

## Detection quality (6 seeds x 28 fault types x one injected fault per run, 20 hosts, 40-tick horizon)

### flat load: macro-averaged over fault types

| detector  | precision | recall |    F1 | mean TTD (ticks) | FP / 1k host-ticks (healthy) | FP incidents (healthy) |
|:----------|----------:|-------:|------:|-----------------:|-----------------------------:|-----------------------:|
| threshold |     1.000 |  1.000 | 1.000 |            3.673 |                        0.000 |                      0 |
| ewma      |     0.954 |  0.976 | 0.957 |            2.159 |                        0.042 |                      1 |
| seasonal  |     1.000 |  1.000 | 1.000 |            2.321 |                        0.000 |                      0 |

### flat load: per fault type (R = recall, TTD = mean ticks to detect, - = never)

| fault              | onset        | thre R | thre F1 | thre TTD | ewma R | ewma F1 | ewma TTD | seas R | seas F1 | seas TTD |
|:-------------------|:-------------|-------:|--------:|---------:|-------:|--------:|---------:|-------:|--------:|---------:|
| thermal            | step         |  1.000 |   1.000 |    2.000 |  1.000 |   1.000 |    2.000 |  1.000 |   1.000 |    2.000 |
| cooling_failure    | ramp         |  1.000 |   1.000 |    6.000 |  1.000 |   1.000 |    2.830 |  1.000 |   1.000 |    3.170 |
| fan_failure        | step         |  1.000 |   1.000 |    2.000 |  1.000 |   1.000 |    2.000 |  1.000 |   1.000 |    2.000 |
| cpu_throttling     | step         |  1.000 |   1.000 |    2.000 |  1.000 |   1.000 |    2.000 |  1.000 |   1.000 |    2.000 |
| service_down       | step         |  1.000 |   1.000 |    2.000 |  1.000 |   1.000 |    2.000 |  1.000 |   1.000 |    2.000 |
| nic_errors         | step         |  1.000 |   1.000 |    2.000 |  1.000 |   0.923 |    2.000 |  1.000 |   1.000 |    2.000 |
| ecc_correctable    | step         |  1.000 |   1.000 |    2.000 |  1.000 |   0.923 |    2.000 |  1.000 |   1.000 |    2.000 |
| ecc_uncorrectable  | step         |  1.000 |   1.000 |    2.000 |  1.000 |   1.000 |    2.000 |  1.000 |   1.000 |    2.000 |
| disk_failing       | step         |  1.000 |   1.000 |    2.000 |  1.000 |   1.000 |    2.000 |  1.000 |   1.000 |    2.000 |
| psu_failure        | step         |  1.000 |   1.000 |    2.000 |  1.000 |   1.000 |    2.000 |  1.000 |   1.000 |    2.000 |
| memory_leak        | ramp         |  1.000 |   1.000 |     11.2 |  0.333 |   0.500 |    3.500 |  1.000 |   1.000 |    6.830 |
| oom_kills          | step         |  1.000 |   1.000 |    2.000 |  1.000 |   0.960 |    2.000 |  1.000 |   1.000 |    2.000 |
| kernel_soft_lockup | step         |  1.000 |   1.000 |    2.000 |  1.000 |   1.000 |    2.000 |  1.000 |   1.000 |    2.000 |
| ntp_drift          | ramp         |  1.000 |   1.000 |    3.500 |  1.000 |   0.923 |    2.000 |  1.000 |   1.000 |    2.000 |
| raid_degraded      | step         |  1.000 |   1.000 |    2.000 |  1.000 |   0.960 |    2.000 |  1.000 |   1.000 |    2.000 |
| bmc_unreachable    | step         |  1.000 |   1.000 |    2.000 |  1.000 |   1.000 |    2.000 |  1.000 |   1.000 |    2.000 |
| disk_latency       | step         |  1.000 |   1.000 |    2.000 |  1.000 |   1.000 |    2.000 |  1.000 |   1.000 |    2.000 |
| packet_loss        | step         |  1.000 |   1.000 |    2.000 |  1.000 |   0.923 |    2.000 |  1.000 |   1.000 |    2.000 |
| uplink_loss        | step         |  1.000 |   1.000 |    2.000 |  1.000 |   1.000 |    2.000 |  1.000 |   1.000 |    2.000 |
| link_flap          | intermittent |  1.000 |   1.000 |    5.000 |  1.000 |   1.000 |    5.000 |  1.000 |   1.000 |    5.000 |
| firmware_mismatch  | step         |  1.000 |   1.000 |    2.000 |  1.000 |   1.000 |    2.000 |  1.000 |   1.000 |    2.000 |
| cert_expiry        | ramp         |  1.000 |   1.000 |     11.0 |  1.000 |   1.000 |    2.000 |  1.000 |   1.000 |    2.000 |
| ssh_unreachable    | step         |  1.000 |   1.000 |    2.000 |  1.000 |   1.000 |    2.000 |  1.000 |   1.000 |    2.000 |
| zombie_growth      | ramp         |  1.000 |   1.000 |    5.170 |  1.000 |   0.923 |    2.000 |  1.000 |   1.000 |    2.000 |
| swap_exhaustion    | ramp         |  1.000 |   1.000 |     10.0 |  1.000 |   1.000 |    2.000 |  1.000 |   1.000 |    2.000 |
| inode_exhaustion   | ramp         |  1.000 |   1.000 |     11.0 |  1.000 |   0.923 |    2.000 |  1.000 |   1.000 |    2.000 |
| gpu_xid            | step         |  1.000 |   1.000 |    2.000 |  1.000 |   0.923 |    2.000 |  1.000 |   1.000 |    2.000 |
| nvme_wear          | step         |  1.000 |   1.000 |    2.000 |  1.000 |   0.923 |    2.000 |  1.000 |   1.000 |    2.000 |

### diurnal load: macro-averaged over fault types

| detector  | precision | recall |    F1 | mean TTD (ticks) | FP / 1k host-ticks (healthy) | FP incidents (healthy) |
|:----------|----------:|-------:|------:|-----------------:|-----------------------------:|-----------------------:|
| threshold |     1.000 |  1.000 | 1.000 |            3.679 |                        0.000 |                      0 |
| ewma      |     0.545 |  0.964 | 0.677 |            2.148 |                        0.354 |                     17 |
| seasonal  |     0.996 |  1.000 | 0.998 |            2.351 |                        0.000 |                      0 |

### diurnal load: per fault type (R = recall, TTD = mean ticks to detect, - = never)

| fault              | onset        | thre R | thre F1 | thre TTD | ewma R | ewma F1 | ewma TTD | seas R | seas F1 | seas TTD |
|:-------------------|:-------------|-------:|--------:|---------:|-------:|--------:|---------:|-------:|--------:|---------:|
| thermal            | step         |  1.000 |   1.000 |    2.000 |  1.000 |   0.868 |    1.830 |  1.000 |   1.000 |    2.000 |
| cooling_failure    | ramp         |  1.000 |   1.000 |    6.000 |  0.833 |   0.783 |    3.000 |  1.000 |   1.000 |    4.000 |
| fan_failure        | step         |  1.000 |   1.000 |    2.000 |  1.000 |   0.852 |    2.000 |  1.000 |   1.000 |    2.000 |
| cpu_throttling     | step         |  1.000 |   1.000 |    2.000 |  1.000 |   0.733 |    2.000 |  1.000 |   1.000 |    2.000 |
| service_down       | step         |  1.000 |   1.000 |    2.000 |  1.000 |   0.632 |    2.000 |  1.000 |   1.000 |    2.000 |
| nic_errors         | step         |  1.000 |   1.000 |    2.000 |  1.000 |   0.600 |    2.000 |  1.000 |   1.000 |    2.000 |
| ecc_correctable    | step         |  1.000 |   1.000 |    2.000 |  1.000 |   0.600 |    2.000 |  1.000 |   1.000 |    2.000 |
| ecc_uncorrectable  | step         |  1.000 |   1.000 |    2.000 |  1.000 |   0.632 |    2.000 |  1.000 |   1.000 |    2.000 |
| disk_failing       | step         |  1.000 |   1.000 |    2.000 |  1.000 |   0.750 |    2.000 |  1.000 |   1.000 |    2.000 |
| psu_failure        | step         |  1.000 |   1.000 |    2.000 |  1.000 |   0.632 |    2.000 |  1.000 |   1.000 |    2.000 |
| memory_leak        | ramp         |  1.000 |   1.000 |     11.3 |  0.167 |   0.268 |    4.000 |  1.000 |   0.973 |    6.830 |
| oom_kills          | step         |  1.000 |   1.000 |    2.000 |  1.000 |   0.750 |    2.000 |  1.000 |   1.000 |    2.000 |
| kernel_soft_lockup | step         |  1.000 |   1.000 |    2.000 |  1.000 |   0.837 |    2.000 |  1.000 |   1.000 |    2.000 |
| ntp_drift          | ramp         |  1.000 |   1.000 |    3.500 |  1.000 |   0.600 |    2.000 |  1.000 |   1.000 |    2.000 |
| raid_degraded      | step         |  1.000 |   1.000 |    2.000 |  1.000 |   0.750 |    2.000 |  1.000 |   1.000 |    2.000 |
| bmc_unreachable    | step         |  1.000 |   1.000 |    2.000 |  1.000 |   0.632 |    2.000 |  1.000 |   1.000 |    2.000 |
| disk_latency       | step         |  1.000 |   1.000 |    2.000 |  1.000 |   0.750 |    2.000 |  1.000 |   1.000 |    2.000 |
| packet_loss        | step         |  1.000 |   1.000 |    2.000 |  1.000 |   0.600 |    2.000 |  1.000 |   1.000 |    2.000 |
| uplink_loss        | step         |  1.000 |   1.000 |    2.000 |  1.000 |   0.750 |    2.000 |  1.000 |   1.000 |    2.000 |
| link_flap          | intermittent |  1.000 |   1.000 |    5.000 |  1.000 |   0.774 |    5.000 |  1.000 |   1.000 |    5.000 |
| firmware_mismatch  | step         |  1.000 |   1.000 |    2.000 |  1.000 |   0.632 |    2.000 |  1.000 |   1.000 |    2.000 |
| cert_expiry        | ramp         |  1.000 |   1.000 |     11.0 |  1.000 |   0.632 |    2.000 |  1.000 |   1.000 |    2.000 |
| ssh_unreachable    | step         |  1.000 |   1.000 |    2.000 |  1.000 |   0.632 |    2.000 |  1.000 |   1.000 |    2.000 |
| zombie_growth      | ramp         |  1.000 |   1.000 |    5.170 |  1.000 |   0.600 |    2.000 |  1.000 |   1.000 |    2.000 |
| swap_exhaustion    | ramp         |  1.000 |   1.000 |     10.0 |  1.000 |   0.857 |    2.000 |  1.000 |   0.973 |    2.000 |
| inode_exhaustion   | ramp         |  1.000 |   1.000 |     11.0 |  1.000 |   0.600 |    2.000 |  1.000 |   1.000 |    2.000 |
| gpu_xid            | step         |  1.000 |   1.000 |    2.000 |  1.000 |   0.600 |    2.000 |  1.000 |   1.000 |    2.000 |
| nvme_wear          | step         |  1.000 |   1.000 |    2.000 |  1.000 |   0.600 |    2.000 |  1.000 |   1.000 |    2.000 |


_section took 186.0s_

## MTTR and containment: 42 scenarios x 5 policies x 3 approver models

Rates are over all faults injected by the scenarios (one scenario may inject many). 'resolved' means the fault was fixed; 'resolved+contained' adds faults whose host was safely drained but still faulty. MTTR is over resolved faults only, in ticks. 'violations' = safety invariants broken (must be 0).

| policy     | approver | faults | detected | resolved | resolved+contained | MTTR mean | MTTR median | pages | denials | peak drained | violations |
|:-----------|:---------|-------:|---------:|---------:|-------------------:|----------:|------------:|------:|--------:|-------------:|-----------:|
| canary     | instant  |    126 |    1.000 |    0.635 |              0.651 |      11.0 |           8 |     4 |       4 |        0.133 |          0 |
| canary     | humans   |    126 |    1.000 |    0.635 |              0.651 |      12.4 |           8 |     5 |       4 |        0.133 |          0 |
| canary     | nobody   |    126 |    0.992 |    0.373 |              0.468 |     7.255 |           7 |    20 |      20 |        0.133 |          0 |
| default    | instant  |    126 |    1.000 |    0.619 |              0.635 |      11.0 |           8 |     6 |       6 |        0.100 |          0 |
| default    | humans   |    126 |    1.000 |    0.619 |              0.635 |      12.8 |          10 |     7 |       6 |        0.100 |          0 |
| default    | nobody   |    126 |    0.992 |    0.214 |              0.389 |     4.815 |           3 |    40 |      40 |        0.100 |          0 |
| freeze     | instant  |    126 |    0.992 |    0.389 |              0.563 |     9.122 |           3 |    34 |      34 |        0.100 |          0 |
| freeze     | humans   |    126 |    0.992 |    0.389 |              0.563 |      10.3 |           5 |    34 |      34 |        0.100 |          0 |
| freeze     | nobody   |    126 |    0.992 |    0.222 |              0.389 |     4.929 |           3 |    39 |      39 |        0.100 |          0 |
| permissive | instant  |    126 |    1.000 |    0.667 |              0.683 |      10.3 |           8 |     0 |       0 |        0.200 |          0 |
| permissive | humans   |    126 |    1.000 |    0.667 |              0.683 |      11.3 |           8 |     1 |       0 |        0.200 |          0 |
| permissive | nobody   |    126 |    0.992 |    0.397 |              0.508 |     7.020 |           7 |    18 |      18 |        0.200 |          0 |
| strict     | instant  |    126 |    1.000 |    0.492 |              0.516 |     8.597 |           5 |    14 |      14 |        0.050 |          0 |
| strict     | humans   |    126 |    1.000 |    0.492 |              0.516 |      11.0 |           6 |    44 |      13 |        0.050 |          0 |
| strict     | nobody   |    126 |    0.992 |    0.127 |              0.270 |     6.938 |           4 |    41 |      41 |        0.050 |          0 |

_section took 21.8s_

## Adversarial safety (2460 runs, 104828 gate evaluations, 7559 actions executed, 1052 approval requests)

| hostile planner | approver    | runs (5 policies) | gate evaluations | actions executed | approval requests | violations | drained <= cap |
|:----------------|:------------|------------------:|-----------------:|-----------------:|------------------:|-----------:|:---------------|
| adversarial     | approve_all |               200 |            17692 |              746 |                55 |          0 | yes            |
| adversarial     | deny_all    |               200 |            17438 |              713 |                64 |          0 | yes            |
| adversarial     | humans      |               200 |            17627 |              745 |                57 |          0 | yes            |
| fuzz            | approve_all |               200 |            17859 |             1939 |               313 |          0 | yes            |
| fuzz            | deny_all    |               200 |            16597 |             1506 |               256 |          0 | yes            |
| fuzz            | humans      |               200 |            17615 |             1910 |               307 |          0 | yes            |
| llm             | approve_all |               420 |                0 |                0 |                 0 |          0 | yes            |
| llm             | deny_all    |               420 |                0 |                0 |                 0 |          0 | yes            |
| llm             | humans      |               420 |                0 |                0 |                 0 |          0 | yes            |

**Total safety-invariant violations: 0; exceptions escaping the orchestrator: 0.** (Both must be 0.)

_section took 88.0s_

## Monte Carlo policy sweep: 288 seeded runs (36 configurations x 8 paired storms)

Each storm: 40 hosts, 10 random faults (drain-heavy mix) injected over ticks 3-20, 70 ticks, simulated on-call humans (first approval after 2 ticks, +1 tick per extra approval). Rows sorted by censored MTTR; `*` marks the 10 Pareto-optimal configurations over (censored MTTR down, peak drained down, sign-offs up).

|   | drain cap | sign-offs | acts/tick | canary | censored MTTR | MTTR (resolved) | resolved | peak drained | sign-offs / risky action | pages |
|:--|----------:|----------:|----------:|-------:|--------------:|----------------:|---------:|-------------:|-------------------------:|------:|
| * |      0.20 |         1 |         3 |    off |          16.0 |            11.4 |    0.899 |        0.128 |                    1.095 |     4 |
| * |      0.20 |         2 |         3 |    off |          16.4 |            11.7 |    0.899 |        0.131 |                    1.690 |     6 |
| * |      0.20 |         3 |         3 |    off |          16.7 |            12.1 |    0.899 |        0.131 |                    2.286 |    29 |
|   |      0.20 |         1 |         3 |     on |          17.0 |            12.5 |    0.899 |        0.131 |                    1.095 |     4 |
|   |      0.20 |         2 |         3 |     on |          17.4 |            12.9 |    0.899 |        0.134 |                    1.690 |     6 |
|   |      0.20 |         3 |         3 |     on |          17.9 |            13.4 |    0.899 |        0.134 |                    2.286 |    29 |
|   |      0.20 |         1 |         1 |    off |          18.6 |            14.1 |    0.899 |        0.138 |                    1.095 |     4 |
|   |      0.20 |         2 |         1 |    off |          18.9 |            14.5 |    0.899 |        0.138 |                    1.690 |     6 |
|   |      0.20 |         1 |         1 |     on |          19.1 |            14.8 |    0.899 |        0.134 |                    1.095 |     4 |
|   |      0.20 |         3 |         1 |    off |          19.2 |            14.8 |    0.899 |        0.134 |                    2.286 |    29 |
|   |      0.20 |         2 |         1 |     on |          19.5 |            15.3 |    0.899 |        0.131 |                    1.690 |     6 |
| * |      0.10 |         1 |         3 |    off |          19.8 |            11.2 |    0.810 |        0.100 |                    1.086 |    14 |
|   |      0.20 |         3 |         1 |     on |          20.0 |            15.7 |    0.899 |        0.138 |                    2.286 |    29 |
| * |      0.10 |         2 |         3 |    off |          20.1 |            11.6 |    0.810 |        0.100 |                    1.743 |    15 |
| * |      0.10 |         3 |         3 |    off |          20.4 |            12.0 |    0.810 |        0.100 |                    2.400 |    37 |
|   |      0.10 |         1 |         3 |     on |          21.0 |            12.1 |    0.797 |        0.100 |                    1.088 |    15 |
|   |      0.10 |         2 |         3 |     on |          21.4 |            12.6 |    0.797 |        0.100 |                    1.735 |    16 |
|   |      0.10 |         3 |         3 |     on |          21.8 |            13.1 |    0.797 |        0.100 |                    2.382 |    37 |
|   |      0.10 |         2 |         1 |    off |          22.5 |            13.1 |    0.785 |        0.100 |                    1.697 |    15 |
|   |      0.10 |         2 |         1 |     on |          22.6 |            14.4 |    0.810 |        0.100 |                    1.714 |    14 |
|   |      0.10 |         1 |         1 |     on |          22.6 |            13.9 |    0.797 |        0.100 |                    1.059 |    15 |
|   |      0.10 |         1 |         1 |    off |          22.8 |            12.8 |    0.772 |        0.100 |                    1.062 |    16 |
|   |      0.10 |         3 |         1 |    off |          22.8 |            13.5 |    0.785 |        0.100 |                    2.394 |    37 |
|   |      0.10 |         3 |         1 |     on |          23.2 |            14.6 |    0.797 |        0.100 |                    2.353 |    37 |
| * |      0.05 |         1 |         3 |    off |          28.2 |           9.500 |    0.608 |        0.050 |                    1.105 |    31 |
| * |      0.05 |         2 |         3 |    off |          28.4 |           9.771 |    0.608 |        0.050 |                    1.684 |    31 |
| * |      0.05 |         3 |         3 |    off |          28.5 |            10.0 |    0.608 |        0.050 |                    2.263 |    42 |
|   |      0.05 |         1 |         3 |     on |          28.6 |            10.2 |    0.608 |        0.050 |                    1.105 |    31 |
|   |      0.05 |         2 |         3 |     on |          28.8 |            10.4 |    0.608 |        0.050 |                    1.684 |    31 |
|   |      0.05 |         3 |         3 |     on |          28.9 |            10.8 |    0.608 |        0.050 |                    2.263 |    42 |
|   |      0.05 |         1 |         1 |    off |          29.5 |            10.5 |    0.595 |        0.050 |                    1.000 |    32 |
|   |      0.05 |         2 |         1 |    off |          29.6 |            10.7 |    0.595 |        0.050 |                    1.684 |    32 |
|   |      0.05 |         1 |         1 |     on |          29.8 |            11.1 |    0.595 |        0.050 |                    1.053 |    32 |
| * |      0.05 |         3 |         1 |    off |          29.8 |            11.0 |    0.595 |        0.050 |                    2.368 |    45 |
|   |      0.05 |         2 |         1 |     on |          29.9 |            11.4 |    0.595 |        0.050 |                    1.684 |    32 |
|   |      0.05 |         3 |         1 |     on |          30.1 |            11.7 |    0.595 |        0.050 |                    2.316 |    44 |

### Marginal effect of each knob (mean over the other knobs)

| knob                 | value | censored MTTR | peak drained | resolved |
|:---------------------|------:|--------------:|-------------:|---------:|
| drain_cap            | 0.050 |          29.2 |        0.050 |    0.601 |
| drain_cap            | 0.100 |          21.8 |        0.100 |    0.797 |
| drain_cap            | 0.200 |          18.1 |        0.134 |    0.899 |
| destructive_signoffs |     1 |          22.8 |        0.094 |    0.765 |
| destructive_signoffs |     2 |          23.0 |        0.095 |    0.767 |
| destructive_signoffs |     3 |          23.3 |        0.095 |    0.766 |
| actions_per_tick     |     1 |          23.9 |        0.095 |    0.762 |
| actions_per_tick     |     3 |          22.1 |        0.094 |    0.770 |
| canary               | False |          22.7 |        0.094 |    0.765 |
| canary               |  True |          23.3 |        0.095 |    0.767 |

**Safety-invariant violations across all 288 runs: 0** (must be 0).

_section took 21.3s_

