# Scenario benchmark

Generated 2026-11-12 by `internal/bench` over `bench/scenarios` (5 files): 100 attack scenarios covering 48 incident rows of `research/threats.md`, 84 benign look-alikes, 299 mutation and variant runs. Rules: 138 enabled (`agent-integrity@2026.11.0,coverage@2026.11.0,credential@2026.11.0,defense-evasion@2026.11.0,destructive@2026.11.0,execution@2026.11.0,exfiltration@2026.11.0,offensive@2026.11.0,persistence@2026.11.0,posture@2026.11.0,process@2026.11.0,sequence@2026.11.0,supply-chain@2026.11.0`, hash `3d7af0367e8c`).

Rates are k/n with Wilson 95% intervals; cells with n < 30 are marked *insufficient*.

## What this corpus cannot show

- The corpus is synthetic: events were written from the incident mechanics in research/threats.md, not recorded from real attacks, and by the same project that wrote the rules (not blind). Recall here is an upper bound on recall against the incidents as they happened.
- Benign look-alikes bound the false-positive rate only on this hand-picked set; they say nothing about prevalence or about the alert volume of a real fleet (see benign-replay.md for real sessions).
- Rates over fewer than 30 trials are marked insufficient. A rule whose recall rests on one or two scenarios has not been measured.
- Mutations rewrite shell commands only; non-shell evasions are covered by hand-written variants where a scenario has them.
- Ablations replay the same events per surface; they do not model what a surface loses in practice (hook payload fields, transcript truncation, process polling misses).

## Headline

| Measure | Value |
|---|---|
| Plain recall (an expected rule fired on the scenario as written) | 95/100 = 95.0% [88.8, 97.8] |
| Robust recall (detected as written and under every applicable mutation and variant) | 54/100 = 54.0% [44.3, 63.4] |
| Any finding or alert fired on the attack (expected or not) | 93/100 = 93.0% [86.3, 96.6] |
| Recall, outcome attempted | 9/10 = 90.0% [59.6, 98.2] *insufficient* |
| Recall, outcome succeeded | 86/90 = 95.6% [89.1, 98.3] |
| Benign look-alikes with a alert-class hit | 0/84 = 0.0% [0.0, 4.4] |
| Benign look-alikes with a finding-class hit | 5/84 = 6.0% [2.6, 13.2] |
| Benign look-alikes with a signal-class hit | 14/84 = 16.7% [10.2, 26.1] |

## Robustness: recall per mutation operator

Each operator rewrites every shell command of an attack; n is the attacks it applies to.

| Operator | What it does | Recall | Not applicable |
|---|---|---|---|
| quoting | empty quotes inside every command name (c''url) | 44/46 = 95.7% [85.5, 98.8] | 54 |
| ifs | argument separators replaced by ${IFS} | 47/47 = 100.0% [92.4, 100.0] | 52 |
| wrapper | the whole command run through sh -c | 46/48 = 95.8% [86.0, 98.8] | 52 |
| var_assembly | command names assembled from shell variables | 44/46 = 95.7% [85.5, 98.8] | 54 |
| interpreter | the command run from a Python one-liner (subprocess, shell=True) | 46/48 = 95.8% [86.0, 98.8] | 52 |
| split | the command written to a script by a file tool, then run in a second event | 5/48 = 10.4% [4.5, 22.2] | 52 |

## Surface ablations

The same attacks with only the events one surface would have delivered.

| Surfaces | Recall | Attacks with no event on these surfaces |
|---|---|---|
| hook_only (agent hooks only (no daemon, no session logs)) | 66/100 = 66.0% [56.3, 74.5] | 29 |
| transcript_only (session logs only (hooks missing or bypassed)) | 66/100 = 66.0% [56.3, 74.5] | 29 |
| os_only (process monitor and posture scan only (no agent cooperation)) | 29/100 = 29.0% [21.0, 38.5] | 70 |

## Trivial oracles

Baselines that look only at tool and program names. The rules have to beat them on recall and false positives together.

| Oracle | Recall | False-positive rate on benign look-alikes |
|---|---|---|
| spoor rules (scenario detected / any finding or alert on benign) | 95/100 = 95.0% [88.8, 97.8] | 5/84 = 6.0% [2.6, 13.2] |
| any_shell: fires when the scenario runs any shell command or child process | 54/100 = 54.0% [44.3, 63.4] | 66/84 = 78.6% [68.7, 86.0] |
| any_write: fires when the scenario writes or edits any file through a tool | 20/100 = 20.0% [13.3, 28.9] | 13/84 = 15.5% [9.3, 24.7] |
| attack_only_names: fires on any tool, MCP server or program name that occurs in some attack and in no benign scenario (fitted on the same corpus: an optimistic leakage check) | 49/100 = 49.0% [39.4, 58.7] | 0/84 = 0.0% [0.0, 4.4] |

## Per technique

| Technique | Recall | Robust recall | FP rate on look-alikes of this technique |
|---|---|---|---|
| atlas.aml.t0011.002 | 1/1 = 100.0% [20.7, 100.0] *insufficient* | 1/1 = 100.0% [20.7, 100.0] *insufficient* | n/a |
| atlas.aml.t0051.001 | 2/2 = 100.0% [34.2, 100.0] *insufficient* | 1/2 = 50.0% [9.5, 90.5] *insufficient* | 0/4 = 0.0% [0.0, 49.0] *insufficient* |
| atlas.aml.t0053 | 1/1 = 100.0% [20.7, 100.0] *insufficient* | 0/1 = 0.0% [0.0, 79.3] *insufficient* | 0/1 = 0.0% [0.0, 79.3] *insufficient* |
| atlas.aml.t0055 | 2/2 = 100.0% [34.2, 100.0] *insufficient* | 1/2 = 50.0% [9.5, 90.5] *insufficient* | n/a |
| atlas.aml.t0077 | 1/1 = 100.0% [20.7, 100.0] *insufficient* | 1/1 = 100.0% [20.7, 100.0] *insufficient* | 0/1 = 0.0% [0.0, 79.3] *insufficient* |
| atlas.aml.t0080.000 | 2/2 = 100.0% [34.2, 100.0] *insufficient* | 2/2 = 100.0% [34.2, 100.0] *insufficient* | 0/1 = 0.0% [0.0, 79.3] *insufficient* |
| atlas.aml.t0081 | 17/17 = 100.0% [81.6, 100.0] *insufficient* | 17/17 = 100.0% [81.6, 100.0] *insufficient* | 2/6 = 33.3% [9.7, 70.0] *insufficient* |
| atlas.aml.t0083 | 8/8 = 100.0% [67.6, 100.0] *insufficient* | 6/8 = 75.0% [40.9, 92.9] *insufficient* | 0/1 = 0.0% [0.0, 79.3] *insufficient* |
| atlas.aml.t0085.002 | 1/1 = 100.0% [20.7, 100.0] *insufficient* | 0/1 = 0.0% [0.0, 79.3] *insufficient* | n/a |
| atlas.aml.t0086 | 3/4 = 75.0% [30.1, 95.4] *insufficient* | 1/4 = 25.0% [4.6, 69.9] *insufficient* | 0/1 = 0.0% [0.0, 79.3] *insufficient* |
| atlas.aml.t0098 | 2/2 = 100.0% [34.2, 100.0] *insufficient* | 0/2 = 0.0% [0.0, 65.8] *insufficient* | 0/1 = 0.0% [0.0, 79.3] *insufficient* |
| atlas.aml.t0102 | 0/1 = 0.0% [0.0, 79.3] *insufficient* | 0/1 = 0.0% [0.0, 79.3] *insufficient* | n/a |
| atlas.aml.t0103 | 3/3 = 100.0% [43.9, 100.0] *insufficient* | 0/3 = 0.0% [0.0, 56.1] *insufficient* | 1/1 = 100.0% [20.7, 100.0] *insufficient* |
| atlas.aml.t0109 | 6/6 = 100.0% [61.0, 100.0] *insufficient* | 6/6 = 100.0% [61.0, 100.0] *insufficient* | 0/2 = 0.0% [0.0, 65.8] *insufficient* |
| atlas.aml.t0110 | 3/3 = 100.0% [43.9, 100.0] *insufficient* | 3/3 = 100.0% [43.9, 100.0] *insufficient* | n/a |
| attack.t1027 | 1/2 = 50.0% [9.5, 90.5] *insufficient* | 0/2 = 0.0% [0.0, 65.8] *insufficient* | n/a |
| attack.t1027.018 | 3/3 = 100.0% [43.9, 100.0] *insufficient* | 3/3 = 100.0% [43.9, 100.0] *insufficient* | 0/2 = 0.0% [0.0, 65.8] *insufficient* |
| attack.t1041 | n/a | n/a | 0/2 = 0.0% [0.0, 65.8] *insufficient* |
| attack.t1048 | n/a | n/a | 0/1 = 0.0% [0.0, 79.3] *insufficient* |
| attack.t1053.003 | n/a | n/a | 0/1 = 0.0% [0.0, 79.3] *insufficient* |
| attack.t1059.004 | 3/3 = 100.0% [43.9, 100.0] *insufficient* | 0/3 = 0.0% [0.0, 56.1] *insufficient* | 0/10 = 0.0% [0.0, 27.8] *insufficient* |
| attack.t1059.006 | 1/1 = 100.0% [20.7, 100.0] *insufficient* | 0/1 = 0.0% [0.0, 79.3] *insufficient* | 0/2 = 0.0% [0.0, 65.8] *insufficient* |
| attack.t1071.004 | 2/2 = 100.0% [34.2, 100.0] *insufficient* | 0/2 = 0.0% [0.0, 65.8] *insufficient* | 0/1 = 0.0% [0.0, 79.3] *insufficient* |
| attack.t1082 | n/a | n/a | 0/1 = 0.0% [0.0, 79.3] *insufficient* |
| attack.t1098.004 | 1/2 = 50.0% [9.5, 90.5] *insufficient* | 0/2 = 0.0% [0.0, 65.8] *insufficient* | 0/1 = 0.0% [0.0, 79.3] *insufficient* |
| attack.t1105 | n/a | n/a | 0/2 = 0.0% [0.0, 65.8] *insufficient* |
| attack.t1140 | 1/1 = 100.0% [20.7, 100.0] *insufficient* | 0/1 = 0.0% [0.0, 79.3] *insufficient* | 0/1 = 0.0% [0.0, 79.3] *insufficient* |
| attack.t1195.001 | n/a | n/a | 0/1 = 0.0% [0.0, 79.3] *insufficient* |
| attack.t1195.002 | 7/7 = 100.0% [64.6, 100.0] *insufficient* | 5/7 = 71.4% [35.9, 91.8] *insufficient* | 1/5 = 20.0% [3.6, 62.4] *insufficient* |
| attack.t1204.005 | 2/2 = 100.0% [34.2, 100.0] *insufficient* | 0/2 = 0.0% [0.0, 65.8] *insufficient* | n/a |
| attack.t1218 | 1/1 = 100.0% [20.7, 100.0] *insufficient* | 1/1 = 100.0% [20.7, 100.0] *insufficient* | n/a |
| attack.t1222.002 | n/a | n/a | 0/1 = 0.0% [0.0, 79.3] *insufficient* |
| attack.t1485 | 4/5 = 80.0% [37.6, 96.4] *insufficient* | 0/5 = 0.0% [0.0, 43.4] *insufficient* | 1/8 = 12.5% [2.2, 47.1] *insufficient* |
| attack.t1528 | n/a | n/a | 0/1 = 0.0% [0.0, 79.3] *insufficient* |
| attack.t1546.004 | 3/3 = 100.0% [43.9, 100.0] *insufficient* | 1/3 = 33.3% [6.1, 79.2] *insufficient* | n/a |
| attack.t1548.003 | n/a | n/a | 0/1 = 0.0% [0.0, 79.3] *insufficient* |
| attack.t1552.001 | n/a | n/a | 0/3 = 0.0% [0.0, 56.1] *insufficient* |
| attack.t1552.003 | n/a | n/a | 0/1 = 0.0% [0.0, 79.3] *insufficient* |
| attack.t1552.004 | n/a | n/a | 0/2 = 0.0% [0.0, 65.8] *insufficient* |
| attack.t1552.005 | n/a | n/a | 0/1 = 0.0% [0.0, 79.3] *insufficient* |
| attack.t1552.007 | n/a | n/a | 0/2 = 0.0% [0.0, 65.8] *insufficient* |
| attack.t1567 | 1/1 = 100.0% [20.7, 100.0] *insufficient* | 0/1 = 0.0% [0.0, 79.3] *insufficient* | n/a |
| attack.t1567.001 | 2/2 = 100.0% [34.2, 100.0] *insufficient* | 0/2 = 0.0% [0.0, 65.8] *insufficient* | 0/2 = 0.0% [0.0, 65.8] *insufficient* |
| attack.t1567.002 | n/a | n/a | 0/1 = 0.0% [0.0, 79.3] *insufficient* |
| attack.t1567.004 | 1/1 = 100.0% [20.7, 100.0] *insufficient* | 0/1 = 0.0% [0.0, 79.3] *insufficient* | n/a |
| attack.t1572 | n/a | n/a | 0/1 = 0.0% [0.0, 79.3] *insufficient* |
| attack.t1574 | 2/2 = 100.0% [34.2, 100.0] *insufficient* | 2/2 = 100.0% [34.2, 100.0] *insufficient* | 0/2 = 0.0% [0.0, 65.8] *insufficient* |
| attack.t1574.006 | 1/1 = 100.0% [20.7, 100.0] *insufficient* | 0/1 = 0.0% [0.0, 79.3] *insufficient* | n/a |
| attack.t1611 | 1/1 = 100.0% [20.7, 100.0] *insufficient* | 0/1 = 0.0% [0.0, 79.3] *insufficient* | 0/2 = 0.0% [0.0, 65.8] *insufficient* |
| attack.t1677 | 1/1 = 100.0% [20.7, 100.0] *insufficient* | 1/1 = 100.0% [20.7, 100.0] *insufficient* | 0/1 = 0.0% [0.0, 79.3] *insufficient* |
| attack.t1685 | 1/1 = 100.0% [20.7, 100.0] *insufficient* | 0/1 = 0.0% [0.0, 79.3] *insufficient* | 0/4 = 0.0% [0.0, 49.0] *insufficient* |
| attack.t1685.007 | 4/4 = 100.0% [51.0, 100.0] *insufficient* | 2/4 = 50.0% [15.0, 85.0] *insufficient* | 0/1 = 0.0% [0.0, 79.3] *insufficient* |
| owasp.asi10 | n/a | n/a | 0/1 = 0.0% [0.0, 79.3] *insufficient* |

## Per rule

TP/FN count attack scenarios that expect the rule; FP counts benign look-alikes it fired on; Extra counts attacks where it fired without being expected. Rules no scenario expects show only their false positives.

| Rule | Class | TP | FN | FP | Extra | Recall | Robust recall | FP rate |
|---|---|---|---|---|---|---|---|---|
| SPR-AGENT-001 | finding | 2 | 0 | 1 | 0 | 2/2 = 100.0% [34.2, 100.0] *insufficient* | 6/6 = 100.0% [61.0, 100.0] *insufficient* | 1/84 = 1.2% [0.2, 6.4] |
| SPR-AGENT-002 | finding | 3 | 0 | 1 | 2 | 3/3 = 100.0% [43.9, 100.0] *insufficient* | 0/1 = 0.0% [0.0, 79.3] *insufficient* | 1/84 = 1.2% [0.2, 6.4] |
| SPR-AGENT-003 | finding | 2 | 0 | 0 | 0 | 2/2 = 100.0% [34.2, 100.0] *insufficient* | 6/6 = 100.0% [61.0, 100.0] *insufficient* | 0/84 = 0.0% [0.0, 4.4] |
| SPR-AGENT-004 | finding | 2 | 0 | 0 | 0 | 2/2 = 100.0% [34.2, 100.0] *insufficient* | n/a | 0/84 = 0.0% [0.0, 4.4] |
| SPR-AGENT-005 | signal | 0 | 0 | 1 | 0 | n/a | n/a | 1/84 = 1.2% [0.2, 6.4] |
| SPR-AGENT-006 | finding | 1 | 0 | 0 | 0 | 1/1 = 100.0% [20.7, 100.0] *insufficient* | n/a | 0/84 = 0.0% [0.0, 4.4] |
| SPR-AGENT-007 | finding | 1 | 0 | 0 | 0 | 1/1 = 100.0% [20.7, 100.0] *insufficient* | 0/1 = 0.0% [0.0, 79.3] *insufficient* | 0/84 = 0.0% [0.0, 4.4] |
| SPR-AGENT-008 | finding | 1 | 0 | 0 | 0 | 1/1 = 100.0% [20.7, 100.0] *insufficient* | 3/4 = 75.0% [30.1, 95.4] *insufficient* | 0/84 = 0.0% [0.0, 4.4] |
| SPR-AGENT-009 | finding | 1 | 0 | 0 | 0 | 1/1 = 100.0% [20.7, 100.0] *insufficient* | 1/1 = 100.0% [20.7, 100.0] *insufficient* | 0/84 = 0.0% [0.0, 4.4] |
| SPR-AGENT-010 | finding | 1 | 0 | 0 | 0 | 1/1 = 100.0% [20.7, 100.0] *insufficient* | 6/6 = 100.0% [61.0, 100.0] *insufficient* | 0/84 = 0.0% [0.0, 4.4] |
| SPR-AGENT-011 | signal | 0 | 0 | 0 | 0 | n/a | n/a | 0/84 = 0.0% [0.0, 4.4] |
| SPR-AGENT-012 | signal | 0 | 0 | 0 | 2 | n/a | n/a | 0/84 = 0.0% [0.0, 4.4] |
| SPR-AGENT-013 | finding | 1 | 0 | 0 | 0 | 1/1 = 100.0% [20.7, 100.0] *insufficient* | 6/6 = 100.0% [61.0, 100.0] *insufficient* | 0/84 = 0.0% [0.0, 4.4] |
| SPR-COV-001 | finding | 0 | 0 | 0 | 0 | n/a | n/a | 0/84 = 0.0% [0.0, 4.4] |
| SPR-COV-002 | finding | 0 | 0 | 0 | 0 | n/a | n/a | 0/84 = 0.0% [0.0, 4.4] |
| SPR-COV-003 | signal | 0 | 0 | 0 | 0 | n/a | n/a | 0/84 = 0.0% [0.0, 4.4] |
| SPR-COV-004 | finding | 0 | 0 | 0 | 0 | n/a | n/a | 0/84 = 0.0% [0.0, 4.4] |
| SPR-COV-005 | signal | 0 | 0 | 0 | 0 | n/a | n/a | 0/84 = 0.0% [0.0, 4.4] |
| SPR-COV-006 | finding | 0 | 0 | 0 | 0 | n/a | n/a | 0/84 = 0.0% [0.0, 4.4] |
| SPR-COV-007 | signal | 0 | 0 | 0 | 0 | n/a | n/a | 0/84 = 0.0% [0.0, 4.4] |
| SPR-CRED-001 | finding | 1 | 0 | 0 | 0 | 1/1 = 100.0% [20.7, 100.0] *insufficient* | n/a | 0/84 = 0.0% [0.0, 4.4] |
| SPR-CRED-002 | finding | 1 | 0 | 0 | 7 | 1/1 = 100.0% [20.7, 100.0] *insufficient* | 6/7 = 85.7% [48.7, 97.4] *insufficient* | 0/84 = 0.0% [0.0, 4.4] |
| SPR-CRED-003 | signal | 0 | 0 | 1 | 1 | n/a | n/a | 1/84 = 1.2% [0.2, 6.4] |
| SPR-CRED-004 | finding | 0 | 0 | 0 | 0 | n/a | n/a | 0/84 = 0.0% [0.0, 4.4] |
| SPR-CRED-005 | signal | 0 | 0 | 1 | 0 | n/a | n/a | 1/84 = 1.2% [0.2, 6.4] |
| SPR-CRED-006 | finding | 2 | 0 | 0 | 0 | 2/2 = 100.0% [34.2, 100.0] *insufficient* | 10/12 = 83.3% [55.2, 95.3] *insufficient* | 0/84 = 0.0% [0.0, 4.4] |
| SPR-CRED-007 | finding | 1 | 0 | 0 | 0 | 1/1 = 100.0% [20.7, 100.0] *insufficient* | 5/6 = 83.3% [43.6, 97.0] *insufficient* | 0/84 = 0.0% [0.0, 4.4] |
| SPR-CRED-008 | finding | 3 | 0 | 0 | 0 | 3/3 = 100.0% [43.9, 100.0] *insufficient* | 10/12 = 83.3% [55.2, 95.3] *insufficient* | 0/84 = 0.0% [0.0, 4.4] |
| SPR-CRED-009 | finding | 0 | 0 | 0 | 1 | n/a | n/a | 0/84 = 0.0% [0.0, 4.4] |
| SPR-CRED-010 | finding | 0 | 0 | 0 | 0 | n/a | n/a | 0/84 = 0.0% [0.0, 4.4] |
| SPR-CRED-011 | finding | 0 | 0 | 0 | 0 | n/a | n/a | 0/84 = 0.0% [0.0, 4.4] |
| SPR-CRED-012 | signal | 0 | 0 | 1 | 1 | n/a | n/a | 1/84 = 1.2% [0.2, 6.4] |
| SPR-CRED-013 | finding | 0 | 0 | 0 | 0 | n/a | n/a | 0/84 = 0.0% [0.0, 4.4] |
| SPR-DESTR-001 | alert | 1 | 0 | 0 | 0 | 1/1 = 100.0% [20.7, 100.0] *insufficient* | 7/8 = 87.5% [52.9, 97.8] *insufficient* | 0/84 = 0.0% [0.0, 4.4] |
| SPR-DESTR-002 | alert | 0 | 0 | 0 | 0 | n/a | n/a | 0/84 = 0.0% [0.0, 4.4] |
| SPR-DESTR-003 | finding | 2 | 0 | 1 | 0 | 2/2 = 100.0% [34.2, 100.0] *insufficient* | 10/12 = 83.3% [55.2, 95.3] *insufficient* | 1/84 = 1.2% [0.2, 6.4] |
| SPR-DESTR-004 | finding | 0 | 0 | 0 | 0 | n/a | n/a | 0/84 = 0.0% [0.0, 4.4] |
| SPR-DESTR-005 | finding | 1 | 0 | 0 | 0 | 1/1 = 100.0% [20.7, 100.0] *insufficient* | 5/6 = 83.3% [43.6, 97.0] *insufficient* | 0/84 = 0.0% [0.0, 4.4] |
| SPR-DESTR-006 | finding | 0 | 0 | 0 | 1 | n/a | n/a | 0/84 = 0.0% [0.0, 4.4] |
| SPR-DESTR-007 | signal | 0 | 0 | 1 | 0 | n/a | n/a | 1/84 = 1.2% [0.2, 6.4] |
| SPR-DESTR-008 | finding | 1 | 0 | 0 | 0 | 1/1 = 100.0% [20.7, 100.0] *insufficient* | 5/6 = 83.3% [43.6, 97.0] *insufficient* | 0/84 = 0.0% [0.0, 4.4] |
| SPR-EVADE-001 | finding | 1 | 0 | 0 | 0 | 1/1 = 100.0% [20.7, 100.0] *insufficient* | 5/6 = 83.3% [43.6, 97.0] *insufficient* | 0/84 = 0.0% [0.0, 4.4] |
| SPR-EVADE-002 | alert | 1 | 0 | 0 | 0 | 1/1 = 100.0% [20.7, 100.0] *insufficient* | 9/10 = 90.0% [59.6, 98.2] *insufficient* | 0/84 = 0.0% [0.0, 4.4] |
| SPR-EVADE-003 | alert | 1 | 0 | 0 | 0 | 1/1 = 100.0% [20.7, 100.0] *insufficient* | n/a | 0/84 = 0.0% [0.0, 4.4] |
| SPR-EVADE-004 | finding | 0 | 0 | 0 | 0 | n/a | n/a | 0/84 = 0.0% [0.0, 4.4] |
| SPR-EVADE-005 | finding | 0 | 0 | 0 | 0 | n/a | n/a | 0/84 = 0.0% [0.0, 4.4] |
| SPR-EVADE-006 | finding | 0 | 0 | 0 | 0 | n/a | n/a | 0/84 = 0.0% [0.0, 4.4] |
| SPR-EVADE-007 | signal | 0 | 0 | 0 | 1 | n/a | n/a | 0/84 = 0.0% [0.0, 4.4] |
| SPR-EVADE-008 | finding | 0 | 0 | 0 | 0 | n/a | n/a | 0/84 = 0.0% [0.0, 4.4] |
| SPR-EVADE-009 | alert | 2 | 0 | 0 | 0 | 2/2 = 100.0% [34.2, 100.0] *insufficient* | n/a | 0/84 = 0.0% [0.0, 4.4] |
| SPR-EVADE-010 | signal | 0 | 0 | 1 | 0 | n/a | n/a | 1/84 = 1.2% [0.2, 6.4] |
| SPR-EVADE-011 | finding | 0 | 0 | 0 | 0 | n/a | n/a | 0/84 = 0.0% [0.0, 4.4] |
| SPR-EVADE-012 | finding | 1 | 0 | 0 | 0 | 1/1 = 100.0% [20.7, 100.0] *insufficient* | 5/6 = 83.3% [43.6, 97.0] *insufficient* | 0/84 = 0.0% [0.0, 4.4] |
| SPR-EXEC-001 | finding | 4 | 0 | 0 | 2 | 4/4 = 100.0% [51.0, 100.0] *insufficient* | 19/22 = 86.4% [66.7, 95.3] *insufficient* | 0/84 = 0.0% [0.0, 4.4] |
| SPR-EXEC-002 | finding | 1 | 0 | 0 | 0 | 1/1 = 100.0% [20.7, 100.0] *insufficient* | 5/6 = 83.3% [43.6, 97.0] *insufficient* | 0/84 = 0.0% [0.0, 4.4] |
| SPR-EXEC-003 | finding | 1 | 0 | 0 | 0 | 1/1 = 100.0% [20.7, 100.0] *insufficient* | 2/3 = 66.7% [20.8, 93.9] *insufficient* | 0/84 = 0.0% [0.0, 4.4] |
| SPR-EXEC-004 | finding | 1 | 0 | 0 | 0 | 1/1 = 100.0% [20.7, 100.0] *insufficient* | 5/6 = 83.3% [43.6, 97.0] *insufficient* | 0/84 = 0.0% [0.0, 4.4] |
| SPR-EXEC-005 | finding | 2 | 0 | 0 | 0 | 2/2 = 100.0% [34.2, 100.0] *insufficient* | 10/12 = 83.3% [55.2, 95.3] *insufficient* | 0/84 = 0.0% [0.0, 4.4] |
| SPR-EXEC-006 | finding | 2 | 0 | 0 | 0 | 2/2 = 100.0% [34.2, 100.0] *insufficient* | 10/12 = 83.3% [55.2, 95.3] *insufficient* | 0/84 = 0.0% [0.0, 4.4] |
| SPR-EXEC-007 | signal | 0 | 0 | 1 | 1 | n/a | n/a | 1/84 = 1.2% [0.2, 6.4] |
| SPR-EXEC-008 | alert | 2 | 0 | 0 | 1 | 2/2 = 100.0% [34.2, 100.0] *insufficient* | 6/7 = 85.7% [48.7, 97.4] *insufficient* | 0/84 = 0.0% [0.0, 4.4] |
| SPR-EXEC-009 | finding | 1 | 0 | 0 | 0 | 1/1 = 100.0% [20.7, 100.0] *insufficient* | 5/7 = 71.4% [35.9, 91.8] *insufficient* | 0/84 = 0.0% [0.0, 4.4] |
| SPR-EXFIL-001 | alert | 3 | 0 | 0 | 0 | 3/3 = 100.0% [43.9, 100.0] *insufficient* | 11/13 = 84.6% [57.8, 95.7] *insufficient* | 0/84 = 0.0% [0.0, 4.4] |
| SPR-EXFIL-002 | finding | 1 | 0 | 0 | 0 | 1/1 = 100.0% [20.7, 100.0] *insufficient* | 6/7 = 85.7% [48.7, 97.4] *insufficient* | 0/84 = 0.0% [0.0, 4.4] |
| SPR-EXFIL-003 | signal | 0 | 0 | 0 | 2 | n/a | n/a | 0/84 = 0.0% [0.0, 4.4] |
| SPR-EXFIL-004 | finding | 2 | 0 | 0 | 0 | 2/2 = 100.0% [34.2, 100.0] *insufficient* | 10/12 = 83.3% [55.2, 95.3] *insufficient* | 0/84 = 0.0% [0.0, 4.4] |
| SPR-EXFIL-005 | finding | 2 | 0 | 0 | 4 | 2/2 = 100.0% [34.2, 100.0] *insufficient* | 10/12 = 83.3% [55.2, 95.3] *insufficient* | 0/84 = 0.0% [0.0, 4.4] |
| SPR-EXFIL-006 | signal | 0 | 0 | 2 | 0 | n/a | n/a | 2/84 = 2.4% [0.7, 8.3] |
| SPR-EXFIL-007 | finding | 0 | 0 | 0 | 0 | n/a | n/a | 0/84 = 0.0% [0.0, 4.4] |
| SPR-EXFIL-008 | finding | 2 | 0 | 0 | 0 | 2/2 = 100.0% [34.2, 100.0] *insufficient* | 10/12 = 83.3% [55.2, 95.3] *insufficient* | 0/84 = 0.0% [0.0, 4.4] |
| SPR-EXFIL-009 | signal | 0 | 0 | 0 | 0 | n/a | n/a | 0/84 = 0.0% [0.0, 4.4] |
| SPR-EXFIL-010 | finding | 1 | 0 | 0 | 0 | 1/1 = 100.0% [20.7, 100.0] *insufficient* | n/a | 0/84 = 0.0% [0.0, 4.4] |
| SPR-EXFIL-011 | finding | 1 | 0 | 0 | 0 | 1/1 = 100.0% [20.7, 100.0] *insufficient* | 5/6 = 83.3% [43.6, 97.0] *insufficient* | 0/84 = 0.0% [0.0, 4.4] |
| SPR-EXFIL-012 | finding | 0 | 0 | 0 | 0 | n/a | n/a | 0/84 = 0.0% [0.0, 4.4] |
| SPR-EXFIL-013 | signal | 0 | 0 | 0 | 0 | n/a | n/a | 0/84 = 0.0% [0.0, 4.4] |
| SPR-OFFSEC-001 | finding | 4 | 0 | 1 | 0 | 4/4 = 100.0% [51.0, 100.0] *insufficient* | 20/24 = 83.3% [64.1, 93.3] *insufficient* | 1/84 = 1.2% [0.2, 6.4] |
| SPR-OFFSEC-002 | alert | 1 | 0 | 0 | 0 | 1/1 = 100.0% [20.7, 100.0] *insufficient* | 5/6 = 83.3% [43.6, 97.0] *insufficient* | 0/84 = 0.0% [0.0, 4.4] |
| SPR-OFFSEC-003 | signal | 0 | 0 | 1 | 0 | n/a | n/a | 1/84 = 1.2% [0.2, 6.4] |
| SPR-OFFSEC-004 | finding | 0 | 0 | 0 | 0 | n/a | n/a | 0/84 = 0.0% [0.0, 4.4] |
| SPR-OFFSEC-005 | signal | 0 | 0 | 1 | 1 | n/a | n/a | 1/84 = 1.2% [0.2, 6.4] |
| SPR-OFFSEC-006 | finding | 1 | 0 | 0 | 0 | 1/1 = 100.0% [20.7, 100.0] *insufficient* | 5/6 = 83.3% [43.6, 97.0] *insufficient* | 0/84 = 0.0% [0.0, 4.4] |
| SPR-OFFSEC-007 | alert | 1 | 0 | 0 | 0 | 1/1 = 100.0% [20.7, 100.0] *insufficient* | n/a | 0/84 = 0.0% [0.0, 4.4] |
| SPR-OFFSEC-008 | signal | 0 | 0 | 0 | 0 | n/a | n/a | 0/84 = 0.0% [0.0, 4.4] |
| SPR-PERS-001 | finding | 2 | 0 | 0 | 1 | 2/2 = 100.0% [34.2, 100.0] *insufficient* | 5/6 = 83.3% [43.6, 97.0] *insufficient* | 0/84 = 0.0% [0.0, 4.4] |
| SPR-PERS-002 | alert | 0 | 1 | 0 | 0 | 0/1 = 0.0% [0.0, 79.3] *insufficient* | n/a | 0/84 = 0.0% [0.0, 4.4] |
| SPR-PERS-003 | finding | 0 | 0 | 0 | 0 | n/a | n/a | 0/84 = 0.0% [0.0, 4.4] |
| SPR-PERS-004 | signal | 0 | 0 | 1 | 0 | n/a | n/a | 1/84 = 1.2% [0.2, 6.4] |
| SPR-PERS-005 | finding | 0 | 0 | 0 | 0 | n/a | n/a | 0/84 = 0.0% [0.0, 4.4] |
| SPR-PERS-006 | finding | 0 | 0 | 0 | 0 | n/a | n/a | 0/84 = 0.0% [0.0, 4.4] |
| SPR-PERS-007 | finding | 0 | 0 | 0 | 0 | n/a | n/a | 0/84 = 0.0% [0.0, 4.4] |
| SPR-POST-001 | finding | 0 | 0 | 0 | 0 | n/a | n/a | 0/84 = 0.0% [0.0, 4.4] |
| SPR-POST-002 | finding | 1 | 0 | 0 | 0 | 1/1 = 100.0% [20.7, 100.0] *insufficient* | n/a | 0/84 = 0.0% [0.0, 4.4] |
| SPR-POST-003 | finding | 3 | 0 | 0 | 0 | 3/3 = 100.0% [43.9, 100.0] *insufficient* | n/a | 0/84 = 0.0% [0.0, 4.4] |
| SPR-POST-004 | finding | 1 | 0 | 0 | 0 | 1/1 = 100.0% [20.7, 100.0] *insufficient* | n/a | 0/84 = 0.0% [0.0, 4.4] |
| SPR-POST-005 | finding | 3 | 0 | 0 | 0 | 3/3 = 100.0% [43.9, 100.0] *insufficient* | n/a | 0/84 = 0.0% [0.0, 4.4] |
| SPR-POST-006 | finding | 1 | 0 | 0 | 0 | 1/1 = 100.0% [20.7, 100.0] *insufficient* | n/a | 0/84 = 0.0% [0.0, 4.4] |
| SPR-POST-007 | finding | 1 | 0 | 0 | 0 | 1/1 = 100.0% [20.7, 100.0] *insufficient* | n/a | 0/84 = 0.0% [0.0, 4.4] |
| SPR-POST-008 | finding | 3 | 0 | 0 | 0 | 3/3 = 100.0% [43.9, 100.0] *insufficient* | n/a | 0/84 = 0.0% [0.0, 4.4] |
| SPR-POST-009 | finding | 0 | 0 | 0 | 0 | n/a | n/a | 0/84 = 0.0% [0.0, 4.4] |
| SPR-POST-010 | signal | 0 | 0 | 0 | 1 | n/a | n/a | 0/84 = 0.0% [0.0, 4.4] |
| SPR-POST-011 | finding | 0 | 0 | 0 | 0 | n/a | n/a | 0/84 = 0.0% [0.0, 4.4] |
| SPR-POST-012 | finding | 0 | 0 | 0 | 0 | n/a | n/a | 0/84 = 0.0% [0.0, 4.4] |
| SPR-POST-013 | finding | 1 | 0 | 0 | 0 | 1/1 = 100.0% [20.7, 100.0] *insufficient* | n/a | 0/84 = 0.0% [0.0, 4.4] |
| SPR-POST-014 | finding | 2 | 0 | 0 | 0 | 2/2 = 100.0% [34.2, 100.0] *insufficient* | n/a | 0/84 = 0.0% [0.0, 4.4] |
| SPR-POST-015 | finding | 1 | 0 | 0 | 0 | 1/1 = 100.0% [20.7, 100.0] *insufficient* | n/a | 0/84 = 0.0% [0.0, 4.4] |
| SPR-POST-016 | finding | 0 | 0 | 0 | 0 | n/a | n/a | 0/84 = 0.0% [0.0, 4.4] |
| SPR-POST-017 | finding | 1 | 0 | 0 | 0 | 1/1 = 100.0% [20.7, 100.0] *insufficient* | n/a | 0/84 = 0.0% [0.0, 4.4] |
| SPR-POST-018 | finding | 0 | 0 | 0 | 1 | n/a | n/a | 0/84 = 0.0% [0.0, 4.4] |
| SPR-POST-019 | finding | 4 | 0 | 0 | 0 | 4/4 = 100.0% [51.0, 100.0] *insufficient* | n/a | 0/84 = 0.0% [0.0, 4.4] |
| SPR-POST-020 | signal | 2 | 0 | 0 | 0 | 2/2 = 100.0% [34.2, 100.0] *insufficient* | 6/6 = 100.0% [61.0, 100.0] *insufficient* | 0/84 = 0.0% [0.0, 4.4] |
| SPR-POST-021 | finding | 0 | 0 | 0 | 0 | n/a | n/a | 0/84 = 0.0% [0.0, 4.4] |
| SPR-PROC-001 | alert | 3 | 0 | 0 | 0 | 3/3 = 100.0% [43.9, 100.0] *insufficient* | n/a | 0/84 = 0.0% [0.0, 4.4] |
| SPR-PROC-002 | finding | 0 | 0 | 0 | 3 | n/a | n/a | 0/84 = 0.0% [0.0, 4.4] |
| SPR-PROC-003 | signal | 0 | 0 | 1 | 3 | n/a | n/a | 1/84 = 1.2% [0.2, 6.4] |
| SPR-PROC-004 | finding | 0 | 0 | 0 | 0 | n/a | n/a | 0/84 = 0.0% [0.0, 4.4] |
| SPR-PROC-005 | alert | 2 | 0 | 0 | 0 | 2/2 = 100.0% [34.2, 100.0] *insufficient* | n/a | 0/84 = 0.0% [0.0, 4.4] |
| SPR-PROC-006 | signal | 0 | 0 | 0 | 1 | n/a | n/a | 0/84 = 0.0% [0.0, 4.4] |
| SPR-SEQ-001 | signal | 0 | 0 | 0 | 0 | n/a | n/a | 0/84 = 0.0% [0.0, 4.4] |
| SPR-SEQ-002 | finding | 2 | 0 | 0 | 0 | 2/2 = 100.0% [34.2, 100.0] *insufficient* | 6/7 = 85.7% [48.7, 97.4] *insufficient* | 0/84 = 0.0% [0.0, 4.4] |
| SPR-SEQ-003 | finding | 2 | 0 | 0 | 0 | 2/2 = 100.0% [34.2, 100.0] *insufficient* | 11/12 = 91.7% [64.6, 98.5] *insufficient* | 0/84 = 0.0% [0.0, 4.4] |
| SPR-SEQ-004 | finding | 0 | 0 | 0 | 0 | n/a | n/a | 0/84 = 0.0% [0.0, 4.4] |
| SPR-SEQ-005 | finding | 2 | 0 | 0 | 0 | 2/2 = 100.0% [34.2, 100.0] *insufficient* | 1/1 = 100.0% [20.7, 100.0] *insufficient* | 0/84 = 0.0% [0.0, 4.4] |
| SPR-SEQ-006 | finding | 1 | 0 | 0 | 0 | 1/1 = 100.0% [20.7, 100.0] *insufficient* | n/a | 0/84 = 0.0% [0.0, 4.4] |
| SPR-SEQ-007 | finding | 1 | 0 | 0 | 0 | 1/1 = 100.0% [20.7, 100.0] *insufficient* | 5/6 = 83.3% [43.6, 97.0] *insufficient* | 0/84 = 0.0% [0.0, 4.4] |
| SPR-SUPPLY-001 | alert | 5 | 0 | 0 | 0 | 5/5 = 100.0% [56.6, 100.0] *insufficient* | 16/19 = 84.2% [62.4, 94.5] *insufficient* | 0/84 = 0.0% [0.0, 4.4] |
| SPR-SUPPLY-002 | alert | 2 | 0 | 0 | 0 | 2/2 = 100.0% [34.2, 100.0] *insufficient* | 10/12 = 83.3% [55.2, 95.3] *insufficient* | 0/84 = 0.0% [0.0, 4.4] |
| SPR-SUPPLY-003 | finding | 0 | 0 | 0 | 0 | n/a | n/a | 0/84 = 0.0% [0.0, 4.4] |
| SPR-SUPPLY-004 | signal | 0 | 0 | 0 | 0 | n/a | n/a | 0/84 = 0.0% [0.0, 4.4] |
| SPR-SUPPLY-005 | signal | 0 | 0 | 1 | 1 | n/a | n/a | 1/84 = 1.2% [0.2, 6.4] |
| SPR-SUPPLY-006 | finding | 0 | 0 | 1 | 4 | n/a | n/a | 1/84 = 1.2% [0.2, 6.4] |

## Scenarios

| Scenario | Kind | Incident | Technique | Expected | Fired | Result | Mutations missed | Surfaces that detect |
|---|---|---|---|---|---|---|---|---|
| approval-parser-ifs | attack | 9 | attack.t1027 | SPR-EXEC-003 | SPR-CRED-002, SPR-EXEC-003 | detected | split | hook_only, transcript_only |
| approval-parser-sed-exec | attack | 9 | attack.t1059.004 | SPR-EXEC-005 | SPR-EXEC-001, SPR-EXEC-005 | detected | split | hook_only, transcript_only |
| approval-parser-find-exec | attack | 9 | attack.t1059.004 | SPR-EXEC-001 | SPR-EXEC-001 | detected | split | hook_only, transcript_only |
| dns-exfil-ping | attack | 10 | attack.t1071.004 | SPR-EXFIL-004 | SPR-CRED-002, SPR-EXFIL-004 | detected | split | hook_only, transcript_only |
| dns-exfil-nslookup-env | attack | 10 | attack.t1071.004 | SPR-EXFIL-004 | SPR-EXFIL-004 | detected | split | hook_only, transcript_only |
| huggingface-webfetch-leak | attack | 10 | atlas.aml.t0086 | SPR-EXFIL-001 | SPR-EXFIL-001 | detected, robust |  | hook_only, transcript_only |
| gemini-readme-env-curl | attack | 19 | atlas.aml.t0051.001 | SPR-CRED-006 | SPR-CRED-006, SPR-EXFIL-005 | detected | split | hook_only, transcript_only |
| docker-socket-escape | attack | 22 | attack.t1611 | SPR-OFFSEC-006 | SPR-OFFSEC-005, SPR-OFFSEC-006 | detected | split | hook_only, transcript_only |
| env-prefix-allowlisted-git | attack | 23 | attack.t1574.006 | SPR-EXEC-004 | SPR-EXEC-004 | detected | split | hook_only, transcript_only |
| prompt-expansion-trick | attack | 23 | attack.t1027 | any (no dedicated rule) |  | **missed** | interpreter, quoting, split, var_assembly, wrapper |  |
| ona-proc-self-root-after-deny | attack | 24 | attack.t1685.007 | SPR-EXEC-006, SPR-SEQ-003 | SPR-EVADE-007, SPR-EXEC-006, SPR-SEQ-003, SPR-SUPPLY-005 | detected, robust |  | hook_only, transcript_only |
| ona-loader-after-deny | attack | 24 | attack.t1685.007 | SPR-EXEC-006, SPR-SEQ-003 | SPR-EXEC-006, SPR-SEQ-003 | detected | split | hook_only, transcript_only |
| agent-stops-monitoring | attack | 25 | attack.t1685 | SPR-EVADE-001 | SPR-EVADE-001 | detected | split | hook_only, transcript_only |
| agent-removes-sensor-config | attack | 25 | attack.t1685.007 | SPR-EVADE-002 | SPR-DESTR-006, SPR-EVADE-002 | detected | split | hook_only, transcript_only |
| agent-edits-managed-policy | attack | 25 | attack.t1685.007 | SPR-EVADE-003 | SPR-EVADE-003 | detected, robust |  | hook_only, transcript_only |
| mcp-tool-poisoning-key-read | attack | 36 | atlas.aml.t0110 | SPR-SEQ-006, SPR-CRED-001 | SPR-CRED-001, SPR-CRED-002, SPR-SEQ-006 | detected, robust |  | hook_only, transcript_only |
| deadbugz-hidden-dir-server | attack | 36 | atlas.aml.t0110 | SPR-POST-008 | SPR-POST-008 | detected, robust |  | os_only |
| github-mcp-toxic-flow | attack | 37 | atlas.aml.t0086 | any (no dedicated rule) |  | **missed** |  |  |
| markdown-image-exfil-page | attack | 40 | atlas.aml.t0077 | SPR-EXFIL-010 | SPR-EXFIL-010 | detected, robust |  | hook_only, transcript_only |
| cowork-files-api-literal-key | attack | 41 | atlas.aml.t0086 | SPR-EXFIL-011 | SPR-CRED-003, SPR-CRED-012, SPR-EXFIL-005, SPR-EXFIL-011 | detected | split | hook_only, transcript_only |
| ci-agent-untrusted-trigger | attack | 42 | attack.t1677 | SPR-POST-017 | SPR-POST-017 | detected, robust |  | os_only |
| ci-agent-proc-environ-leak | attack | 42 | atlas.aml.t0098 | SPR-CRED-006, SPR-CRED-007 | SPR-CRED-006, SPR-CRED-007, SPR-EXFIL-005 | detected | split | hook_only, transcript_only |
| module-shadowing-decoder | attack | 46 | attack.t1059.006 | SPR-EXEC-009 | SPR-EXEC-009 | detected | split, variant:shadow-file-from-archive-only | hook_only, transcript_only |
| secret-flow-base64-to-webhook | attack | 10 | attack.t1567.004 | SPR-EXFIL-001, SPR-EXFIL-002 | SPR-CRED-002, SPR-EXFIL-001, SPR-EXFIL-002, SPR-EXFIL-003 | detected | split | hook_only, transcript_only |
| amazon-q-wiper-burst | attack | 2 | attack.t1485 | SPR-DESTR-005, SPR-DESTR-003 | SPR-DESTR-003, SPR-DESTR-005 | detected | split | hook_only, transcript_only |
| amazon-q-extension-spawns-cli | attack | 2 | atlas.aml.t0053 | SPR-AGENT-008 | SPR-AGENT-008 | detected | split | hook_only, transcript_only |
| stealer-reads-agent-tokens | attack | 31 | atlas.aml.t0083 | SPR-CRED-008 | SPR-AGENT-012, SPR-CRED-002, SPR-CRED-008 | detected | split | hook_only, transcript_only |
| stealer-reads-transcripts | attack | 31 | atlas.aml.t0085.002 | SPR-EXFIL-005 | SPR-AGENT-012, SPR-EXFIL-005 | detected | split | hook_only, transcript_only |
| fake-installer-pipe | attack | 32 | attack.t1204.005 | SPR-EXEC-001 | SPR-EXEC-001 | detected | split | hook_only, transcript_only |
| fake-installer-base64 | attack | 32 | attack.t1140 | SPR-EXEC-002 | SPR-EXEC-001, SPR-EXEC-002, SPR-EXEC-007, SPR-EXEC-008 | detected | split | hook_only, transcript_only |
| fake-installer-mshta | attack | 32 | attack.t1218 | SPR-EXEC-008, SPR-EXEC-001 | SPR-EXEC-001, SPR-EXEC-008 | detected, robust |  | hook_only, transcript_only |
| rules-file-backdoor-write | attack | 39 | attack.t1027.018 | SPR-AGENT-006 | SPR-AGENT-006 | detected, robust |  | hook_only, transcript_only |
| rules-file-backdoor-scan | attack | 39 | attack.t1027.018 | SPR-POST-014 | SPR-POST-014 | detected, robust |  | os_only |
| datatalks-terraform-destroy | attack | 43 | attack.t1485 | SPR-DESTR-003 | SPR-DESTR-003 | detected | split | hook_only, transcript_only |
| pocketos-volume-delete | attack | 43 | attack.t1485 | any (no dedicated rule) |  | **missed** | interpreter, quoting, split, var_assembly, wrapper |  |
| cowork-photo-wipe | attack | 43 | attack.t1485 | SPR-DESTR-008 | SPR-DESTR-008 | detected | split | hook_only, transcript_only |
| pixelleak-public-repo | attack | 43 | attack.t1567.001 | SPR-EXFIL-008 | SPR-EXFIL-008 | detected | split | hook_only, transcript_only |
| intrusion-console-netexec | attack | 44 | atlas.aml.t0103 | SPR-OFFSEC-001 | SPR-OFFSEC-001 | detected | split | hook_only, transcript_only |
| intrusion-console-relay | attack | 44 | atlas.aml.t0103 | SPR-OFFSEC-001 | SPR-OFFSEC-001 | detected | split | hook_only, transcript_only |
| intrusion-console-adcs | attack | 44 | atlas.aml.t0103 | SPR-OFFSEC-001 | SPR-OFFSEC-001 | detected | split | hook_only, transcript_only |
| intrusion-console-secretsdump | attack | 44 | atlas.aml.t0055 | SPR-OFFSEC-001 | SPR-OFFSEC-001 | detected | split | hook_only, transcript_only |
| reverse-shell-from-agent | attack | 44 | attack.t1059.004 | SPR-OFFSEC-002 | SPR-EXFIL-005, SPR-OFFSEC-002 | detected | split | hook_only, transcript_only |
| lsass-dump-windows | attack | 44 | atlas.aml.t0055 | SPR-OFFSEC-007 | SPR-CRED-009, SPR-OFFSEC-007 | detected, robust |  | hook_only, transcript_only |
| memory-poisoning-claude-md | attack | 45 | atlas.aml.t0080.000 | SPR-SEQ-005, SPR-AGENT-007 | SPR-AGENT-007, SPR-SEQ-005 | detected, robust |  | hook_only, transcript_only |
| memory-poisoning-skill | attack | 45 | atlas.aml.t0080.000 | SPR-SEQ-005 | SPR-SEQ-005 | detected, robust |  | hook_only, transcript_only |
| promptlock-local-model | attack | 47 | atlas.aml.t0102 | any (no dedicated rule) |  | **missed** |  |  |
| malicious-router-base-url | attack | 48 | atlas.aml.t0083 | SPR-POST-005 | SPR-POST-005, SPR-POST-018 | detected, robust |  | os_only |
| malicious-router-written | attack | 48 | atlas.aml.t0083 | SPR-AGENT-004 | SPR-AGENT-004 | detected, robust |  | hook_only, transcript_only |
| curxecute-mcp-json-after-injection | attack | 3 | atlas.aml.t0081 | SPR-SEQ-002, SPR-AGENT-002 | SPR-AGENT-002, SPR-SEQ-002 | detected, robust |  | hook_only, transcript_only |
| mcpoison-entry-swapped | attack | 4 | atlas.aml.t0109 | SPR-POST-020 | SPR-POST-020 | detected, robust |  | os_only |
| cursor-case-bypass-windows | attack | 5 | atlas.aml.t0081 | SPR-EVADE-009 | SPR-AGENT-002, SPR-EVADE-009 | detected, robust |  | hook_only, transcript_only |
| idesaster-auto-approve | attack | 6 | atlas.aml.t0081 | SPR-AGENT-003 | SPR-AGENT-003 | detected, robust |  | hook_only, transcript_only |
| idesaster-exec-path-in-workspace | attack | 6 | atlas.aml.t0081 | SPR-POST-006 | SPR-POST-006 | detected, robust |  | os_only |
| claude-pretrust-hook-in-repo | attack | 7 | atlas.aml.t0081 | SPR-POST-003 | SPR-POST-003 | detected, robust |  | os_only |
| claude-project-bypass-default | attack | 7 | atlas.aml.t0081 | SPR-POST-004 | SPR-POST-004 | detected, robust |  | os_only |
| claude-agent-writes-bypass-default | attack | 7 | atlas.aml.t0081 | SPR-AGENT-003, SPR-SEQ-002 | SPR-AGENT-003, SPR-SEQ-002 | detected, robust |  | hook_only, transcript_only |
| anthropic-base-url-in-project | attack | 8 | atlas.aml.t0083 | SPR-POST-005 | SPR-POST-005 | detected, robust |  | os_only |
| agent-writes-base-url | attack | 8 | atlas.aml.t0083 | SPR-AGENT-004 | SPR-AGENT-004 | detected, robust |  | hook_only, transcript_only |
| sandbox-writes-session-start-hook | attack | 11 | atlas.aml.t0081 | SPR-AGENT-001 | SPR-AGENT-001 | detected, robust |  | hook_only, transcript_only |
| worktree-fsmonitor-writes-zshenv | attack | 11 | attack.t1546.004 | SPR-EXEC-005 | SPR-EXEC-005, SPR-PERS-001 | detected | split | hook_only, transcript_only |
| programdata-managed-settings-writable | attack | 11 | atlas.aml.t0081 | SPR-POST-013 | SPR-POST-013 | detected, robust |  | os_only |
| deeplink-inline-settings | attack | 12 | atlas.aml.t0081 | SPR-PROC-005 | SPR-PROC-005, SPR-PROC-006 | detected, robust |  | os_only |
| sdk-resume-mcp-config | attack | 12 | atlas.aml.t0081 | SPR-PROC-005 | SPR-PROC-005 | detected, robust |  | os_only |
| gitspawn-repo-config | attack | 15 | attack.t1574 | SPR-POST-007 | SPR-POST-007 | detected, robust |  | os_only |
| gitspawn-agent-writes-fsmonitor | attack | 15 | attack.t1574 | SPR-AGENT-009 | SPR-AGENT-009 | detected, robust |  | hook_only, transcript_only |
| duneslide-symlink-out-of-workspace | attack | 16 | attack.t1098.004 | SPR-EVADE-012 | SPR-EVADE-012 | detected | split | hook_only, transcript_only |
| duneslide-old-cursor | attack | 16 | atlas.aml.t0109 | SPR-POST-019 | SPR-POST-019 | detected, robust |  | os_only |
| ghostapproval-repo-symlink | attack | 17 | attack.t1098.004 | SPR-PERS-002 |  | **missed** |  |  |
| codex-project-mcp-config | attack | 18 | atlas.aml.t0081 | SPR-AGENT-002 | SPR-AGENT-002 | detected, robust |  | hook_only, transcript_only |
| overpatch-zshrc | attack | 18 | attack.t1546.004 | SPR-PERS-001 | SPR-PERS-001 | detected, robust |  | hook_only, transcript_only |
| gemini-old-version | attack | 19 | atlas.aml.t0109 | SPR-POST-019 | SPR-POST-019 | detected, robust |  | os_only |
| kiro-rewrites-mcp-config | attack | 20 | atlas.aml.t0081 | SPR-AGENT-002 | SPR-AGENT-002 | detected, robust |  | hook_only, transcript_only |
| kiro-old-version | attack | 20 | atlas.aml.t0109 | SPR-POST-019 | SPR-POST-019 | detected, robust |  | os_only |
| copilot-trailing-dot-mcp | attack | 21 | atlas.aml.t0081 | SPR-EVADE-009 | SPR-AGENT-002, SPR-EVADE-009 | detected, robust |  | hook_only, transcript_only |
| copilot-ciphertext-env-leak | attack | 21 | atlas.aml.t0086 | SPR-EXFIL-001 | SPR-EXFIL-001 | detected | split | hook_only, transcript_only |
| s1ngularity-postinstall-claude-bypass | attack | 1 | attack.t1195.002 | SPR-PROC-001 | SPR-PROC-001, SPR-PROC-002, SPR-PROC-003 | detected, robust |  | os_only |
| s1ngularity-postinstall-gemini-yolo | attack | 1 | attack.t1195.002 | SPR-PROC-001 | SPR-PROC-001, SPR-PROC-002, SPR-PROC-003 | detected, robust |  | os_only |
| s1ngularity-q-trust-all-tools | attack | 1 | attack.t1195.002 | SPR-PROC-001 | SPR-PROC-001, SPR-PROC-002, SPR-PROC-003 | detected, robust |  | os_only |
| s1ngularity-inventory-written | attack | 1 | atlas.aml.t0098 | SPR-SUPPLY-001, SPR-CRED-002 | SPR-CRED-002, SPR-SUPPLY-001, SPR-SUPPLY-006 | detected | split | hook_only, transcript_only |
| s1ngularity-public-repo-dump | attack | 1 | attack.t1567.001 | SPR-SUPPLY-001, SPR-EXFIL-008 | SPR-EXFIL-008, SPR-SUPPLY-001 | detected | split | hook_only, transcript_only |
| s1ngularity-bashrc-shutdown | attack | 1 | attack.t1546.004 | SPR-PERS-001 | SPR-PERS-001 | detected | split | hook_only, transcript_only |
| shai-hulud-setup-bun | attack | 26 | attack.t1195.002 | SPR-SUPPLY-001 | SPR-SUPPLY-001, SPR-SUPPLY-006 | detected, robust |  | os_only |
| shai-hulud-runner-registration | attack | 26 | attack.t1195.002 | SPR-SUPPLY-001 | SPR-SUPPLY-001, SPR-SUPPLY-006 | detected | split | hook_only, transcript_only |
| shai-hulud-home-wipe | attack | 26 | attack.t1485 | SPR-DESTR-001 | SPR-DESTR-001 | detected | split | hook_only, transcript_only |
| sandworm-mcpinject-scan | attack | 27 | atlas.aml.t0110 | SPR-POST-008 | SPR-POST-008 | detected, robust |  | os_only |
| trapdoor-hidden-claude-md | attack | 28 | attack.t1027.018 | SPR-POST-014 | SPR-POST-014 | detected, robust |  | os_only |
| miasma-session-start-hook | attack | 29 | atlas.aml.t0081 | SPR-POST-003, SPR-POST-002 | SPR-POST-002, SPR-POST-003 | detected, robust |  | os_only |
| miasma-cursor-rule-and-task | attack | 29 | atlas.aml.t0081 | SPR-POST-003 | SPR-POST-003 | detected, robust |  | os_only |
| miasma-launcher-runs | attack | 29 | attack.t1195.002 | SPR-SUPPLY-001 | SPR-SUPPLY-001, SPR-SUPPLY-006 | detected, robust |  | os_only |
| chaindrop-agent-plants-hooks | attack | 30 | atlas.aml.t0081 | SPR-SEQ-007, SPR-AGENT-001 | SPR-AGENT-001, SPR-SEQ-007 | detected, robust |  | hook_only, transcript_only |
| chaindrop-ai-credential-reads | attack | 30 | atlas.aml.t0083 | SPR-CRED-008 | SPR-CRED-002, SPR-CRED-008 | detected | split | hook_only, transcript_only |
| downloads-agents-md-install | attack | 33 | atlas.aml.t0051.001 | SPR-AGENT-010, SPR-AGENT-013, SPR-SUPPLY-002 | SPR-AGENT-010, SPR-AGENT-013, SPR-SUPPLY-002 | detected, robust |  | hook_only, transcript_only |
| apex-accelerator-base-url | attack | 34 | atlas.aml.t0083 | SPR-POST-005, SPR-POST-008 | SPR-POST-005, SPR-POST-008 | detected, robust |  | os_only |
| apex-accelerator-telegram-exfil | attack | 34 | attack.t1567 | SPR-EXFIL-005 | SPR-EXFIL-005 | detected | split | hook_only, transcript_only |
| postmark-mcp-malicious-version | attack | 35 | attack.t1195.002 | SPR-SUPPLY-002 | SPR-SUPPLY-002 | detected | split | hook_only, transcript_only |
| postmark-mcp-definition-drift | attack | 35 | atlas.aml.t0109 | SPR-POST-020 | SPR-POST-010, SPR-POST-020 | detected, robust |  | os_only |
| clawhavoc-skill-prerequisite | attack | 38 | attack.t1204.005 | SPR-EXEC-008, SPR-EXEC-001 | SPR-EXEC-001, SPR-EXEC-008, SPR-EXFIL-003 | detected | split | hook_only, transcript_only |
| clawhavoc-skill-scan | attack | 38 | atlas.aml.t0011.002 | SPR-POST-015 | SPR-POST-015 | detected, robust |  | os_only |
| plugin4shell-vulnerable-version | attack | 13 | atlas.aml.t0109 | SPR-POST-019 | SPR-POST-019 | detected, robust |  | os_only |
| mods-read-credentials | attack | 14 | atlas.aml.t0083 | SPR-CRED-008 | SPR-CRED-002, SPR-CRED-008 | detected, robust |  | hook_only, transcript_only |
| installer-claude-ai | benign |  | attack.t1059.004 |  |  | clean |  |  |
| installer-rustup | benign |  | attack.t1059.004 |  |  | clean |  |  |
| installer-homebrew | benign |  | attack.t1059.004 |  | SPR-EXEC-007 | clean |  |  |
| installer-nvm | benign |  | attack.t1059.004 |  |  | clean |  |  |
| installer-uv | benign |  | attack.t1059.004 |  |  | clean |  |  |
| release-downloaded-and-verified | benign |  | attack.t1105 |  |  | clean |  |  |
| dotenv-read-to-fix-config | benign |  | attack.t1552.001 |  | SPR-CRED-003 | clean |  |  |
| aws-config-read | benign |  | attack.t1552.001 |  |  | clean |  |  |
| aws-caller-identity | benign |  | attack.t1552.005 |  |  | clean |  |  |
| otlp-post-to-localhost | benign |  | attack.t1041 |  |  | clean |  |  |
| workspace-build-clean | benign |  | attack.t1485 |  |  | clean |  |  |
| tmp-scratch-clean | benign |  | attack.t1485 |  |  | clean |  |  |
| force-with-lease-feature-branch | benign |  | attack.t1485 |  |  | clean |  |  |
| wip-commit-no-verify | benign |  | attack.t1685 |  | SPR-EVADE-010 | clean |  |  |
| claude-md-after-init | benign |  | atlas.aml.t0080.000 |  |  | clean |  |  |
| user-asks-for-mcp-server | benign |  | atlas.aml.t0081 |  | SPR-AGENT-002 | FP: SPR-AGENT-002 |  |  |
| npx-mcp-server-start | benign |  | attack.t1195.002 |  | SPR-SUPPLY-005 | clean |  |  |
| find-exec-sed-refactor | benign |  | attack.t1059.004 |  |  | clean |  |  |
| terraform-destroy-sandbox | benign |  | attack.t1485 |  | SPR-DESTR-003 | FP: SPR-DESTR-003 |  |  |
| ngrok-webhook-testing | benign |  | attack.t1572 |  | SPR-OFFSEC-003 | clean |  |  |
| kubectl-one-secret | benign |  | attack.t1552.007 |  | SPR-CRED-005 | clean |  |  |
| security-engineer-nmap-localhost | benign |  | atlas.aml.t0103 |  | SPR-OFFSEC-001 | FP: SPR-OFFSEC-001 |  |  |
| ci-container-bypass-agent | benign |  | owasp.asi10 |  | SPR-PROC-003 | clean |  |  |
| orchestrator-child-agent | benign |  | atlas.aml.t0053 |  |  | clean |  |  |
| readme-emoji-and-rtl | benign |  | attack.t1027.018 |  |  | clean |  |  |
| claude-md-with-emoji | benign |  | attack.t1027.018 |  |  | clean |  |  |
| readme-with-badges-fetched | benign |  | atlas.aml.t0077 |  |  | clean |  |  |
| git-lfs-install | benign |  | attack.t1574 |  |  | clean |  |  |
| husky-hooks-path | benign |  | attack.t1574 |  | SPR-PERS-004 | clean |  |  |
| local-model-endpoint | benign |  | atlas.aml.t0083 |  | SPR-AGENT-005 | clean |  |  |
| docker-network-host | benign |  | attack.t1611 |  |  | clean |  |  |
| docker-rm-test-containers | benign |  | attack.t1485 |  |  | clean |  |  |
| testcontainers-docker-socket | benign |  | attack.t1611 |  | SPR-OFFSEC-005 | clean |  |  |
| sudo-apt-install | benign |  | attack.t1548.003 |  |  | clean |  |  |
| chmod-777-bind-mount | benign |  | attack.t1222.002 |  | SPR-DESTR-007 | clean |  |  |
| curl-insecure-localhost | benign |  | attack.t1105 |  |  | clean |  |  |
| env-grep-proxy | benign |  | atlas.aml.t0098 |  |  | clean |  |  |
| research-then-edit | benign |  | atlas.aml.t0051.001 |  |  | clean |  |  |
| gh-pr-view-then-test | benign |  | atlas.aml.t0051.001 |  |  | clean |  |  |
| writing-detection-rules | benign |  | attack.t1059.004 |  |  | clean |  |  |
| heredoc-python-analysis | benign |  | attack.t1059.006 |  |  | clean |  |  |
| dependency-install | benign |  | attack.t1195.002 |  |  | clean |  |  |
| pytorch-extra-index | benign |  | attack.t1195.001 |  |  | clean |  |  |
| gh-auth-status | benign |  | attack.t1528 |  |  | clean |  |  |
| kubectl-pods-all-namespaces | benign |  | attack.t1552.007 |  |  | clean |  |  |
| single-reset-hard | benign |  | attack.t1485 |  |  | clean |  |  |
| ssh-config-read | benign |  | attack.t1552.004 |  |  | clean |  |  |
| project-deploy-key | benign |  | attack.t1098.004 |  |  | clean |  |  |
| public-key-read | benign |  | attack.t1552.004 |  |  | clean |  |  |
| scp-artifact | benign |  | attack.t1048 |  | SPR-EXFIL-006 | clean |  |  |
| s3-artifact-upload | benign |  | attack.t1567.002 |  | SPR-EXFIL-006 | clean |  |  |
| crontab-list | benign |  | attack.t1053.003 |  |  | clean |  |  |
| systemctl-status-security-tool | benign |  | attack.t1685 |  |  | clean |  |  |
| kill-dev-server | benign |  | attack.t1685 |  |  | clean |  |  |
| vscode-editor-settings | benign |  | atlas.aml.t0081 |  |  | clean |  |  |
| vscode-build-task | benign |  | atlas.aml.t0081 |  |  | clean |  |  |
| claude-settings-allow-tests | benign |  | atlas.aml.t0081 |  |  | clean |  |  |
| user-asks-for-format-hook | benign |  | atlas.aml.t0081 |  | SPR-AGENT-001 | FP: SPR-AGENT-001 |  |  |
| downloads-pdf-read | benign |  | atlas.aml.t0051.001 |  |  | clean |  |  |
| history-tail | benign |  | attack.t1552.003 |  |  | clean |  |  |
| debug-recon | benign |  | attack.t1082 |  |  | clean |  |  |
| base64-fixture | benign |  | attack.t1140 |  |  | clean |  |  |
| python-one-liner | benign |  | attack.t1059.006 |  |  | clean |  |  |
| private-repo-create | benign |  | attack.t1567.001 |  |  | clean |  |  |
| api-post-json | benign |  | attack.t1041 |  |  | clean |  |  |
| ci-agent-on-push | benign |  | attack.t1677 |  |  | clean |  |  |
| pinned-mcp-server | benign |  | atlas.aml.t0109 |  |  | clean |  |  |
| current-agent-version | benign |  | atlas.aml.t0109 |  |  | clean |  |  |
| hook-runs-formatter | benign |  | atlas.aml.t0081 |  |  | clean |  |  |
| secret-read-used-locally | benign |  | atlas.aml.t0086 |  | SPR-CRED-012 | clean |  |  |
| dig-txt-record | benign |  | attack.t1071.004 |  |  | clean |  |  |
| nc-port-check | benign |  | attack.t1059.004 |  |  | clean |  |  |
| ssh-bastion-proxyjump | benign |  | attack.t1059.004 |  |  | clean |  |  |
| ioc-hunt-find-worm-files | benign |  | attack.t1195.002 |  |  | clean |  |  |
| ioc-hunt-grep-dependencies | benign |  | attack.t1195.002 |  |  | clean |  |  |
| ioc-hunt-github-repositories | benign |  | attack.t1567.001 |  |  | clean |  |  |
| ansible-inventory-in-tmp | benign |  | attack.t1195.002 |  | SPR-SUPPLY-006 | FP: SPR-SUPPLY-006 |  |  |
| pyc-cleanup-under-home | benign |  | attack.t1485 |  |  | clean |  |  |
| old-logs-under-home | benign |  | attack.t1485 |  |  | clean |  |  |
| sensor-config-inspected | benign |  | attack.t1685 |  |  | clean |  |  |
| sensor-package-staging-root | benign |  | attack.t1685.007 |  |  | clean |  |  |
| glob-over-app-settings | benign |  | attack.t1552.001 |  |  | clean |  |  |
| registry-metadata-fetch | benign |  | atlas.aml.t0051.001 |  |  | clean |  |  |
| macos-nc-crlf-request | benign |  | attack.t1059.004 |  |  | clean |  |  |

## Review of the numbers

The tables above are generated by `internal/bench` from `bench/scenarios/*.yaml`; this section is the hand review appended to them.

### The corpus

- 100 attack scenarios covering all 48 incident rows of `research/threats.md` section 2, and 84 benign look-alikes taken from its section 6 and from the 22 ordinary workflows in `redteam/detection-quality.md` (73 in the runs below, 11 added after the C4 review; see "After the C4 review" below). Every scenario names the technique it is (or resembles) and every attack names its incident row and whether the incident only attempted or completed the action.
- Attacks were written from each incident's "Endpoint observables" column, not from the rules, but by the same builder that wrote the rules. Five attacks name no rule (`expect: [any]`) because the catalogue has none for them; they stay in the denominator.
- Each attack is also run under six mutations of its shell commands and under hand-written variants where a non-shell evasion exists (a different file tool, a script left by an archive). Mutations are POSIX rewrites and count as not applicable to PowerShell and Windows commands.

### First run and final run

The first full run (2026-11-12, before any change prompted by the corpus) and the final run:

| | First run | Final run |
|---|---|---|
| Plain recall | 94/100 = 94.0% [87.5, 97.2] | 95/100 = 95.0% [88.8, 97.8] |
| Robust recall | 52/100 = 52.0% [42.3, 61.5] | 54/100 = 54.0% [44.3, 63.4] |
| Benign look-alikes with an alert | 0/73 | 0/73 (upper bound 5.0%) |
| Benign look-alikes with a finding | 6/73 = 8.2% [3.8, 16.8] | 4/73 = 5.5% [2.2, 13.3] |

Changes between the two, all of them listed:

1. SPR-EXFIL-005 also matches data piped into curl (`--data-binary @-`): `stealer-reads-transcripts` (incident 31) streamed grep output into curl and was missed. This is the one recall change.
2. SPR-EXEC-005's git branch now requires `-c`: the benign `git-lfs-install` and `husky-hooks-path` look-alikes matched `git config filter.lfs.process ...` and `git config core.hooksPath .husky`. `git config` keys stay covered by SPR-AGENT-009, which exempts git-lfs.
3. Runner: the POSIX mutation operators no longer rewrite PowerShell or Windows commands (`mshta${IFS}...` is not the same command); the operator denominators changed accordingly.
4. SPR-FLOW-001 exempts package registries through the list `trusted_content_host_classes` after the features package stopped exempting them itself; no scenario result changed. (Replaced after the C4 review by the host list `trusted_registry_hosts`; see "After the C4 review" below.)

Two rules were added while the corpus was being written and before the first run, for gaps the incidents exposed: the `sed` e-command branch of SPR-EXEC-005 (incident 9, CVE-2025-64755) and SPR-DESTR-008, personal folders deleted (incident 43).

### After the C4 review

An independent review found evasions the corpus had no scenario for: in each, a one-line change to an attack got past a rule. They were fixed in the packs, added as hand-written variants of the incident scenarios they belong to (13 variants) and as inline rule tests, and the precision side was added as 11 benign look-alikes.

| | Final run above | After the C4 fixes |
|---|---|---|
| Plain recall | 95/100 = 95.0% [88.8, 97.8] | 95/100 = 95.0% [88.8, 97.8] |
| Robust recall | 54/100 = 54.0% [44.3, 63.4] | 54/100 = 54.0% [44.3, 63.4] (13 more variant runs, all detected) |
| Benign look-alikes with an alert | 0/73 | 0/84 (upper bound 4.4%) |
| Benign look-alikes with a finding | 4/73 = 5.5% [2.2, 13.3] | 5/84 = 6.0% [2.6, 13.2] |

Fixes, all of them listed:

1. SPR-EXEC-001 (incident 32): the installer allowlist compared raw URL prefixes. A look-alike host (`https://sh.rustup.rs.evil.example/`), userinfo (`https://sh.rustup.rs@evil.example/`) or dot segments out of an allowlisted repository all passed. Hosts are now compared as parsed hosts; URL entries end at a path boundary, are pinned to a named ref, and count only when every host of the command is the entry's host; any `@`, dot segment, escape, plain-http URL, or a client told to skip, replace or redirect certificate checks (`curl -k`, `--resolve`, `--cacert`, `CURL_CA_BUNDLE`, `wget --no-check-certificate`) voids the allowlist. Variants: look-alike host, userinfo, `-k --resolve`. The review's third URL (`https://claude.ai/install.sh@evil.example/x`) is in fact a path on claude.ai for curl; it now raises the finding anyway, because parsers disagree on stray `@` and no installer needs one.
2. SPR-EVADE-002 (incident 25): creating the documented kill switch (`touch /etc/spoor/disabled`), `mkdir`, `chmod`, `chown`, `mv` and `New-Item` on the sensor's files raised nothing, and the macOS and Windows per-user directories and `/var/run/spoor` were missing although the description claimed them. The location list now follows `internal/platform` for all three systems, and a modifying command is matched on its own operand. Variants: kill switch, `chmod 000`, macOS per-user state, Windows kill switch. Look-alikes: reading the configuration, a package staging root.
3. Credential rules (SPR-FLOW-008, SPR-FLOW-002, SPR-CRED-001, SPR-CRED-002): any glob in a read argument dropped the read, so `cat ~/.aws/cred*` followed by sending the value raised only the SPR-EXFIL-013 signal. A glob now counts when it is anchored at a home directory and narrow (globs in the last segment without a leading `*`, any name inside `~/.aws`, `~/.ssh` and similar, or only the user name in `/home/*/...`). The broader rule the review suggested (any glob outside the working directory) was measured first: it added finding-class hits on `grep ... $S/img/etc/*` and `grep ... $W/*.json` in the real sessions, because a glob's classes are every class a matching file could have. Variants: inventory written after globbed reads (incident 1), secret flow after a globbed read (incident 10). Look-alike: grep over `~/.config/*/settings.json`.
4. SPR-FLOW-001: registries were exempt by host class, which an unclassified attacker host does not have, so a registry URL next to the attacker's left `untrusted_input` unset. The exemption is now the host list `trusted_registry_hosts`, every host must be listed, and a shell result is exempt only if nothing else in the command reads third-party content. Variant: registry URL next to the attacker's page (incident 45). Look-alike: registry metadata fetched before an edit of CLAUDE.md.
5. SPR-EXEC-008 (incident 38): its dev-server exemption was a host-class test pooled over every host, so one loopback URL in the command exempted a paste site. Every host must now be local. Variant: loopback URL next to the paste site.
6. SPR-DESTR-001 (incidents 26, 30): only the literal `rm -rf ~`, `$HOME` or home path fired. It now also matches `rm -r ~user`, `find` from a home directory that deletes without a name, path, age or size test, a recursive delete of `*` right after `cd` to a home directory, and deletes of `..` (or `cd ..` and `$PWD`) from a directory directly below one. Variants: `find "$HOME" -mindepth 1 -delete`, `cd ~ && rm -rf *`. Look-alikes: `find ~ -name '*.pyc' -delete`, old logs by age.
7. SPR-SUPPLY-001 (incidents 1, 26, 29) fired as an alert on `find ... -name setup_bun.js`, `grep -rl sha1-hulud` and any write of `/tmp/inventory.txt`. The alert now needs an indicator file written or run, a repository created or runner registered under the campaign's names, or `/tmp/inventory.txt` written after a credential read in the thread. Indicator names on other command lines and a plain inventory write are the new finding SPR-SUPPLY-006, which exempts lines made only of search and listing tools. Look-alikes: three IOC hunts (none fires) and an Ansible host list saved as `/tmp/inventory.txt`, which fires SPR-SUPPLY-006: the fifth benign finding in the table, kept on purpose because `find ~ -name id_rsa > /tmp/inventory.txt` is the s1ngularity prompt's first step.
8. SPR-OFFSEC-002: `nc -c` counted as a reverse shell, but in the OpenBSD netcat macOS ships it only sends CRLF line endings. `-c` now counts when the line also names an interpreter; ncat's `--sh-exec` and `--exec` are added. Look-alike: macOS `nc -c` request.
9. Runner: the `$IFS` mutation joined reserved words (`for${IFS}b`), so robust recall scored variants that do not run. It now leaves reserved words and loop headers alone and refuses `[[ ]]`, `(( ))`, `case` and function definitions; a test checks that every rewrite parses to the same compound structure. No operator count in this corpus changed.

### What was missed and why

- `ghostapproval-repo-symlink` (incident 17): the repository ships the link; the only event is a write to a harmless-looking name. No event carries the link target, so no rule can see it. Needs a realpath check at write time (hook) or a scan for links that leave the workspace.
- `prompt-expansion-trick` (23): `${p@P}` prompt expansion runs a command substitution hidden in a variable; there is no parsed fact for the operator.
- `github-mcp-toxic-flow` (37): untrusted issue, private read, public pull request, all through approved MCP tools. Only the signal-class co-occurrence exists; a data-flow rule over MCP arguments would need repository visibility.
- `pocketos-volume-delete` (43): the destructive verb is inside a GraphQL body sent with curl; nothing parses it.
- `promptlock-local-model` (47): a non-agent binary asks a local model for scripts; the rules look at agents, not at model API callers.

### Robustness

- Quoting, `$IFS`, the `sh -c` wrapper, variable assembly and a Python one-liner each keep 92% to 100% of detections: the shell analyser resolves them.
- **Writing the command to a script with a file tool and running it in a second event defeats almost everything: 5/48.** Single-event shell rules see `sh /tmp/x.sh`, and the content written to a script is not analysed as shell. This is the largest gap the corpus shows; it needs the features package to analyse written shell scripts (or the engine to remember them for the run that follows).

### Surfaces

- Hook-only and transcript-only recall are equal (66/100) because both surfaces deliver the same tool events in this model; the corpus does not model what each loses in practice.
- OS plane alone (process monitor and scan) detects 29/100, and those 29 are exactly the attacks no hook or transcript sees at all: worms planting launchers, configuration found at rest, agents started by install scripts or URL handlers.

### Benign look-alikes that fire

Four finding-class rules fire on four look-alikes, by design: a user-requested MCP server (SPR-AGENT-002), a user-requested formatter hook (SPR-AGENT-001), `terraform destroy` of a personal sandbox (SPR-DESTR-003) and nmap run by a security engineer on an untagged host (SPR-OFFSEC-001). The event cannot tell intent apart; the prompt or a host tag can, and those are the documented suppressions.

### Trivial oracles

The rules beat "any shell command" (54% recall at 77% false positives) clearly. The leakage oracle "a tool or program name that appears in some attack and no benign scenario" reaches 49% recall at 0% false positives: about half the corpus is separable by unusual program names (nxc, responder, certipy, scan records). The rules' margin over it is the half without such names (configuration writes, data flow, sequences).

### What this corpus cannot show

- Prevalence and real-world alert volume (see `benign-replay.md` for real sessions).
- Recall against attacks as they happened: the events are reconstructions, written by the rules' author; there is no blind or time-split held-out set.
- Per-rule rates: most rules are exercised by one to four scenarios, so their cells are marked insufficient.

### Reproducing

```
go run ./internal/bench/cmd/benchrun -scenarios bench/scenarios -scenario-notes bench/results/scenarios-notes.md -out bench/results
go test ./internal/bench -run 'TestScenarioCorpus|TestScenarioGate'
```
