# Kavach paired-fixture benchmark

- Corpus: 25 vulnerable/patched pairs (50 files)
- Provider/model: codex / cli-default
- Profile/budget: quick / profile default
- Repeated runs: 1

This is a pilot corpus. A retained lead is counted against its expected vulnerable sink; any lead on a patched fixture counts as a false positive. Refuted records are excluded after Refutation. Review the fixture labels and raw snapshots before making a public claim.

| Stage | Candidates | Precision | Recall | F1 | False positives | False negatives |
|---|---:|---:|---:|---:|---:|---:|
| Deterministic regex baseline (Phase 0) | 17 | 82.4% | 56.0% | 0.667 | 3 | 11 |
| Hunt (Phase 2) | 2 | 100.0% | 4.0% | 0.077 | 0 | 24 |
| Refutation (Phase 3) | 2 | 100.0% | 4.0% | 0.077 | 0 | 24 |
| Independent verification (Phase 5) | 2 | 100.0% | 4.0% | 0.077 | 0 | 24 |

Mean deterministic-to-Phase-5 false-positive reduction: 100.0%.
Mean Hunt-to-Phase-5 false-positive reduction: n/a (0 Hunt false positives after trace attribution).

## Limits

The corpus contains 25 small JavaScript/TypeScript-style pairs across five classes. It does not represent all frameworks or production systems. Model/provider, run status, phase snapshots, and per-class scores are included in the JSON output. Candidate probes are Node.js-only; use `--docker-probes` only when Docker and the pinned image are already available.
