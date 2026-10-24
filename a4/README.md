# Assignment 4: empirical study of the tamper-evidence mechanism

Course project (Research Methods and Tools, Assignment 4). The study tests the integrity mechanisms of this
prototype against 17 predefined attacks and benchmarks their write time and storage overhead.
The report is a separate LaTeX document; this folder holds the code and the evidence.

| File | Content |
|---|---|
| `run_a4.py` | One command for the whole study: environment record, code check against commit `d753388`, unit tests, attack suite, benchmark (3 warm-up + 20 rounds, Latin-square order), figures. |
| `make_figures.py` | Figures from the CSV files of a run. |
| `anonymize_evidence.py` | Replaces user and host names in the evidence files with `<user>` / `<host>`. |
| `make_reference.py`, `reference_d753388/` | Snapshot of the five prototype files of commit `d753388` that `run_a4.py` compares with. |
| `inventory.md` | Code inventory and the expected outcome of every attack, written before the run (Russian). |
| `table6_provenance.md` | Where the timing values of the paper's Table VI come from (Russian). |
| `evidence/` | Files of run `20261023_230505`: environment, unit-test log, time-stamped attack and benchmark logs, attack matrix, per-round times, summary, paired tests, storage, and the unchanged result files of the prototype scripts. |

`run_a4.py` expects the restructured layout of the prototype used for the run (`code/`, `tests/`, `data/r4.2/device.csv`),
passed with `--proto <path>` (default `~/audit-paper`). The CERT data are not included.

The tests in `../tests/` cover the hash chains, the verifiers and the metrics. Run them with
`python -m pytest tests` from the repository root.
