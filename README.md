# Risk-Aware Tamper-Evident Audit Logging — code and results

Companion code repository for a study on behavioral risk-based intrusion/insider-threat
detection and tamper-evident audit logging, evaluated on the CERT Insider Threat Test
Dataset (r4.2 and, for external validation, r5.2). Paper title/authors to be filled in
once the manuscript is finalized.

**What this repository contains:** every script used to produce the numbers, tables and
figures in the paper, the resulting CSV tables, run logs, and the final figures.
**What it does not contain:** the CERT dataset itself (licensed, not ours to redistribute —
see [Getting the data](#getting-the-data) below).

---

## Repository layout

```
.
├── cert_*.py                    - analysis scripts (see "Scripts" below)
├── step1_generate.py             - early synthetic-log prototype, not used in the paper
├── step2_detect.py, step3_tamper.py  - same, kept for history
├── audit_independent.py          - independent re-implementation that re-derives the
│                                   headline numbers from raw CSVs without importing any
│                                   of the other modules, as a cross-check
├── check_figures.py              - verifies that what is actually drawn on each figure
│                                   matches the result tables (0 discrepancies expected)
├── check_report_numbers.py       - cross-checks headline numbers against logs/tables
├── *_results.csv                 - result tables from the main (r4.2) experiment
├── curves_points.csv             - points behind fig6/fig7
├── results_revision/              - results from the post-review revision round
│                                   (external r5.2 test, baselines, ablations, tamper
│                                   tests, performance, localization; see the .md file
│                                   in that folder for metric definitions)
├── logs/                          - captured stdout of every run, for traceability
└── fig*.png                       - the five figures used in the paper (single-column
                                    IEEE width, 300 dpi)
```

## Getting the data

This code expects the **CERT Insider Threat Test Dataset** (Carnegie Mellon University
Software Engineering Institute), which is not included here.

- **Copies used in this study:** both r4.2 and r5.2 were obtained from Kaggle mirrors of
  the official release (r5.2 `device.csv` has one extra column, `file_tree`, which the
  code ignores).
- **Official source:** CMU KiltHub (Figshare), DOI
  [10.1184/R1/12841247.v1](https://doi.org/10.1184/R1/12841247.v1) —
  <https://kilthub.cmu.edu/articles/dataset/Insider_Threat_Test_Dataset/12841247>
- **r4.2** (main experiment): download the `r4.2` release. From it you need
  `logon.csv`, `device.csv`, `file.csv` (optional, used only in a supplementary
  experiment) and `insiders.csv`. Place them in the repository root, next to the scripts.
- **r5.2** (external validation only, `results_revision/r52_external_test.csv`):
  download the `r5.2` release, take `logon.csv` and `device.csv`, and place them in a
  `data_r52/` subfolder of the repository root. `insiders.csv` is shared across all CERT
  releases — the r4.2 copy already has the r5.2 rows (filtered by the `dataset` column).
- The archives are large mainly because of `http.csv`, which this project does not use;
  you only need to extract the two or three files listed above.

**Citation** (cite both the paper and the dataset):

> J. Glasser and B. Lindauer, "Bridging the Gap: A Pragmatic Approach to Generating
> Insider Threat Data," in *2013 IEEE Security and Privacy Workshops*, San Francisco,
> CA, USA, May 2013, pp. 98–104, doi: 10.1109/SPW.2013.37.

> B. Lindauer, *Insider Threat Test Dataset*, Carnegie Mellon University, 2020,
> doi: [10.1184/R1/12841247.v1](https://doi.org/10.1184/R1/12841247.v1).

## Setup

- Python 3.11+ (developed and tested on 3.14.5).
- No third-party dependencies for the analysis scripts themselves — standard library
  only (`csv`, `hashlib`, `hmac`, `datetime`, `statistics`, ...).
- `matplotlib` is needed only for the two plotting scripts, `cert_plots.py` and
  `cert_curves.py`. Tested with matplotlib 3.10.9.

```bash
pip install matplotlib   # only needed for the two plotting scripts
```

No `requirements.txt`/virtual environment is strictly required beyond that one optional
package; see `requirements.txt` in this folder for a pinned version if you want exact
reproducibility of the plots.

## Running

All scripts are run from the repository root, with the CERT CSVs (see above) also in
the repository root (and `data_r52/` for the r5.2 files). Each script prints a short
explanation of what it computed and writes its own CSV; nothing needs command-line
arguments.

**Suggested order** (later scripts import earlier ones as modules, so run at least the
core scripts first):

1. `cert_ablation.py` — loads the data, builds per-user profiles, computes the risk
   score, first (uncorrected) day-level comparison of `logon`/`device`/`logon+device`.
2. `cert_leakcheck.py` — checks there is no leakage from the future into the training
   profiles.
3. `cert_honest_split.py` — the honest train/validation/test split used everywhere
   after this point.
4. `cert_user_level.py`, then `cert_user_level2.py` — user-level recall/FPR, Wilson
   intervals, the main results table (`user_level2_results.csv`).
5. `cert_observed.py`, `cert_curves.py` — observed-population diagnostics and the
   recall-vs-FPR curves (`fig6`, `fig7`).
6. `cert_chain_hmac.py`, `cert_block_baseline.py` — the tamper-evident logging schemes,
   attack tests, and overhead measurements.
7. `cert_riskaware_test.py`, `cert_plots.py` — the risk-aware cost figures (`fig2`,
   `fig4`, `fig8`).
8. `audit_independent.py` — optional, independent cross-check of the headline numbers.
9. Anything under **the post-review revision round** (`cert_r52_external_test.py`,
   `cert_selection_baselines.py`, `cert_weight_sensitivity.py`,
   `cert_detection_metrics.py`, `cert_tamper_extended.py`,
   `cert_performance_revised.py`, `cert_localization_realtime.py`) can be run
   independently once the steps above have produced their CSVs; each writes into
   `results_revision/`.
10. Follow-up checks after the second review round, also writing into
    `results_revision/`: `cert_r52_fpr_normalized.py` (length-normalized FPR
    comparison r4.2 vs r5.2), `cert_single_feature_config.py` (single-feature
    configuration), `cert_scenario4_diagnostics.py` (r5.2 scenario 4 diagnostics),
    `cert_score_granularity.py` (reachable risk-score levels and per-record
    protection coverage), `cert_coverage_concentration.py` (how the protected
    malicious records are distributed over days, insiders and scenarios).

`step1_generate.py`/`step2_detect.py`/`step3_tamper.py` and `cert_experiment.py`/
`cert_experiment_full.py` are early prototypes (a synthetic-log generator and an
early single-file version of the ablation experiment); they are kept for history but
are not part of the reported results.

## Reproducibility notes

- All train/validation/test splits are by calendar time, not random — there is no
  random seed to fix for the detection results. The one place randomness is used
  (`cert_selection_baselines.py`, random-selection baseline) fixes `random.Random(42)`.
- Timing/performance numbers (`chain_*_overhead_results.csv`,
  `results_revision/performance_revised.csv`) were measured on: AMD Ryzen 7 250 (8
  cores / 16 threads), 23.3 GB RAM, NVMe SSD, Windows 11 Pro, Python 3.14.5. Absolute
  times will differ on other hardware; relative comparisons between schemes are the
  point, not the absolute milliseconds.
- `logs/` contains the captured console output of the actual runs that produced the
  committed CSVs, for anyone who wants to check a number without re-running everything.

## License

Not yet decided by the authors — do not redistribute without checking with them first.
The CERT dataset itself is governed by CMU's own terms on KiltHub, independent of
whatever license this code ends up under.
