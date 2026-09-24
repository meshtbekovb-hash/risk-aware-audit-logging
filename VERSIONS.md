# Versions

## Software
| Component | Version used |
|---|---|
| Python | 3.14.5 |
| matplotlib (plotting scripts only) | 3.10.9 |
| Standard library only for everything else | — |

## Dataset
| Release | DOI | Used for |
|---|---|---|
| CERT Insider Threat Test Dataset **r4.2** | [10.1184/R1/12841247.v1](https://doi.org/10.1184/R1/12841247.v1) | Main experiment: feature/threshold/weight design, all detection results, tamper-evident logging benchmarks |
| CERT Insider Threat Test Dataset **r5.2** | [10.1184/R1/12841247.v1](https://doi.org/10.1184/R1/12841247.v1) (same collection, different release within it) | External validation only (`results_revision/r52_external_test.csv`) — the detection method is frozen from its r4.2 selection and evaluated on r5.2 without any refitting |

Both releases are part of the same KiltHub collection; the DOI resolves to a page listing
all released versions (r1.1 through r6.2 at the time of writing). See the README for
which specific files are needed from each.

## Benchmark machine (for the timing/overhead numbers only)
| | |
|---|---|
| CPU | AMD Ryzen 7 250 (mobile, Zen 4), 8 cores / 16 threads |
| RAM | 23.3 GB |
| Disk | NVMe SSD (Samsung MZVMX1T0HCLD) |
| OS | Windows 11 Pro, build 10.0.26200 |

Detection results (recall, FPR, precision, ...) do not depend on the machine.
Write-time and fsync numbers do — see the note in `results_revision/performance_revised.csv`
and the caveats in the paper's Limitations section.
