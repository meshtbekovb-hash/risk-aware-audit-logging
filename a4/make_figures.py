"""
РИСУНКИ ДЛЯ A4 (строятся только из CSV в a4/evidence/)

Запуск:  python a4/make_figures.py <run id>      (run_a4.py вызывает его сам)
         python a4/make_figures.py                (берёт последний прогон)

Рисунки (a4/figures/run_<run id>/, PDF для LaTeX и PNG для просмотра), все читаются в чёрно-белой печати:
  attack_matrix.pdf   атака x схема/класс: код исхода в клетке, заливка по группе исхода
  write_time.pdf      среднее время записи 10 000 записей с 95% ДИ
  storage.pdf         рост объёма относительно обычного журнала, hex и бинарные теги
"""

import csv
import glob
import os
import sys

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
from matplotlib.patches import Patch, Rectangle

A4 = os.path.dirname(os.path.abspath(__file__))
EVIDENCE = os.path.join(A4, "evidence")
FIGURES = os.path.join(A4, "figures")

plt.rcParams.update({"font.family": "serif", "font.size": 8, "axes.linewidth": 0.6,
                     "xtick.major.width": 0.6, "ytick.major.width": 0.6,
                     "pdf.fonttype": 42, "savefig.bbox": "tight", "savefig.pad_inches": 0.02})

SCHEME_LABEL = {"ordinary": "Ordinary\nlog", "sha256_chain": "SHA-256\nchain",
                "hmac_chain": "Per-record\nHMAC", "block_hmac": "Block tags\nB = 1000"}
COLUMN_LABEL = {"sha_asis": "SHA-256\nas is", "sha_recomp": "SHA-256\nrecomputed",
                "hmac_A1": "HMAC chain\nA1", "hmac_A2": "HMAC chain\nA2",
                "block_A1": "Block tags\nA1", "block_A2": "Block tags\nA2"}
# Заливка по группе исхода: светлая - обнаружено, тёмная - пропущено, штриховка - хвост
GROUP_STYLE = {"detected": ("0.88", "", "black"), "missed": ("0.25", "", "white"),
               "unconfirmed tail": ("white", "////", "black"), "n/a": ("white", "", "0.4"),
               "not tested": ("white", "", "0.6")}
# Клетки, где прогон не проверял схему, но прототип печатает вердикт константой (не проверкой):
# SHA-256 в атаках 6 и 7 из cert_chain_hmac.attack_tests (см. inventory.md). Подписываются n.t., а не «–».
NOT_TESTED_BY_PROTOTYPE = {("6", "sha_asis"), ("6", "sha_recomp"), ("7", "sha_asis"), ("7", "sha_recomp")}


def read(name, run):
    with open(os.path.join(EVIDENCE, f"{name}_{run}.csv"), encoding="utf-8") as f:
        return list(csv.DictReader(f))


OUT = FIGURES                       # папка прогона, задаётся в main()


def save(fig, name):
    os.makedirs(OUT, exist_ok=True)
    for ext in ("pdf", "png"):
        fig.savefig(os.path.join(OUT, f"{name}.{ext}"), dpi=300)
    plt.close(fig)


def attack_matrix(run):
    rows = read("attack_matrix", run)
    cols = list(COLUMN_LABEL)
    attacks = []
    for r in rows:
        if (r["attack_id"], r["attack"]) not in attacks:
            attacks.append((r["attack_id"], r["attack"]))
    cell = {(r["attack_id"], r["column"]): r for r in rows}

    fig, ax = plt.subplots(figsize=(6.6, 4.6))
    for i, (aid, _) in enumerate(attacks):
        for j, col in enumerate(cols):
            r = cell[(aid, col)]
            group = r["observed_group"]
            face, hatch, ink = GROUP_STYLE[group]
            ax.add_patch(Rectangle((j, i), 1, 1, facecolor=face, edgecolor="white", linewidth=1.5))
            if hatch:   # цвет штриховки берётся из edgecolor, поэтому отдельный слой без рамки
                ax.add_patch(Rectangle((j + 0.03, i + 0.05), 0.94, 0.9, facecolor="none", hatch=hatch,
                                       edgecolor="0.45", linewidth=0))
            text = r["observed"] if r["observed"] else "–"
            if (aid, col) in NOT_TESTED_BY_PROTOTYPE and not r["observed"]:
                text = "n.t."
            if r["observed"] == "NA":
                text = "n/a"
            if (r["expected"] or r["observed"]) and r["code_match"] != "True":
                text += "*"                                    # отличие от ожидаемого кода
            weight = "bold" if group in ("missed", "unconfirmed tail") else "normal"
            ax.text(j + 0.5, i + 0.5, text, ha="center", va="center", color=ink,
                    fontsize=7.5, fontweight=weight,
                    bbox=dict(boxstyle="square,pad=0.35", fc="white", ec="none") if hatch else None)
    ax.set_xlim(0, len(cols))
    ax.set_ylim(len(attacks), 0)
    ax.set_xticks([j + 0.5 for j in range(len(cols))], [COLUMN_LABEL[c] for c in cols])
    ax.set_yticks([i + 0.5 for i in range(len(attacks))], [f"{a}. {n}" for a, n in attacks])
    ax.xaxis.tick_top()
    ax.tick_params(length=0)
    for s in ax.spines.values():
        s.set_visible(False)
    handles = [Patch(facecolor=GROUP_STYLE[g][0], hatch=GROUP_STYLE[g][1], edgecolor="0.5", label=lbl)
               for g, lbl in [("detected", "Detected (R record, B block, C checkpoint, D detected)"),
                              ("missed", "Missed (M)"), ("unconfirmed tail", "Unconfirmed tail (U)")]]
    ax.legend(handles=handles, loc="upper center", bbox_to_anchor=(0.35, -0.01), ncol=3,
              frameon=False, fontsize=7, handlelength=1.6)
    save(fig, "attack_matrix")


def write_time(run):
    rows = read("bench_summary", run)
    fig, ax = plt.subplots(figsize=(4.2, 2.3))
    hatches = ["", "\\\\\\\\", "////", "...."]
    x = range(len(rows))
    means = [float(r["mean_ms"]) for r in rows]
    lo = [float(r["mean_ms"]) - float(r["ci95_lo_ms"]) for r in rows]
    hi = [float(r["ci95_hi_ms"]) - float(r["mean_ms"]) for r in rows]
    ax.bar(x, means, width=0.6, color="white", edgecolor="black", linewidth=0.7, hatch=None)
    for xi, m, h in zip(x, means, hatches):
        ax.bar(xi, m, width=0.6, color="white", edgecolor="0.35", linewidth=0, hatch=h)
        ax.bar(xi, m, width=0.6, color="none", edgecolor="black", linewidth=0.7)
    ax.errorbar(x, means, yerr=[lo, hi], fmt="none", ecolor="black", elinewidth=0.8, capsize=3)
    for xi, r in zip(x, rows):
        ax.text(xi, float(r["ci95_hi_ms"]) + max(means) * 0.03,
                f"{float(r['mean_ms']):.1f} ms\n{float(r['ratio_to_ordinary_mean']):.2f}×",
                ha="center", va="bottom", fontsize=7)
    ax.set_xticks(list(x), [SCHEME_LABEL[r["scheme"]] for r in rows])
    ax.set_ylabel("Write time, ms (mean, 95% CI)")
    ax.set_ylim(0, max(means) * 1.35)
    ax.spines[["top", "right"]].set_visible(False)
    ax.yaxis.grid(True, linewidth=0.3, color="0.8")
    ax.set_axisbelow(True)
    save(fig, "write_time")


def storage(run):
    rows = [r for r in read("storage", run) if r["scheme"] != "ordinary"]
    fig, ax = plt.subplots(figsize=(3.5, 1.9))
    labels, values, hatch = [], [], []
    for r in rows:
        labels.append(f"{SCHEME_LABEL[r['scheme']].replace(chr(10), ' ')}, {r['tag_encoding']}")
        values.append(float(r["overhead_pct"]))
        hatch.append("" if r["tag_encoding"] == "hex" else "////")
    y = range(len(rows))
    ax.barh(list(y), values, height=0.6, color="white", edgecolor="black", linewidth=0.7)
    for yi, v, h in zip(y, values, hatch):
        if h:
            ax.barh(yi, v, height=0.6, color="none", edgecolor="0.35", linewidth=0, hatch=h)
        ax.text(v + max(values) * 0.02, yi, f"+{v:.2f}%" if v < 1 else f"+{v:.1f}%",
                va="center", fontsize=7)
    ax.set_yticks(list(y), labels)
    ax.invert_yaxis()
    ax.set_xlabel("Storage overhead vs. ordinary log, %")
    ax.set_xlim(0, max(values) * 1.2)
    ax.spines[["top", "right"]].set_visible(False)
    save(fig, "storage")


def main():
    if len(sys.argv) > 1:
        run = sys.argv[1]
    else:
        run = sorted(glob.glob(os.path.join(EVIDENCE, "attack_matrix_*.csv")))[-1][-19:-4]
    global OUT
    OUT = os.path.join(FIGURES, f"run_{run}")   # у каждого прогона свои рисунки, отчёт ничего не теряет
    attack_matrix(run)
    if os.path.exists(os.path.join(EVIDENCE, f"bench_summary_{run}.csv")):
        write_time(run)
        storage(run)
    print(f"figures for run {run} written to {OUT}")


if __name__ == "__main__":
    main()
