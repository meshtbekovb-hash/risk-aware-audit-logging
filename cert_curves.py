"""
КРИВЫЕ user recall против user FPR (PNG, 300 dpi, подписи на английском)

  fig6_user_recall_vs_fpr.png   - все инсайдеры: user recall против user FPR, три конфигурации
  fig7_scenario2_curve.png      - то же только для сценария 2 (15 инсайдеров в тесте)

Как строится кривая (это важно для честности):
  1. Для каждой конфигурации перебираются все комбинации (порог риска, N, W).
  2. На ВАЛИДАЦИИ из них оставляем фронтир: точки, у которых нет другой точки
     с меньшим или равным FPR и большим recall. Фронтир определяется только валидацией.
  3. На график кладём результат этих же точек на ТЕСТЕ. Тест ничего не выбирает,
     он только показывает, как выбранные на валидации параметры работают на новых данных.
  4. Звездой отмечена рабочая точка с user FPR не выше 3%, выбранная на валидации
     (то же правило, что в cert_user_level2.py).
Пунктир - те же точки на валидации, для сравнения.

Запуск (из папки с CSV):  python cert_curves.py
"""

import csv

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
from matplotlib.lines import Line2D

import cert_ablation as ab
import cert_honest_split as hs
import cert_user_level2 as u2

DPI = 300
COLORS = {"logon": "#4c72b0", "device": "#dd8452", "logon+device": "#55a868"}
OUTPUT = "curves_points.csv"

# Одна колонка IEEE (задача 9 REVISION_PLAN.md): ширина 3.5 дюйма, подписи осей >= 8 pt.
COL_WIDTH = 3.62
AXIS_FS = 8
TICK_FS = 8
LEGEND_FS = 6.5


def all_points(st, used):
    """Оценка каждой комбинации (порог, N, W) на валидации и на тесте."""
    pts = []
    for cutoff in u2.score_levels(used):
        for n in u2.N_VALUES:
            for w in u2.W_VALUES:
                v = st.run("валидация", used, cutoff, n, w)
                t = st.run("тест", used, cutoff, n, w)
                pts.append({"cutoff": cutoff, "N": n, "W": w, "v": v, "t": t})
    return pts


def frontier(points, metric):
    """
    Фронтир по ВАЛИДАЦИИ: идём по возрастанию val-FPR и оставляем точку,
    только если её val-метрика строго лучше всех предыдущих.
    metric(r) - функция, достающая recall (общий или по сценарию) из результата.
    """
    pts = sorted(points, key=lambda p: (p["v"]["fpr"], -metric(p["v"])))
    front, best = [], -1.0
    for p in pts:
        m = metric(p["v"])
        if m > best:
            front.append(p)
            best = m
    return front


def recall_all(r):
    return r["recall"]


def recall_sc2(r):
    total = r["total_sc"].get("2", 0)
    return r["by_sc"].get("2", 0) / total if total else 0.0


def draw(configs_pts, metric, title_y, fname, mark_working_point):
    """Одна колонка IEEE (3.5 дюйма). Легенда с шестью элементами занимает больше места
    по высоте, чем в широкой версии - график сделан выше (4.3 вместо 4.0 дюйма), чтобы
    легенда не наезжала на подписи оси X."""
    fig, ax = plt.subplots(figsize=(COL_WIDTH, 4.3))
    rows = []
    for name, pts, work in configs_pts:
        front = frontier(pts, metric)
        xs_v = [100 * p["v"]["fpr"] for p in front]
        ys_v = [100 * metric(p["v"]) for p in front]
        xs_t = [100 * p["t"]["fpr"] for p in front]
        ys_t = [100 * metric(p["t"]) for p in front]
        ax.plot(xs_v, ys_v, "--", color=COLORS[name], alpha=0.45, linewidth=1)
        ax.plot(xs_t, ys_t, "o-", color=COLORS[name], label=f"{name} (test)", markersize=3.5)
        if mark_working_point and work:
            ax.plot(100 * work["t"]["fpr"], 100 * metric(work["t"]), "*", color=COLORS[name],
                    markersize=12, markeredgecolor="black")
        for p in front:
            rows.append({"figure": fname, "config": name, "cutoff": p["cutoff"], "N": p["N"], "W": p["W"],
                         "val_fpr": round(p["v"]["fpr"], 4), "val_recall": round(metric(p["v"]), 4),
                         "test_fpr": round(p["t"]["fpr"], 4), "test_recall": round(metric(p["t"]), 4)})
    ax.axvline(3, color="gray", linestyle=":", linewidth=1)
    ax.set_xlabel("User-level false-positive rate, % of non-insiders", fontsize=AXIS_FS)
    ax.set_ylabel(title_y, fontsize=AXIS_FS)
    ax.set_xlim(0, 20)
    ax.set_ylim(0, 102)
    ax.tick_params(labelsize=TICK_FS)
    ax.grid(alpha=0.3)
    # Легенда объясняет все элементы: сплошные линии (тест), пунктир (валидация), звезда, линия 3%.
    # Точки каждой кривой соединены в порядке FPR НА ВАЛИДАЦИИ, поэтому на тесте линия может идти назад.
    handles, labels = ax.get_legend_handles_labels()
    handles.append(Line2D([0], [0], color="gray", linestyle="--", alpha=0.6, linewidth=1))
    labels.append("same parameter sets on validation")
    if mark_working_point:
        handles.append(Line2D([0], [0], color="gray", marker="*", linestyle="", markersize=10, markeredgecolor="black"))
        labels.append("working point chosen on validation (user FPR ≤ 3%)")
    handles.append(Line2D([0], [0], color="gray", linestyle=":", linewidth=1))
    labels.append("3% user FPR")
    # Легенда под графиком в один столбец, чтобы длинные подписи не обрезались по ширине колонки
    ax.legend(handles, labels, loc="upper center", bbox_to_anchor=(0.5, -0.19), ncol=1,
              fontsize=LEGEND_FS, framealpha=0.9)
    fig.tight_layout()
    fig.savefig(fname, dpi=DPI, bbox_inches="tight")
    plt.close(fig)
    print(f"  сохранено: {fname}")
    return rows


def main():
    print("Загрузка и перебор параметров...")
    st = u2.Setup()
    per_cfg = []
    for name, cfg in u2.CONFIGS:
        used = hs.CONFIG_FEATURES[cfg]
        pts = all_points(st, used)
        sel = u2.select_on_validation(st, used, hybrid=False)       # рабочая точка: только валидация
        work = None
        if sel:
            p = sel[0]
            work = {"v": sel[1], "t": st.run("тест", used, p["cutoff"], p["N"], p["W"]), **p}
        per_cfg.append((name, pts, work))

    rows = draw(per_cfg, recall_all, "User-level recall, % of insiders (n = 35)",
                "fig6_user_recall_vs_fpr.png", True)
    # Кривая сценария 2: рабочих точек по бюджету 3% для этого сценария не отмечаем
    rows += draw(per_cfg, recall_sc2, "Scenario 2 user-level recall, % (n = 15)",
                 "fig7_scenario2_curve.png", False)

    print("\nФронтир сценария 2 по валидации и результат на тесте (device):")
    for name, pts, _ in per_cfg:
        if name != "device":
            continue
        for p in frontier(pts, recall_sc2):
            print(f"  порог {p['cutoff']:<4} N={p['N']} W={p['W']:>2} | валидация: сц.2 "
                  f"{p['v']['by_sc'].get('2', 0)}/{p['v']['total_sc']['2']} при FPR {100 * p['v']['fpr']:.1f}% | "
                  f"тест: сц.2 {p['t']['by_sc'].get('2', 0)}/{p['t']['total_sc']['2']} при FPR {100 * p['t']['fpr']:.1f}%")

    with open(OUTPUT, "w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=list(rows[0].keys()))
        w.writeheader()
        w.writerows(rows)
    print(f"\nТочки кривых сохранены: {OUTPUT}")


if __name__ == "__main__":
    main()
