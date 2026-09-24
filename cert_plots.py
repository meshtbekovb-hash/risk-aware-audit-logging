"""
ГРАФИКИ ДЛЯ СТАТЬИ (PNG, 300 dpi, подписи на английском)

Задача 9 REVISION_PLAN.md: все рисунки, идущие в статью, пересобраны под ОДНУ колонку
IEEE (ширина 3.5 дюйма), шрифт подписей осей не меньше 8 pt. Там, где раньше было два
графика рядом (fig4, fig8) - теперь друг под другом, иначе на 3.5 дюйма подписи стали
бы нечитаемыми (это уже отмечалось в materials_Shugyla.md).

  fig1_pr_vs_threshold.png   - (устарел, не идёт в статью, оставлен для истории)
  fig2_chain_overhead.png    - накладные расходы хеш-цепочки от объёма журнала
  fig3_recall_by_scenario.png- (устарел, не идёт в статью, оставлен для истории)
  fig4_riskaware_cost.png    - стоимость защиты: весь журнал против risk-aware (доп. рисунок)
  fig5_insider_level.png     - (устарел, заменён fig6/fig7 из cert_curves.py)
  fig8_scheme_comparison.png - сравнение схем защиты: стоимость и покрытие (основной рисунок)

Графики 2, 4, 8 берут числа из CSV, которые создали остальные скрипты, поэтому
сначала запусти cert_ablation.py, cert_chain_hmac.py, cert_riskaware_test.py,
cert_block_baseline.py. Графики 1, 3, 5 считаются заново из данных CERT, но в
main() не вызываются (устарели, см. раздел 9 FULL_REPORT_for_review.md).

Запуск (из папки с CSV):  python cert_plots.py
"""

import csv
from datetime import timedelta

import matplotlib
matplotlib.use("Agg")           # рисуем в файл, окно не нужно
import matplotlib.pyplot as plt

import cert_ablation as ab

DPI = 300
COLORS = {"logon": "#4c72b0", "device": "#dd8452", "combined": "#55a868"}
LABELS = {"logon": "logon only", "device": "device only", "combined": "logon + device"}

# Одна колонка IEEE. Шрифт подписей осей и делений - не меньше 8 pt (задача 9, пункт 1).
COL_WIDTH = 3.62
AXIS_FS = 8
TICK_FS = 8
LEGEND_FS = 7


def read_csv(path):
    with open(path, encoding="utf-8") as f:
        return list(csv.DictReader(f))


def save(fig, name):
    fig.tight_layout()
    fig.savefig(name, dpi=DPI, bbox_inches="tight")            # bbox tight учитывает легенды вне осей
    plt.close(fig)
    print(f"  сохранено: {name}")


def fig1_precision_recall():
    """Precision и recall в зависимости от порога, конфигурация device."""
    windows = ab.load_labels()
    ud = ab.load_events()
    days = sorted({d for _, d in ud})
    split = days[0] + timedelta(days=ab.BASELINE_DAYS)
    prof = ab.build_profiles(ud, split)
    test_keys = [k for k in ud if k[1] >= split]
    rows = [(ab.score(ud[k], prof.get(k[0]), "device"),
             ab.scenario_of(windows, k[0], k[1])) for k in test_keys]

    # Оценка риска принимает мало значений, поэтому точек на графике немного
    cutoffs = sorted({round(s, 2) for s, _ in rows if s > 0})
    prec, rec = [], []
    for c in cutoffs:
        m, _, _ = ab.metrics(rows, c)
        prec.append(m["precision"])
        rec.append(m["recall"])

    fig, ax = plt.subplots(figsize=(4.5, 3.2))
    ax.plot(cutoffs, prec, "o-", color="#c44e52", label="Precision")
    ax.plot(cutoffs, rec, "s-", color="#4c72b0", label="Recall")
    ax.set_xlabel("Risk score threshold")
    ax.set_ylabel("Metric value")
    ax.set_ylim(0, max(max(prec), max(rec)) * 1.15)
    ax.grid(alpha=0.3)
    ax.legend()
    save(fig, "fig1_pr_vs_threshold.png")


def fig2_overhead():
    """Накладные расходы: обычный журнал, простая SHA-256 цепочка, HMAC-схема. Одна колонка IEEE."""
    data = read_csv("chain_hmac_overhead_results.csv")
    n = [int(r["records"]) for r in data]
    plain = [float(r["plain_ms"]) for r in data]
    sha = [float(r["sha_chain_ms"]) for r in data]
    hm = [float(r["hmac_chain_ms"]) for r in data]
    verify = [float(r["hmac_verify_ms"]) for r in data]

    fig, ax = plt.subplots(figsize=(COL_WIDTH, 3.1))
    ax.plot(n, plain, "o-", color="#4c72b0", label="Plain log (write)", markersize=4)
    ax.plot(n, sha, "s-", color="#c44e52", label="SHA-256 chain (write)", markersize=4)
    ax.plot(n, hm, "D-", color="#dd8452", label="HMAC chain + anchors (write)", markersize=4)
    ax.plot(n, verify, "^--", color="#55a868", label="HMAC chain (verify)", markersize=4)
    ax.set_xscale("log")
    ax.set_yscale("log")
    ax.set_xlabel("Number of log records", fontsize=AXIS_FS)
    ax.set_ylabel("Time, ms", fontsize=AXIS_FS)
    ax.tick_params(labelsize=TICK_FS)
    ax.grid(alpha=0.3, which="both")
    ax.legend(loc="upper center", bbox_to_anchor=(0.5, -0.24), ncol=1, fontsize=LEGEND_FS, framealpha=0.9)
    save(fig, "fig2_chain_overhead.png")


def fig3_recall_by_scenario():
    """Столбчатая диаграмма полноты по сценариям для трёх конфигураций."""
    data = {r["config"]: r for r in read_csv("cert_ablation_results.csv")}
    configs = ["logon", "device", "combined"]
    scenarios = ["1", "2", "3"]
    width = 0.26

    fig, ax = plt.subplots(figsize=(4.5, 3.2))
    for i, cfg in enumerate(configs):
        vals = [100 * float(data[cfg][f"recall_s{s}"]) for s in scenarios]
        xs = [j + (i - 1) * width for j in range(len(scenarios))]
        ax.bar(xs, vals, width, color=COLORS[cfg], label=LABELS[cfg])
    ax.set_xticks(range(len(scenarios)))
    ax.set_xticklabels([f"Scenario {s}" for s in scenarios])
    ax.set_ylabel("Recall at FPR ≤ 1%, %")
    ax.grid(alpha=0.3, axis="y")
    ax.legend()
    save(fig, "fig3_recall_by_scenario.png")


def fig4_riskaware_cost():
    """
    Стоимость защиты: весь журнал в цепочке против risk-aware при разных порогах.
    Одна колонка IEEE - панели друг под другом (не рядом, как раньше), иначе на
    ширине 3.5 дюйма каждая панель осталась бы ýже 2 дюймов и подписи стали бы нечитаемы.
    """
    data = read_csv("riskaware_test_results.csv")   # тестовый период, честное разбиение
    cutoffs = [r["cutoff"] for r in data]
    full_time = float(data[0]["full_chain_time_ms"])
    full_size = float(data[0]["full_chain_size_kb"]) / 1024
    plain_time = float(data[0]["plain_time_ms"])
    plain_size = float(data[0]["plain_size_kb"]) / 1024

    fig, (a1, a2) = plt.subplots(2, 1, figsize=(COL_WIDTH, 4.6), sharex=True)
    for ax, key, full, plain, unit in [
            (a1, "riskaware_time_ms", full_time, plain_time, "Write time, ms"),
            (a2, "riskaware_size_kb", full_size, plain_size, "Log size, MB")]:
        vals = [float(r[key]) for r in data]
        if unit.endswith("MB"):
            vals = [v / 1024 for v in vals]
        ax.bar(range(len(cutoffs)), vals, color="#55a868", width=0.55,
               label="Per-record chain, high-risk days only")
        ax.axhline(full, color="#c44e52", linestyle="--", label="Uniform per-record chain (all records)")
        ax.axhline(plain, color="#4c72b0", linestyle=":", label="Plain log (no protection)")
        ax.set_ylabel(unit, fontsize=AXIS_FS)
        ax.tick_params(labelsize=TICK_FS)
        ax.grid(alpha=0.3, axis="y")
        ax.set_ylim(0, full * 1.15)
    # При sharex=True matplotlib сам убирает подписи делений с верхней панели (a1), это
    # штатное поведение, не ошибка - поэтому xticks/xticklabels задаются только один раз,
    # на нижней (a2), а не на обеих.
    a2.set_xticks(range(len(cutoffs)))
    a2.set_xticklabels(cutoffs)
    a2.set_xlabel(r"Risk score threshold $\tau$", fontsize=AXIS_FS)
    # Общая легенда под обоими графиками: длинные подписи не должны закрывать оси
    handles, labels = a1.get_legend_handles_labels()
    fig.legend(handles, labels, loc="upper center", bbox_to_anchor=(0.5, 0.015), ncol=1, fontsize=LEGEND_FS)
    save(fig, "fig4_riskaware_cost.png")


def fig5_insider_level():
    """Сколько инсайдеров из 70 поймано хотя бы раз, по сценариям и конфигурациям."""
    data = read_csv("cert_insider_level_results.csv")
    names = [r["config"] for r in data]
    parts = [("1", "Scenario 1 (30)", "#4c72b0"),
             ("2", "Scenario 2 (30)", "#dd8452"),
             ("3", "Scenario 3 (10)", "#55a868")]

    fig, ax = plt.subplots(figsize=(6.5, 3.4))
    bottom = [0] * len(data)
    for sc, label, color in parts:
        vals = [int(r[f"caught_s{sc}"]) for r in data]
        ax.bar(range(len(data)), vals, bottom=bottom, color=color, label=label)
        bottom = [b + v for b, v in zip(bottom, vals)]
    for i, total in enumerate(bottom):
        ax.text(i, total + 1, str(total), ha="center", fontsize=8)
    ax.axhline(70, color="gray", linestyle=":", linewidth=1)
    ax.set_xticks(range(len(data)))
    ax.set_xticklabels(names, rotation=20, ha="right", fontsize=8)
    ax.set_ylabel("Insiders detected (of 70)")
    ax.set_ylim(0, 92)
    ax.legend(fontsize=8, loc="upper center", ncol=3)
    save(fig, "fig5_insider_level.png")


def fig8_scheme_comparison():
    """
    Сравнение схем защиты журнала на тестовом периоде (168 392 записи): стоимость и покрытие.
    Данные из block_baseline_results.csv; время дано как отношение к обычной записи в том же запуске.
    Одна колонка IEEE - панели друг под другом (были рядом, на 3.5 дюйма стали бы нечитаемы).
    """
    data = {r["scheme"]: r for r in read_csv("block_baseline_results.csv")}
    plain = float(data["plain log"]["time_ms"])
    picks = [("Plain\nlog", "plain log", "#9e9e9e"),
             ("Per-record\n(all)", "full per-record HMAC chain", "#c44e52"),
             ("Block\n(all)", "block HMAC, B=1000", "#4c72b0"),
             ("Per-record\n(high-risk)", "risk-aware per-record chain only, tau=0.3", "#dd8452"),
             ("Hybrid", "hybrid: block B=1000 for all + per-record chain tau=0.3", "#55a868")]
    labels = [p[0] for p in picks]
    ratio = [float(data[p[1]]["time_ms"]) / plain for p in picks]
    covered = [float(data[p[1]]["malicious_covered_pct"]) for p in picks]
    colors = [p[2] for p in picks]

    fig, (a1, a2) = plt.subplots(2, 1, figsize=(COL_WIDTH, 5.2))
    a1.bar(range(len(picks)), ratio, color=colors, width=0.6)
    a1.axhline(1, color="gray", linestyle=":", linewidth=1)
    for i, v in enumerate(ratio):
        a1.text(i, v + 0.12, f"{v:.2f}x", ha="center", fontsize=7)
    a1.set_ylabel("Write time,\nx plain log", fontsize=AXIS_FS)
    a1.set_ylim(0, max(ratio) * 1.22)
    a1.tick_params(labelsize=TICK_FS)

    a2.bar(range(len(picks)), covered, color=colors, width=0.6)
    # Под процентом подписана гранулярность: «100%» у блочной и поэлементной схемы означает разную локализацию подделки.
    # Подпись последнего столбца (Hybrid) короче остальных - у правого края колонки длинный текст обрезался бы полем графика.
    granularity = ["", "record", "block", "record,\nhigh-risk only", "block+record"]
    for i, v in enumerate(covered):
        pct = f"{v:.0f}%" if v in (0, 100) else f"{v:.1f}%"
        a2.text(i, v + 3, f"{pct}\n({granularity[i]})" if granularity[i] else pct,
                ha="center", fontsize=6.5)
    a2.set_ylabel("Malicious records\ncovered, %", fontsize=AXIS_FS)
    a2.set_xlim(-0.7, len(picks) - 0.3)
    a2.set_ylim(0, 133)
    a2.tick_params(labelsize=TICK_FS)

    for ax in (a1, a2):
        ax.set_xticks(range(len(picks)))
        ax.set_xticklabels(labels, fontsize=7)
        ax.grid(alpha=0.3, axis="y")
    save(fig, "fig8_scheme_comparison.png")


def main():
    """
    fig1, fig3 (recall_by_scenario), fig5 построены на прежней оценке (весь период,
    порог выбран на тесте или все 70 инсайдеров) и заменены честными fig6 и fig7 из
    cert_curves.py. Функции оставлены в файле для истории, но не вызываются.

    Прежняя функция fig3_same_run() (черновая однокорпусная версия fig4, задача 9
    REVISION_PLAN.md) удалена - fig4_riskaware_cost() теперь сама строит панели друг
    под другом на ширину одной колонки, отдельная черновая версия больше не нужна.
    """
    print("Строим графики (одна колонка IEEE, 3.5 дюйма, шрифт осей >= 8 pt)...")
    fig2_overhead()
    fig4_riskaware_cost()
    fig8_scheme_comparison()


if __name__ == "__main__":
    main()
