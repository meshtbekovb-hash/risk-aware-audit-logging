"""
ПРОВЕРКА ГРАФИКОВ: то, что нарисовано, сверяется с таблицами результатов.

Как работает. Перехватываем matplotlib.figure.Figure.savefig: перед сохранением каждого рисунка
записываем данные, которые на нём НА САМОМ ДЕЛЕ нарисованы (линии, столбцы, подписи осей, легенда),
а затем сравниваем их с CSV. Так проверяется не код построения, а результат.

Запуск (из папки с CSV и результатами):  python check_figures.py
Рисунки при этом перезаписываются теми же данными.
"""

import csv
import os
import sys

import matplotlib
matplotlib.use("Agg")
import matplotlib.figure as mfig

sys.path.insert(0, os.getcwd())

captured = {}
_orig = mfig.Figure.savefig


def _capture(self, fname, *a, **k):
    info = []
    for ax in self.axes:
        d = {"xlabel": ax.get_xlabel(), "ylabel": ax.get_ylabel(),
             "xscale": ax.get_xscale(), "yscale": ax.get_yscale(),
             "xlim": tuple(round(v, 3) for v in ax.get_xlim()),
             "ylim": tuple(round(v, 3) for v in ax.get_ylim()),
             "legend": [t.get_text() for t in ax.get_legend().get_texts()] if ax.get_legend() else [],
             "lines": [(ln.get_label(), list(ln.get_xdata()), list(ln.get_ydata()), ln.get_linestyle(), ln.get_marker())
                       for ln in ax.get_lines()],
             "bars": [round(p.get_height(), 4) for p in ax.patches],
             "xticklabels": [t.get_text() for t in ax.get_xticklabels()],
             "texts": [t.get_text() for t in ax.texts]}
        info.append(d)
    captured[os.path.basename(str(fname))] = info
    return _orig(self, fname, *a, **k)


mfig.Figure.savefig = _capture

import cert_plots as cp
import cert_curves as cc


def read(path):
    with open(path, encoding="utf-8") as f:
        return list(csv.DictReader(f))


problems = []


def check(cond, msg):
    print(("OK   " if cond else "ОШИБКА  ") + msg)
    if not cond:
        problems.append(msg)


def close(a, b, tol=1e-6):
    return abs(a - b) <= tol * max(1.0, abs(b))


def near(a, b):
    """Сравнение процентов с CSV, где значения округлены до 4 знаков (доли), то есть до 0.005 процентных пункта."""
    return abs(a - b) <= 0.006


# ---------------- fig2 ----------------
cp.fig2_overhead()
ax = captured["fig2_chain_overhead.png"][0]
rows = read("chain_hmac_overhead_results.csv")
n = [int(r["records"]) for r in rows]
cols = {"Plain log (write)": "plain_ms", "SHA-256 chain (write)": "sha_chain_ms",
        "HMAC chain + anchors (write)": "hmac_chain_ms", "HMAC chain (verify)": "hmac_verify_ms"}
print("\nfig2:", ax["xlabel"], "|", ax["ylabel"], "| шкалы", ax["xscale"], ax["yscale"], "| легенда", ax["legend"])
for label, xs, ys, ls, mk in ax["lines"]:
    col = cols[label]
    check(xs == n and all(close(y, float(r[col])) for y, r in zip(ys, rows)), f"fig2: линия '{label}' совпадает с колонкой {col}")
check(ax["xscale"] == "log" and ax["yscale"] == "log", "fig2: обе оси логарифмические")

# ---------------- fig4 ----------------
cp.fig4_riskaware_cost()
axs = captured["fig4_riskaware_cost.png"]
rows = read("riskaware_test_results.csv")
print("\nfig4:", [(a["ylabel"], a["legend"]) for a in axs])
for a, key, full_key, plain_key, div in [(axs[0], "riskaware_time_ms", "full_chain_time_ms", "plain_time_ms", 1.0),
                                          (axs[1], "riskaware_size_kb", "full_chain_size_kb", "plain_size_kb", 1024.0)]:
    check(all(close(h, float(r[key]) / div, 1e-3) for h, r in zip(a["bars"], rows)), f"fig4: столбцы '{a['ylabel']}' совпадают с {key}")
    ys = sorted({round(l[2][0], 3) for l in a["lines"]})
    exp = sorted({round(float(rows[0][full_key]) / div, 3), round(float(rows[0][plain_key]) / div, 3)})
    check(all(close(y, e, 1e-3) for y, e in zip(ys, exp)), f"fig4: горизонтальные линии = полная цепочка и обычный журнал ({a['ylabel']})")
check([t for t in axs[1]["xticklabels"]] == [r["cutoff"] for r in rows], "fig4: подписи порогов совпадают с таблицей")
# Задача 9: панели fig4 теперь друг под другом (sharex=True, одна колонка IEEE), поэтому
# matplotlib сам убирает подписи делений с верхней панели (axs[0]) - это штатное поведение,
# подписи проверяем на нижней (axs[1]), где они и остаются видимыми.

# ---------------- fig8 ----------------
cp.fig8_scheme_comparison()
axs = captured["fig8_scheme_comparison.png"]
data = {r["scheme"]: r for r in read("block_baseline_results.csv")}
plain = float(data["plain log"]["time_ms"])
keys = ["plain log", "full per-record HMAC chain", "block HMAC, B=1000",
        "risk-aware per-record chain only, tau=0.3", "hybrid: block B=1000 for all + per-record chain tau=0.3"]
print("\nfig8:", [(a["ylabel"], a["xticklabels"]) for a in axs])
check(all(close(h, float(data[k]["time_ms"]) / plain, 1e-3) for h, k in zip(axs[0]["bars"], keys)), "fig8: левый график = время/обычная запись")
check(all(close(h, float(data[k]["malicious_covered_pct"]), 1e-3) for h, k in zip(axs[1]["bars"], keys)), "fig8: правый график = % вредоносных записей под защитой")

# ---------------- fig6 и fig7 ----------------
cc.main()
pts = read("curves_points.csv")
main = {r["config"]: r for r in read("user_level2_results.csv") if r["table"] == "main"}
for fname, fig in [("fig6_user_recall_vs_fpr.png", "fig6_user_recall_vs_fpr.png"), ("fig7_scenario2_curve.png", "fig7_scenario2_curve.png")]:
    ax = captured[fname][0]
    print(f"\n{fname}:", ax["xlabel"], "|", ax["ylabel"], "| xlim", ax["xlim"], "ylim", ax["ylim"], "| легенда", ax["legend"])
    for label, xs, ys, ls, mk in ax["lines"]:
        if not label.endswith("(test)"):
            continue
        cfg = label.replace(" (test)", "")
        exp = [(100 * float(r["test_fpr"]), 100 * float(r["test_recall"])) for r in pts
               if r["figure"] == fig and r["config"] == cfg]
        got = list(zip(xs, ys))
        check(len(exp) == len(got) and all(near(a, b) and near(c, d) for (a, c), (b, d) in zip(got, exp)),
              f"{fname}: линия '{label}' = точки test из curves_points.csv ({len(got)} точек)")
    if fname.startswith("fig6"):
        stars = [(l[0], l[1][0], l[2][0]) for l in ax["lines"] if l[4] == "*"]
        for cfg in ("logon", "device", "logon+device"):
            r = main[cfg]
            found = any(near(x, 100 * float(r["test_fpr"])) and near(y, 100 * float(r["test_recall"]))
                        for _, x, y in stars)
            check(found, f"fig6: звезда для '{cfg}' стоит в ({100 * float(r['test_fpr']):.2f}%, {100 * float(r['test_recall']):.1f}%) = главная таблица")
        # монотонность: линии соединяют точки в порядке валидации, тест не обязан быть монотонным
        for label, xs, ys, ls, mk in ax["lines"]:
            if label.endswith("(test)"):
                back = sum(1 for i in range(1, len(xs)) if xs[i] < xs[i - 1] or ys[i] < ys[i - 1])
                print(f"     '{label}': шагов, где линия идёт назад (test FPR или recall убывает): {back} из {len(xs) - 1}")

print(f"\nОшибок: {len(problems)}")
