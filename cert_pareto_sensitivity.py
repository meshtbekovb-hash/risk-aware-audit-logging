"""
ДОПОЛНЕНИЕ К cert_block_size_pareto.py: АНАЛИЗ ПО КАЖДОМУ ГИБРИДУ ОТДЕЛЬНО

Почему нужно. Граница Парето по одной только измеренной сетке B = 1, 2, 5, 10, ... может
оставить гибрид «недоминированным» просто потому, что промежуточные B (3, 4, 700, 950 ...)
не измерялись. Здесь каждый гибрид сравнивается:
  (а) с измеренными конфигурациями (строго, только замеры);
  (б) с блочной схемой ЛЮБОГО целого размера блока B = 1..20000, время которой берётся из
      модели t(B) = a + b / B, подогнанной методом наименьших квадратов по измеренным блочным
      точкам. Модель простая: постоянная часть (запись строк, кодирование) плюс часть,
      пропорциональная числу блоков (одна метка и одна строка во внешний файл на блок).
      Качество подгонки печатается; это модель, не замер.
Для каждого гибрида ищется наименьшая цена одной внешней фиксации c (мс), при которой он
становится недоминированным: время + c * число фиксаций. Цена c - предположение, не
измерение (локальная запись в файл не отражает реальный внешний сервис, где возможны пакетная
отправка и асинхронная запись).

Вход: results_revision/block_size_pareto.csv. Выход: results_revision/hybrid_dominance.csv
"""

import csv
import math

IN = "results_revision/block_size_pareto.csv"
OUT = "results_revision/hybrid_dominance.csv"
N = 168392
C_GRID = [0.0] + [round(10 ** (e / 20), 6) for e in range(-80, 61)]     # 0 и 1e-4 ... 1e3 мс


def block_area(B):
    """Средняя область поиска блочной схемы по всем записям при фактических границах:
    сумма квадратов размеров блоков / n. По вредоносным записям для B <= 10000 она
    практически совпадает (см. block_size_pareto.csv), поэтому одна формула на оба случая."""
    full, rest = divmod(N, B)
    return (full * B * B + rest * rest) / N


def main():
    rows = list(csv.DictReader(open(IN, encoding="utf-8")))
    blocks = [r for r in rows if r["scheme"] == "block"]
    hybrids = [r for r in rows if r["scheme"].startswith("hybrid")]
    chain_all = [r for r in rows if r["scheme"] == "per-record chain, all"]

    # --- модель t(B) = a + b/B, МНК по измеренным блочным точкам ---
    xs = [1 / int(r["B"]) for r in blocks]
    ys = [float(r["mean_ms"]) for r in blocks]
    mx, my = sum(xs) / len(xs), sum(ys) / len(ys)
    b = sum((x - mx) * (y - my) for x, y in zip(xs, ys)) / sum((x - mx) ** 2 for x in xs)
    a = my - b * mx
    print(f"модель времени блочной схемы: t(B) = {a:.1f} + {b:.1f} / B  (мс)")
    for r in blocks:
        B = int(r["B"])
        print(f"   B={B:>5}: замер {float(r['mean_ms']):6.1f} ± {float(r['std_ms']):4.1f}, модель {a + b / B:6.1f}")
    model_blocks = [{"name": f"block B={B} (модель)", "t": a + b / B, "k": math.ceil(N / B),
                     "area": block_area(B)} for B in range(1, 20001)]

    out = []
    for target in ("all", "bad"):
        for adv in ("no_key", "key"):
            col = f"area_{target}_{adv}"
            measured = [{"name": f"{r['scheme']} B={r['B']}", "t": float(r["mean_ms"]),
                         "k": int(r["external_commits"]), "area": float(r[col])}
                        for r in blocks + hybrids + chain_all]
            print(f"\n[{target}, {adv}]")
            for h in hybrids:
                me = {"name": f"hybrid B={h['B']}", "t": float(h["mean_ms"]), "k": int(h["external_commits"]),
                      "area": float(h[col])}

                def dominators(pool, c):
                    return [p for p in pool if p["name"] != me["name"]
                            and p["t"] + c * p["k"] <= me["t"] + c * me["k"] and p["area"] <= me["area"]
                            and (p["t"] + c * p["k"] < me["t"] + c * me["k"] or p["area"] < me["area"])]

                res = {}
                for label, pool in (("measured", measured), ("model", model_blocks)):
                    dom0 = dominators(pool, 0.0)
                    best0 = min(dom0, key=lambda p: p["t"]) if dom0 else None
                    c_free = next((c for c in C_GRID if not dominators(pool, c)), None)
                    res[label] = (best0, c_free)
                bm, cm = res["measured"]
                bo, co = res["model"]
                print(f"  hybrid B={h['B']:>5} ({me['t']:.1f} мс, область {me['area']:.1f}): "
                      f"по замерам {'доминирован, напр. ' + bm['name'] + f' ({bm['t']:.1f} мс, {bm['area']:.1f})' if bm else 'не доминирован'}; "
                      f"недоминирован при c >= {cm if cm is not None else '>1000'}; "
                      f"против блоков любого B: {'доминирован, напр. ' + bo['name'] + f' ({bo['t']:.1f} мс, {bo['area']:.1f})' if bo else 'не доминирован'}; "
                      f"недоминирован при c >= {co if co is not None else '>1000'}")
                out.append({"target": target, "adversary": adv, "hybrid_B": h["B"], "hybrid_ms": me["t"],
                            "hybrid_commits": me["k"], "hybrid_area": me["area"],
                            "dominated_measured_c0": bm is not None,
                            "example_dominator_measured": bm["name"] if bm else "",
                            "c_min_nondominated_measured_ms": cm if cm is not None else ">1000",
                            "dominated_model_c0": bo is not None,
                            "example_dominator_model": (f"{bo['name']}: {bo['t']:.1f} ms, area {bo['area']:.1f}" if bo else ""),
                            "c_min_nondominated_model_ms": co if co is not None else ">1000"})
    with open(OUT, "w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=list(out[0].keys()))
        w.writeheader()
        w.writerows(out)
    print(f"\nсохранено: {OUT}")


if __name__ == "__main__":
    main()
