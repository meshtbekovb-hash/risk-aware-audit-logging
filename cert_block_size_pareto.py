"""
БЛОК 2 ВНЕШНЕЙ ПРОВЕРКИ: ОПРАВДАН ЛИ ГИБРИД? РАЗМЕР БЛОКА И ГРАНИЦА ПАРЕТО
(и БЛОК 3: область поиска для нарушителя без ключа и с ключом)

Логика вопроса. Гибрид с блоком B даёт среднюю область поиска примерно (1-p)*B, где p - доля
записей с поэлементной защитой. Обычная блочная схема с блоком B' = (1-p)*B даёт ту же
область без поэлементной цепочки. Если время блочной схемы от B почти не зависит, такая
замена бесплатна, и гибрид не нужен. Проверяем это измерением, а не рассуждением.

Что измеряется (тот же журнал, что в разделе 6.8: device, тест r4.2 с 2010-10-01, 168 392 записи):
  - B = 1, 2, 5, 10, 25, 50, 100, 250, 500, 1000, 10000;
  - блочная схема write_block_hmac(..., block=B)  - при B=1 измеряется именно она, а не
    поэлементная цепочка (это разные реализации: у блочной метка каждого блока уходит во
    внешнее хранилище, у цепочки метка лежит в строке, во внешнее уходят точки раз в 1000);
  - гибрид: блочная схема с тем же B + поэлементная HMAC-цепочка для записей дней с r >= 0.30;
  - для справки: обычный журнал и поэлементная цепочка для всего журнала.
Для каждой конфигурации:
  - время записи: 20 повторов после 3 прогревочных (не считаются), среднее, std, 95% ДИ;
  - число внешних фиксаций: метки блоков (+ у гибрида контрольные точки цепочки);
  - объём файлов;
  - ожидаемая область поиска при подделке ОДНОЙ записи, выбранной равновероятно: среднее
    число записей, которые аналитику придётся просмотреть. Считается по фактическим
    размерам блоков и фактическому положению записей цепочки, не по формуле; отдельно по
    всем записям и по вредоносным; отдельно для двух моделей нарушителя:
      * без ключа: запись из цепочки локализуется до 1 записи; остальные - до блока;
      * с ключом: нарушитель пересчитывает цепочку, поэтому запись из цепочки обнаруживается
        только на контрольной точке, т.е. до отрезка цепочки между точками (до 1000 записей
        цепочки). Блочная метка всё равно указывает блок (внешнюю метку нарушитель не меняет),
        поэтому аналитик смотрит пересечение «блок ∩ отрезок цепочки». Для сравнения
        сохраняется и вариант «только отрезок цепочки», без пересечения.
      Предположение модели: нарушитель меняет запись согласованно и в журнале, и в её копии
      в цепочке (иначе расхождение копии с журналом было бы отдельным сигналом; сверки копий
      в прототипе нет).
Затем граница Парето (время против средней области поиска) и анализ чувствительности к
цене одной внешней фиксации c: время + c * число фиксаций. Это анализ предположения, а не
измерение: локальная запись в файл не отражает стоимость реального внешнего сервиса.

Ничего не подбирается: τ = 0.30 и признаки те же, что во всём проекте.

Результаты: results_revision/block_size_pareto.csv, results_revision/pareto_frontier.csv,
            results_revision/commit_cost_sensitivity.csv
Запуск (из папки с CSV, долго, ~15 минут):  python cert_block_size_pareto.py
"""

import csv
import math
import os
import time
from collections import Counter
from datetime import timedelta
from statistics import mean, stdev

import cert_ablation as ab
import cert_block_baseline as bb
import cert_chain as ch
import cert_chain_hmac as chm
import cert_honest_split as hs
import cert_riskaware as ra

B_GRID = [1, 2, 5, 10, 25, 50, 100, 250, 500, 1000, 10000]
TAU = 0.30
WARMUP, REPEATS = 3, 20
T_975_DF19 = 2.093                    # квантиль t-распределения для 95% ДИ при 20 повторах
CP = chm.CHECKPOINT_EVERY             # интервал контрольных точек цепочки (1000)
KEY = chm.KEY
TMP = ch.TMP_DIR
P = {n: os.path.join(TMP, f"bsp_{n}.csv") for n in ("plain", "blog", "btags", "clog", "canch")}

OUT_MAIN = "results_revision/block_size_pareto.csv"
OUT_FRONT = "results_revision/pareto_frontier.csv"
OUT_SENS = "results_revision/commit_cost_sensitivity.csv"


def timed(write_fn):
    """20 замеров после 3 прогревочных: среднее, std, 95% ДИ (мс)."""
    vals = []
    for i in range(WARMUP + REPEATS):
        t0 = time.perf_counter()
        write_fn()
        dt = 1000 * (time.perf_counter() - t0)
        if i >= WARMUP:
            vals.append(dt)
    m, s = mean(vals), stdev(vals)
    half = T_975_DF19 * s / math.sqrt(REPEATS)
    return m, s, m - half, m + half


def size_kb(paths):
    return sum(os.path.getsize(p) for p in paths if os.path.exists(p)) / 1024


def block_of(n_total, block):
    """Для каждой позиции 0..n-1: (номер блока, размер этого блока) по фактическим границам."""
    out = []
    for start in range(0, n_total, block):
        size = min(block, n_total - start)
        out.extend([(start // block, size)] * size)
    return out


def search_areas(n_total, block, chain_pos, bad_pos):
    """
    Средняя область поиска (записей к просмотру) при подделке одной равновероятно выбранной
    записи. chain_pos - позиции записей, попавших в поэлементную цепочку (пусто для чистой
    блочной схемы), в порядке журнала. Возвращает словарь со средними по всем и по вредоносным.
    """
    blk = block_of(n_total, block)
    # отрезок цепочки для каждой записи цепочки: j-я запись цепочки -> отрезок j // CP
    seg_of = {pos: j // CP for j, pos in enumerate(chain_pos)}
    seg_size = Counter(seg_of.values())
    inter = Counter((seg_of[pos], blk[pos][0]) for pos in chain_pos)   # |блок ∩ отрезок|

    def area(pos, model):
        if pos in seg_of:
            if model == "no_key":
                return 1
            if model == "key":
                return inter[(seg_of[pos], blk[pos][0])]
            if model == "key_chain_only":
                return seg_size[seg_of[pos]]
        return blk[pos][1]

    res = {}
    for model in ("no_key", "key", "key_chain_only"):
        res[f"area_all_{model}"] = mean(area(p, model) for p in range(n_total))
        res[f"area_bad_{model}"] = mean(area(p, model) for p in bad_pos)
    return res


def pareto(points):
    """points: список (имя, время, область). Возвращает множество имён на границе Парето
    (никакая другая точка не лучше по обоим показателям и строго лучше хотя бы по одному)."""
    front = set()
    for n1, t1, a1 in points:
        dominated = any((t2 <= t1 and a2 <= a1) and (t2 < t1 or a2 < a1) for n2, t2, a2 in points if n2 != n1)
        if not dominated:
            front.add(n1)
    return front


def main():
    windows = ab.load_labels()
    ud = ab.load_events()
    days = sorted({d for _, d in ud})
    train_end = days[0] + timedelta(days=ab.BASELINE_DAYS)
    prof = ab.build_profiles(ud, train_end)
    test_keys = [k for k in ud if k[1] >= hs.TEST_START]
    events = ra.load_test_events(hs.TEST_START)
    rows = [r for r, _, _ in events]
    n = len(rows)
    bad_pos = [i for i, (_, u, d) in enumerate(events) if ab.scenario_of(windows, u, d) is not None]
    flagged = ra.flagged_days(ud, prof, test_keys, TAU)
    chain_pos = [i for i, (_, u, d) in enumerate(events) if (u, d) in flagged]
    chain_rows = [rows[i] for i in chain_pos]
    print(f"журнал: {n} записей, вредоносных {len(bad_pos)}; в цепочке при tau={TAU}: {len(chain_pos)} "
          f"({100 * len(chain_pos) / n:.2f}%), из них вредоносных "
          f"{len(set(chain_pos) & set(bad_pos))} ({100 * len(set(chain_pos) & set(bad_pos)) / len(bad_pos):.1f}%)\n")

    chain_commits = math.ceil(len(chain_rows) / CP)        # точки каждые 1000 + последняя
    results = []

    def add(scheme, B, stats, kb, commits, areas):
        m, s, lo, hi = stats
        row = {"scheme": scheme, "B": B, "mean_ms": round(m, 1), "std_ms": round(s, 1),
               "ci95_lo_ms": round(lo, 1), "ci95_hi_ms": round(hi, 1), "size_kb": round(kb, 1),
               "external_commits": commits}
        row.update({k: round(v, 2) for k, v in areas.items()})
        results.append(row)
        print(f"{scheme:22} B={str(B):>6}  {m:8.1f} ± {s:5.1f} мс  фиксаций {commits:>7}  "
              f"область (все/вредоносные): без ключа {areas['area_all_no_key']:8.1f}/{areas['area_bad_no_key']:8.1f}, "
              f"с ключом {areas['area_all_key']:8.1f}/{areas['area_bad_key']:8.1f}", flush=True)

    # --- для справки: обычный журнал и поэлементная цепочка для всего журнала ---
    st = timed(lambda: ch.write_plain(rows, P["plain"]))
    add("plain log", "-", st, size_kb([P["plain"]]), 0,
        {f"area_{s}_{m}": float("nan") for s in ("all", "bad") for m in ("no_key", "key", "key_chain_only")})

    st = timed(lambda: chm.write_hmac_chain(rows, P["clog"], P["canch"], KEY))
    add("per-record chain, all", "-", st, size_kb([P["clog"], P["canch"]]), math.ceil(n / CP),
        search_areas(n, n, list(range(n)), bad_pos))      # блоков нет: B = n, вся запись в цепочке

    # --- блочная схема и гибрид по сетке B ---
    for B in B_GRID:
        st = timed(lambda: bb.write_block_hmac(rows, P["blog"], P["btags"], KEY, B))
        add("block", B, st, size_kb([P["blog"], P["btags"]]), math.ceil(n / B),
            search_areas(n, B, [], bad_pos))

        def write_hybrid():
            bb.write_block_hmac(rows, P["blog"], P["btags"], KEY, B)
            chm.write_hmac_chain(chain_rows, P["clog"], P["canch"], KEY)
        st = timed(write_hybrid)
        add("hybrid tau=0.30", B, st, size_kb([P["blog"], P["btags"], P["clog"], P["canch"]]),
            math.ceil(n / B) + chain_commits, search_areas(n, B, chain_pos, bad_pos))

    with open(OUT_MAIN, "w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=list(results[0].keys()))
        w.writeheader()
        w.writerows(results)

    # --- граница Парето: время против области поиска, 4 варианта (все/вредоносные x без ключа/с ключом) ---
    protected = [r for r in results if r["scheme"] != "plain log"]
    name = lambda r: f"{r['scheme']} B={r['B']}"
    front_rows = []
    print("\nГРАНИЦА ПАРЕТО (время записи, мс, против средней области поиска, записей)")
    for target in ("all", "bad"):
        for model in ("no_key", "key"):
            col = f"area_{target}_{model}"
            pts = [(name(r), r["mean_ms"], r[col]) for r in protected]
            front = pareto(pts)
            hybrids_on = sorted(p for p in front if p.startswith("hybrid"))
            print(f"  [{target}, {model}] на границе: {sorted(front, key=lambda s: dict((p[0], p[1]) for p in pts)[s])}")
            print(f"      гибрид на границе: {'ДА: ' + ', '.join(hybrids_on) if hybrids_on else 'НЕТ'}")
            for r in protected:
                # кто доминирует эту точку (для недоминированных пусто)
                t1, a1 = r["mean_ms"], r[col]
                dom = [name(q) for q in protected if q is not r and q["mean_ms"] <= t1 and q[col] <= a1
                       and (q["mean_ms"] < t1 or q[col] < a1)]
                front_rows.append({"target": target, "adversary": model, "config": name(r),
                                   "mean_ms": t1, "area": a1, "on_frontier": name(r) in front,
                                   "dominated_by": "; ".join(dom[:4])})
    with open(OUT_FRONT, "w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=list(front_rows[0].keys()))
        w.writeheader()
        w.writerows(front_rows)

    # --- чувствительность к цене одной внешней фиксации c (мс) ---
    c_grid = [0] + [round(10 ** (e / 4), 4) for e in range(-16, 13)]      # 0 и 1e-4 ... 1e3 мс
    sens = []
    print("\nЧУВСТВИТЕЛЬНОСТЬ: время + c * число внешних фиксаций (предположение, не измерение)")
    for target in ("all", "bad"):
        for model in ("no_key", "key"):
            col = f"area_{target}_{model}"
            first_c = None
            for c in c_grid:
                pts = [(name(r), r["mean_ms"] + c * r["external_commits"], r[col]) for r in protected]
                front = pareto(pts)
                hyb = sorted(p for p in front if p.startswith("hybrid"))
                sens.append({"target": target, "adversary": model, "c_ms_per_commit": c,
                             "hybrids_on_frontier": "; ".join(hyb)})
                if hyb and first_c is None:
                    first_c = (c, hyb)
            print(f"  [{target}, {model}] гибрид впервые недоминирован при c = "
                  f"{first_c[0] if first_c else 'нигде в диапазоне 0..1000 мс'}"
                  f"{' (' + ', '.join(first_c[1]) + ')' if first_c else ''}")
    with open(OUT_SENS, "w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=list(sens[0].keys()))
        w.writeheader()
        w.writerows(sens)

    for p in P.values():
        if os.path.exists(p):
            os.remove(p)
    print(f"\nсохранено: {OUT_MAIN}, {OUT_FRONT}, {OUT_SENS}")


if __name__ == "__main__":
    main()
