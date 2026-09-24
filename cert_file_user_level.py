"""
file.csv ПО ЧЕСТНОМУ ПРОТОКОЛУ (разбиение обучение/валидация/тест, метрики по пользователям)

Раньше file.csv оценивался только по старому протоколу (весь период, дневные метрики).
Здесь те же правила, что и для device и logon (cert_user_level2.py):
  - обучение до 2010-05-02, валидация до 2010-10-01, тест с 2010-10-01;
  - порог риска и (N, W) выбираются ТОЛЬКО на валидации: наибольший user-recall
    при user-FPR не выше 3%; на тест идёт уже выбранная комбинация;
  - метрики по пользователям, интервалы Уилсона, парный тест знаков.

Конфигурации: file (только копирование файлов) и device+file.
Для сравнения печатается device из основной таблицы.

Признаки file (веса задавались по аналогии с device, под разметку не подбирались):
novel_file_off_hours 0.65, file_spike 0.30, novel_file_ext 0.30.

Ограничение: пары (пользователь, день), где были ТОЛЬКО события file.csv (без входов и без
подключений носителя), в этой оценке не учитываются, потому что общий каркас строится по logon и device.

Результат: file_user_level_results.csv
Запуск (из папки с CSV):  python cert_file_user_level.py
"""

import csv
from collections import defaultdict
from itertools import combinations

import cert_ablation as ab
import cert_file as cf
import cert_honest_split as hs
import cert_user_level2 as u2

OUTPUT_FILE = "file_user_level_results.csv"
FILE_FEATURES = list(cf.FILE_WEIGHTS)                    # три признака file.csv
ALL_WEIGHTS = {**ab.WEIGHTS, **cf.FILE_WEIGHTS}
CONFIGS = {"file": FILE_FEATURES,
           "device+file": hs.CONFIG_FEATURES["device"] + FILE_FEATURES}


def levels(features):
    """Все возможные значения оценки риска (суммы весов по подмножествам, максимум 1)."""
    out = set()
    for r in range(1, len(features) + 1):
        for sub in combinations(features, r):
            out.add(round(min(sum(ALL_WEIGHTS[f] for f in sub), 1.0), 2))
    return sorted(out)


def main():
    st = u2.Setup()
    fd = cf.load_file_events()
    fprof = cf.build_file_profiles(fd, st.train_end)

    # Признаки каждого дня: 5 признаков logon/device (из шаблона) + 3 признака file
    active = {}
    for keys, _ in st.parts.values():
        for k in keys:
            feats = dict(zip(hs.FEATURES, st.pattern[k]))
            feats.update(cf.file_features(fd.get(k), fprof.get(k[0]), ab.BASELINE_DAYS))
            active[k] = feats

    cache = {}

    def alerts(part, cfg, cutoff):
        """Тревожные дни по пользователям: оценка дня по признакам конфигурации не ниже порога."""
        key = (part, cfg, cutoff)
        if key not in cache:
            days = defaultdict(list)
            for k in st.parts[part][0]:
                s = round(min(sum(ALL_WEIGHTS[f] for f in CONFIGS[cfg] if active[k][f]), 1.0), 2)
                if s >= cutoff:
                    days[k[0]].append(k[1])
            for u in days:
                days[u].sort()
            cache[key] = days
        return cache[key]

    def run(part, cfg, cutoff, n, w):
        return u2.evaluate(alerts(part, cfg, cutoff), None, st.parts[part][1], st.normal[part], n, w)

    results, rows = {}, []
    for cfg in CONFIGS:
        best = None
        for cutoff in levels(CONFIGS[cfg]):
            for n in u2.N_VALUES:
                for w in u2.W_VALUES:
                    v = run("валидация", cfg, cutoff, n, w)
                    if v["fpr"] > u2.TARGET_FPR:
                        continue
                    key = (v["recall"], v["fpr"])
                    if best is None or key > best[0]:
                        best = (key, cutoff, n, w, v)
        if best is None:
            print(f"{cfg}: на валидации нет правила с user-FPR не выше 3%")
            continue
        _, cutoff, n, w, v = best
        t = run("тест", cfg, cutoff, n, w)                        # тест: один раз
        results[cfg] = t
        sc = ", ".join(f"сц.{s}: {t['by_sc'].get(s, 0)}/{t['total_sc'][s]}" for s in sorted(t["total_sc"]))
        lo, hi = u2.wilson(len(t["caught"]), 35)
        print(f"{cfg:12} порог {cutoff}, N={n}, W={w} | валидация {len(v['caught'])}/35 FPR {100 * v['fpr']:.1f}% | "
              f"ТЕСТ recall {len(t['caught'])}/35 = {100 * t['recall']:.1f}% [{100 * lo:.1f}; {100 * hi:.1f}], "
              f"user-FPR {100 * t['fpr']:.1f}% ({len(t['false'])}/{len(st.normal['тест'])}) | {sc}")
        rows.append({"config": cfg, "cutoff": cutoff, "N": n, "W": w,
                     "val_recall": round(v["recall"], 4), "val_fpr": round(v["fpr"], 4),
                     "test_caught": len(t["caught"]), "test_recall": round(t["recall"], 4),
                     "test_fpr": round(t["fpr"], 4), "test_false_users": len(t["false"])})

    # Сравнение с device (основная таблица), тот же протокол
    used = hs.CONFIG_FEATURES["device"]
    p, _ = u2.select_on_validation(st, used, hybrid=False)
    dev = st.run("тест", used, p["cutoff"], p["N"], p["W"])
    print(f"\ndevice (основная таблица): порог {p['cutoff']}, N={p['N']}, W={p['W']} | ТЕСТ "
          f"{len(dev['caught'])}/35, user-FPR {100 * dev['fpr']:.1f}%")
    print("\nПарное сравнение с device (тест знаков; меньше 5 дискордантных пар = теста без мощности):")
    for cfg, t in results.items():
        a, b = len(dev["caught"] - t["caught"]), len(t["caught"] - dev["caught"])
        note = "тест без мощности" if a + b < 5 else "мощность достаточна"
        print(f"  device против {cfg}: только device {a}, только {cfg} {b}, p = {u2.sign_test(a, b):.4f} ({note})")

    with open(OUTPUT_FILE, "w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=list(rows[0].keys()))
        w.writeheader()
        w.writerows(rows)
    print(f"\nТаблица сохранена: {OUTPUT_FILE}")


if __name__ == "__main__":
    main()
