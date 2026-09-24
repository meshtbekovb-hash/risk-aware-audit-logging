"""
МЕТРИКИ НА УРОВНЕ ПОЛЬЗОВАТЕЛЕЙ: recall и FPR рядом, правило накопления тревог

Проблема. Дневной FPR (доля обычных ДНЕЙ с тревогой) и "пользователь пойман, если
у него была хотя бы одна тревога" несопоставимы. При дневном FPR около 1% за
сотни дней почти любой обычный сотрудник хоть раз получает случайную тревогу.
Поэтому считаем оба показателя по ПОЛЬЗОВАТЕЛЯМ и кладём рядом:

  user-level recall = доля инсайдеров, помеченных внутри окна своей атаки
  user-level FPR    = доля НЕинсайдеров, получивших пометку хотя бы раз за период

Правило накопления (N, W): пользователь помечается в день t, если среди последних
W дней (включая t) у него не менее N тревожных дней. N=1 - прежняя метрика
("хотя бы одна тревога"), при N>=2 разовые случайные тревоги перестают
приводить к пометке.

Разбиение то же, что в cert_honest_split.py:
  обучение   до 2010-05-02   - профили
  валидация  до 2010-10-01   - здесь ПОДБИРАЕМ (N, W)
  тест       с 2010-10-01    - только отчёт, на нём ничего не подбирается

Правило выбора (N, W): наибольший user-level recall при user-level FPR не выше 5%,
оба показателя считаются на ВАЛИДАЦИИ. Результат на тесте печатается для отчёта.

Дневной расчёт (cert_ablation.py) не меняется.

Результат: user_level_results.csv
Запуск (из папки с CSV):  python cert_user_level.py
"""

import csv
from datetime import timedelta
from statistics import median
from collections import defaultdict

import cert_ablation as ab
import cert_honest_split as hs

OUTPUT_FILE = "user_level_results.csv"
N_VALUES = [1, 2, 3, 4, 5]
W_VALUES = [7, 14, 30]
MAX_USER_FPR = 0.05          # ограничение для рабочей точки: не более 5% невиновных

# (название, источники признаков, порог тревоги в день)
CONFIGS = [("logon", "logon", 0.75),
           ("device", "device", 0.30),
           ("device (порог 0.65)", "device", 0.65),
           ("logon+device", "combined", 0.60)]


def alert_days_by_user(keys, ud, prof, used, cutoff):
    """
    Для каждого пользователя - отсортированный список дней с тревогой.
    День тревожный, если оценка риска шаблона дня не ниже порога.
    """
    days = defaultdict(list)
    for k in keys:
        pat = hs.day_pattern(ud[k], prof.get(k[0]))
        if round(hs.pattern_score(pat, ab.WEIGHTS, used), 2) >= cutoff:
            days[k[0]].append(k[1])
    for u in days:
        days[u].sort()
    return days


def firing_days(alert_days, n, w):
    """
    Дни, в которые правило (N, W) срабатывает: день t тревожный и среди
    тревожных дней из интервала [t - W + 1, t] их не менее N.
    Идём по тревожным дням слева направо, "левый край" окна двигаем вперёд.
    """
    fired, left = [], 0
    for right, t in enumerate(alert_days):
        while (t - alert_days[left]).days >= w:   # день вышел за окно в W дней
            left += 1
        if right - left + 1 >= n:                 # в окне достаточно тревог
            fired.append(t)
    return fired


def evaluate(alerts, insiders, normal_users, n, w):
    """
    Считает user-level метрики для правила (N, W).
    insiders - {пользователь: (сценарий, начало окна, конец окна)} этой части.
    normal_users - множество неинсайдеров этой части.
    """
    caught, delays, by_sc, total_sc = set(), [], defaultdict(int), defaultdict(int)
    for u, (sc, start, end) in insiders.items():
        total_sc[sc] += 1
        inside = [t for t in firing_days(alerts.get(u, []), n, w) if start <= t <= end]
        if inside:                                # сработало внутри окна атаки
            caught.add(u)
            by_sc[sc] += 1
            delays.append((inside[0] - start).days)
    false_users = {u for u in normal_users if firing_days(alerts.get(u, []), n, w)}
    return {
        "insiders_caught": len(caught), "insiders_total": len(insiders),
        "recall": len(caught) / len(insiders) if insiders else 0.0,
        "false_users": len(false_users), "normal_users": len(normal_users),
        "fpr": len(false_users) / len(normal_users) if normal_users else 0.0,
        "median_delay_days": median(delays) if delays else "",
        "caught_by_scenario": {s: by_sc[s] for s in total_sc},
        "total_by_scenario": dict(total_sc),
    }


def main():
    windows = ab.load_labels()
    ud = ab.load_events()
    days = sorted({d for _, d in ud})
    train_end = days[0] + timedelta(days=ab.BASELINE_DAYS)
    prof = ab.build_profiles(ud, train_end)

    # Окна атак каждого инсайдера: (сценарий, начало, конец) по его первому окну
    info = {u: min(w, key=lambda x: x[1]) for u, w in windows.items()}
    parts = {
        "валидация": ([k for k in ud if train_end <= k[1] < hs.TEST_START],
                      {u: v for u, v in info.items() if v[1] < hs.TEST_START}),
        "тест": ([k for k in ud if k[1] >= hs.TEST_START],
                 {u: v for u, v in info.items() if v[1] >= hs.TEST_START}),
    }
    # Неинсайдеры: пользователи с активностью в части, которых нет в разметке
    normal = {name: {k[0] for k in keys} - set(windows) for name, (keys, _) in parts.items()}
    for name, (keys, ins) in parts.items():
        print(f"{name}: инсайдеров {len(ins)}, неинсайдеров {len(normal[name])}")
    print(f"Ограничение для выбора: user-level FPR не выше {MAX_USER_FPR:.0%} (на валидации)\n")

    rows = []
    for cfg_name, cfg, cutoff in CONFIGS:
        used = hs.CONFIG_FEATURES[cfg]
        alerts = {name: alert_days_by_user(keys, ud, prof, used, cutoff)
                  for name, (keys, _) in parts.items()}
        results = {}
        for n in N_VALUES:
            for w in W_VALUES:
                for name, (_, ins) in parts.items():
                    results[(n, w, name)] = evaluate(alerts[name], ins, normal[name], n, w)

        print(f"=== {cfg_name}, порог дня {cutoff} ===")
        print("  N  W | ВАЛИДАЦИЯ recall  FPR     | ТЕСТ recall  FPR   (ложно затронуто) | по сценариям на тесте")
        for n in N_VALUES:
            for w in W_VALUES:
                v, t = results[(n, w, "валидация")], results[(n, w, "тест")]
                cs, ts = t["caught_by_scenario"], t["total_by_scenario"]
                sc = " ".join(f"{s}:{cs.get(s, 0)}/{ts[s]}" for s in sorted(ts))
                print(f"  {n}  {w:>2} | {v['insiders_caught']:>2}/{v['insiders_total']} "
                      f"{100 * v['recall']:5.1f}%  {100 * v['fpr']:5.1f}%  | "
                      f"{t['insiders_caught']:>2}/{t['insiders_total']} {100 * t['recall']:5.1f}%  "
                      f"{100 * t['fpr']:5.1f}%  ({t['false_users']:>3}) | {sc}")
                for name in ("валидация", "тест"):
                    r = results[(n, w, name)]
                    rows.append({"config": cfg_name, "cutoff": cutoff, "N": n, "W": w,
                                 "part": name, "insiders_caught": r["insiders_caught"],
                                 "insiders_total": r["insiders_total"],
                                 "user_recall": round(r["recall"], 4),
                                 "false_users": r["false_users"],
                                 "normal_users": r["normal_users"],
                                 "user_fpr": round(r["fpr"], 4),
                                 "median_delay_days": r["median_delay_days"]})

        # Выбор рабочей точки ТОЛЬКО по валидации
        ok = [(k, results[k]) for k in results
              if k[2] == "валидация" and results[k]["fpr"] <= MAX_USER_FPR]
        if not ok:
            print("  -> на валидации нет правила с user-level FPR не выше 5%\n")
            continue
        (n, w, _), best = max(ok, key=lambda x: (x[1]["recall"], -x[1]["fpr"], -x[0][1]))
        t = results[(n, w, "тест")]
        print(f"  -> выбрано на валидации: N={n}, W={w} "
              f"(recall {best['insiders_caught']}/{best['insiders_total']}, "
              f"FPR {100 * best['fpr']:.1f}%)")
        print(f"     на ТЕСТЕ: recall {t['insiders_caught']}/{t['insiders_total']} "
              f"({100 * t['recall']:.1f}%), FPR {100 * t['fpr']:.1f}% "
              f"({t['false_users']} из {t['normal_users']} невиновных), "
              f"медиана задержки {t['median_delay_days']} дн.\n")

    with open(OUTPUT_FILE, "w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=list(rows[0].keys()))
        w.writeheader()
        w.writerows(rows)
    print(f"Таблица сохранена: {OUTPUT_FILE}")


if __name__ == "__main__":
    main()
