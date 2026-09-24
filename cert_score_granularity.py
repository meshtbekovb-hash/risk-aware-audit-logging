"""
ЗАДАЧА 14 (доп. правки по повторному ревью): ГРАДАЦИЯ ШКАЛЫ РИСКА И МЕДИАНА ОКНА СЦЕНАРИЯ 4

Часть 1. Медиана длины окна атаки сценария 4 (r5.2) по двум выборкам:
  - все 30 инсайдеров сценария 4;
  - 29 инсайдеров тестовой части (без исключённого по границе обучающего периода).
  В разделе 15.4 стояло 71, в разделе 23.4 - 73.5; здесь выясняем, откуда расхождение.

Часть 2. Какие значения оценки риска ФАКТИЧЕСКИ встречаются на тестовом журнале r4.2
  (с 2010-10-01) для трёх конфигураций: device, logon+device, device_single, и сколько
  пользователь-дней и записей device.csv приходится на каждое значение.
  device_single = только признак novel_dev_off_hours с его родным весом 0.65.

Часть 3. Для device_single на том же журнале, что в разделе 6.8 (168 392 записи device
  тестового периода): какая доля записей попадает под поэлементную защиту (день с
  оценкой >= tau) и какая доля вредоносных записей ею покрыта. Сравнение с тремя
  точками device (tau = 0.30, 0.65, 0.95).

Ничего не подбирается: веса, пороги новизны и признаки - те же, что во всём проекте.

Результат: results_revision/score_granularity.csv, results_revision/scenario4_window_length.csv
Запуск (из папки с CSV):  python cert_score_granularity.py
"""

import csv
from collections import Counter, defaultdict
from datetime import timedelta
from statistics import median, mean

import cert_ablation as ab
import cert_honest_split as hs
import cert_riskaware as ra
import cert_r52_external_test as r52

OUT_GRAN = "results_revision/score_granularity.csv"
OUT_SC4 = "results_revision/scenario4_window_length.csv"


# ---------------------------------------------------------------
# Часть 1. Медиана окна сценария 4
# ---------------------------------------------------------------
def scenario4_windows():
    windows = r52.load_labels_r52()
    ud = r52.load_events_r52()
    days = sorted({d for _, d in ud})
    train_end = days[0] + timedelta(days=ab.BASELINE_DAYS)
    # одно окно на пользователя - так же, как в cert_r52_external_test.py
    info = {u: min(w, key=lambda x: x[1]) for u, w in windows.items()}
    sc4 = {u: v for u, v in info.items() if v[0] == "4"}
    rows = []
    for u, (sc, s, e) in sorted(sc4.items()):
        rows.append({"user": u, "window_start": s, "window_end": e,
                     "window_days": (e - s).days + 1,
                     "in_test_sample": s >= train_end})
    return rows, train_end


def describe(lens):
    return f"n={len(lens)}, мин {min(lens)}, медиана {median(lens)}, среднее {mean(lens):.1f}, макс {max(lens)}"


# ---------------------------------------------------------------
# Часть 2-3. Оценка риска по конфигурациям
# ---------------------------------------------------------------
def score_single(v, pr):
    """device_single: только novel_dev_off_hours, родной вес 0.65."""
    if not pr or pr["days"] == 0:
        return 0.0
    on = ab.device_features(v, pr)["novel_dev_off_hours"]
    return ab.WEIGHTS["novel_dev_off_hours"] if on else 0.0


CONFIGS = {
    "device": lambda v, pr: ab.score(v, pr, "device"),
    "logon+device": lambda v, pr: ab.score(v, pr, "combined"),
    "device_single": score_single,
}


def main():
    # ---- Часть 1 ----
    sc4_rows, train_end52 = scenario4_windows()
    all_lens = [r["window_days"] for r in sc4_rows]
    test_lens = [r["window_days"] for r in sc4_rows if r["in_test_sample"]]
    excluded = [r for r in sc4_rows if not r["in_test_sample"]]
    print("ЧАСТЬ 1. Длина окна атаки, сценарий 4, r5.2")
    print(f"  все инсайдеры сценария 4:        {describe(all_lens)}")
    print(f"  тестовая выборка (начало >= {train_end52}): {describe(test_lens)}")
    for r in excluded:
        print(f"  исключён: {r['user']}, окно {r['window_start']}..{r['window_end']} = {r['window_days']} дн.")
    with open(OUT_SC4, "w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=list(sc4_rows[0].keys()))
        w.writeheader()
        w.writerows(sc4_rows)

    # ---- Часть 2 ----
    windows = ab.load_labels()
    ud = ab.load_events()
    days = sorted({d for _, d in ud})
    train_end = days[0] + timedelta(days=ab.BASELINE_DAYS)
    prof = ab.build_profiles(ud, train_end)
    test_keys = [k for k in ud if k[1] >= hs.TEST_START]

    events = ra.load_test_events(hs.TEST_START)           # тот же журнал, что в разделе 6.8
    total = len(events)
    is_bad = [ab.scenario_of(windows, u, d) is not None for _, u, d in events]
    total_bad = sum(is_bad)
    print(f"\nЖурнал device тестового периода: {total} записей, вредоносных {total_bad}")

    # оценка каждого пользователь-дня теста по каждой конфигурации
    day_score = {name: {k: round(fn(ud[k], prof.get(k[0])), 2) for k in test_keys}
                 for name, fn in CONFIGS.items()}

    out = []
    print("\nЧАСТЬ 2. Фактические значения оценки риска на тесте r4.2")
    for name in CONFIGS:
        sc = day_score[name]
        days_by = Counter(sc.values())
        rec_by, bad_by = Counter(), Counter()
        for (_, u, d), b in zip(events, is_bad):
            s = sc.get((u, d), 0.0)
            rec_by[s] += 1
            bad_by[s] += b
        print(f"\n  {name}: достижимые значения {sorted(days_by)}")
        print(f"    {'оценка':>7} {'польз.-дней':>12} {'записей device':>15} {'доля записей':>13} {'вредоносных':>12}")
        for s in sorted(days_by):
            print(f"    {s:7.2f} {days_by[s]:12d} {rec_by[s]:15d} {100*rec_by[s]/total:12.2f}% {bad_by[s]:12d}")
            out.append({"part": "distribution", "config": name, "score_value": s,
                        "user_days": days_by[s], "device_records": rec_by[s],
                        "device_records_pct": round(100 * rec_by[s] / total, 2),
                        "malicious_records": bad_by[s], "tau": "", "records_protected_pct": "",
                        "malicious_protected_pct": ""})

    # ---- Часть 3 ----
    print("\nЧАСТЬ 3. Поэлементная защита: доля записей и доля вредоносных под защитой")
    flagged_sets = {}
    for name in ("device", "device_single"):
        levels = sorted(v for v in set(day_score[name].values()) if v > 0)
        for tau in levels:
            flagged = {k for k, s in day_score[name].items() if s >= tau}
            flagged_sets[(name, tau)] = flagged
            n_in = sum(1 for _, u, d in events if (u, d) in flagged)
            n_bad = sum(1 for (_, u, d), b in zip(events, is_bad) if b and (u, d) in flagged)
            rp, bp = round(100 * n_in / total, 2), round(100 * n_bad / total_bad, 1)
            print(f"  {name:14} tau={tau:.2f}: записей под защитой {rp}%, вредоносных {bp}%")
            out.append({"part": "protection", "config": name, "score_value": "", "user_days": len(flagged),
                        "device_records": n_in, "device_records_pct": "", "malicious_records": n_bad,
                        "tau": tau, "records_protected_pct": rp, "malicious_protected_pct": bp})

    # Любой tau в (0; 0.65] даёт у device_single одно и то же множество дней - проверяем прямо
    single_any = {k for k, s in day_score["device_single"].items() if s >= 0.30}
    print(f"\n  device_single при tau=0.30 и tau=0.65 - одно и то же множество дней: "
          f"{single_any == flagged_sets[('device_single', 0.65)]}")
    print(f"  device_single (tau=0.65) и device (tau=0.65) - одно и то же множество дней: "
          f"{flagged_sets[('device_single', 0.65)] == flagged_sets[('device', 0.65)]}")

    with open(OUT_GRAN, "w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=list(out[0].keys()))
        w.writeheader()
        w.writerows(out)
    print(f"\nсохранено: {OUT_GRAN}, {OUT_SC4}")


if __name__ == "__main__":
    main()
