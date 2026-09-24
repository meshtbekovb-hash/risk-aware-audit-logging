"""
ЗАДАЧА 10 REVISION_PLAN.md (доп. правка): СОПОСТАВИМОЕ СРАВНЕНИЕ FPR r4.2 vs r5.2

Замечание: раздел 15.4 сравнивал user FPR device r4.2 (11.5%) и r5.2 (13.0%) как "почти
не изменился". Это некорректно: user FPR определён как "помечен хотя бы раз ЗА ВЕСЬ
ПЕРИОД", а периоды разной длины - r4.2 тест 228 дней (2010-10-01..2011-05-17), r5.2 тест
396 дней (2010-05-02..2011-06-02), в 1.74 раза длиннее. FPR механически растёт с длиной
наблюдения даже при одинаковой "истинной" частоте ложных тревог.

Два способа привести к сопоставимому виду:
  1. Уже посчитанная метрика "ложных тревог на пользователя в месяц" (раздел 18,
     results_revision/detection_metrics.csv) - она уже нормирована на длину периода,
     просто раньше не была использована для ЭТОГО сравнения явно.
  2. Усечь тестовый период r5.2 до 228 дней (длина r4.2) и ПОЛНОСТЬЮ пересчитать user
     recall и user FPR на усечённом окне, тем же замороженным порогом device
     (tau=0.65, N=2, W=7). Инсайдеры, чьё окно атаки НАЧИНАЕТСЯ после точки усечения,
     из усечённого теста выпадают - считаем, сколько.

Метод не меняется нигде. Результат: results_revision/r52_fpr_normalized.csv
Запуск (из папки с CSV):  python cert_r52_fpr_normalized.py
"""

import csv
from datetime import timedelta

import cert_ablation as ab
import cert_honest_split as hs
import cert_user_level as ul
import cert_user_level2 as u2
import cert_r52_external_test as r52

OUTPUT_FILE = "results_revision/r52_fpr_normalized.csv"
FROZEN_DEVICE = {"cutoff": 0.65, "N": 2, "W": 7}   # тот же порог, что везде для device


def main():
    print("=" * 100)
    print("1. Точные длины тестовых периодов")
    print("=" * 100)
    # Берём точные даты так же, как их считают остальные скрипты (максимум дня в данных),
    # а не переписываем вручную - чтобы не разойтись с тем, что реально в CSV.
    st = u2.Setup()
    r42_end = max(d for _, d in st.ud)
    r42_start = hs.TEST_START
    r42_len = (r42_end - r42_start).days
    print(f"r4.2 тест: {r42_start} .. {r42_end} = {r42_len} дней")

    windows52 = r52.load_labels_r52()
    ud52 = r52.load_events_r52()
    days52 = sorted({d for _, d in ud52})
    train_end52 = days52[0] + timedelta(days=ab.BASELINE_DAYS)
    r52_end = max(d for _, d in ud52)
    r52_len = (r52_end - train_end52).days
    print(f"r5.2 тест: {train_end52} .. {r52_end} = {r52_len} дней")
    print(f"отношение длин: {r52_len / r42_len:.3f}x\n")

    prof52 = ab.build_profiles(ud52, train_end52)
    info_all52 = {u: min(w, key=lambda x: x[1]) for u, w in windows52.items()}

    print("=" * 100)
    print("2. Способ 1: уже посчитанная метрика 'ложных тревог на пользователя в месяц' (раздел 18)")
    print("=" * 100)
    dm = {(r["dataset"], r["config"]): r for r in csv.DictReader(open("results_revision/detection_metrics.csv", encoding="utf-8"))}
    r42_rate = float(dm[("r4.2", "device")]["false_alerts_per_user_per_month"])
    r52_rate = float(dm[("r5.2", "device")]["false_alerts_per_user_per_month"])
    print(f"device, r4.2: {r42_rate:.4f} ложных тревожных дней на пользователя в месяц")
    print(f"device, r5.2: {r52_rate:.4f} ложных тревожных дней на пользователя в месяц")
    print(f"r5.2 / r4.2: {r52_rate / r42_rate:.3f}x  (< 1 значит на r5.2 РЕЖЕ, не 'почти так же')\n")

    print("=" * 100)
    print(f"3. Способ 2: усечь тест r5.2 до {r42_len} дней ({r42_len} = длина теста r4.2) и пересчитать")
    print("=" * 100)
    cutoff52 = train_end52 + timedelta(days=r42_len)
    print(f"усечённое окно r5.2: {train_end52} .. {cutoff52} ({r42_len} дней, как у r4.2)\n")

    test_keys52_trunc = [k for k in ud52 if train_end52 <= k[1] < cutoff52]
    normal_test52_trunc = {k[0] for k in test_keys52_trunc} - set(windows52)

    insiders_full = {u: v for u, v in info_all52.items() if v[1] >= train_end52}
    insiders_trunc = {u: v for u, v in insiders_full.items() if v[1] < cutoff52}
    dropped = {u: v for u, v in insiders_full.items() if v[1] >= cutoff52}
    print(f"инсайдеров в полном тесте r5.2 (396 дней): {len(insiders_full)}")
    print(f"инсайдеров в усечённом тесте r5.2 ({r42_len} дней): {len(insiders_trunc)}")
    print(f"выпало при усечении (окно атаки начинается ПОСЛЕ {cutoff52}): {len(dropped)}")
    by_sc_dropped = {}
    for u, (sc, s, e) in dropped.items():
        by_sc_dropped.setdefault(sc, []).append(u)
    for sc in sorted(by_sc_dropped):
        print(f"  сценарий {sc}: {len(by_sc_dropped[sc])} выпало из него")
    print()

    # Тревожные дни по замороженному порогу device, ТОЛЬКО в усечённом окне
    used = hs.CONFIG_FEATURES["device"]
    alerts = {}
    for k in test_keys52_trunc:
        pat = hs.day_pattern(ud52[k], prof52.get(k[0]))
        s = round(hs.pattern_score(pat, ab.WEIGHTS, used), 2)
        if s >= FROZEN_DEVICE["cutoff"]:
            alerts.setdefault(k[0], []).append(k[1])
    for u in alerts:
        alerts[u].sort()

    caught, by_sc, total_sc = set(), {}, {}
    for u, (sc, s, e) in insiders_trunc.items():
        total_sc[sc] = total_sc.get(sc, 0) + 1
        fired = ul.firing_days(alerts.get(u, []), FROZEN_DEVICE["N"], FROZEN_DEVICE["W"])
        if any(s <= t <= e for t in fired):
            caught.add(u)
            by_sc[sc] = by_sc.get(sc, 0) + 1

    false_users = {u for u in normal_test52_trunc if ul.firing_days(alerts.get(u, []), FROZEN_DEVICE["N"], FROZEN_DEVICE["W"])}

    n_ins, n_norm = len(insiders_trunc), len(normal_test52_trunc)
    recall = len(caught) / n_ins if n_ins else 0.0
    fpr = len(false_users) / n_norm if n_norm else 0.0
    r_lo, r_hi = u2.wilson(len(caught), n_ins)
    f_lo, f_hi = u2.wilson(len(false_users), n_norm)

    print(f"На усечённом окне r5.2 ({r42_len} дней, device, tau=0.65,N=2,W=7 - те же параметры, не подбирались):")
    print(f"  инсайдеров: {n_ins}, обычных: {n_norm}")
    print(f"  user recall: {len(caught)}/{n_ins} = {100*recall:.1f}% [{100*r_lo:.1f};{100*r_hi:.1f}]")
    print(f"  user FPR:    {len(false_users)}/{n_norm} = {100*fpr:.1f}% [{100*f_lo:.1f};{100*f_hi:.1f}]")
    for sc in sorted(total_sc):
        print(f"  сц.{sc}: {by_sc.get(sc,0)}/{total_sc[sc]}")

    # Для сравнения рядом - полный (нетронутый) результат r5.2 device (396 дней) и r4.2 (228 дней)
    r42_row = dm[("r4.2", "device")]
    full52 = {
        "user_recall": 30/98, "user_fpr": 48/1865,   # из результатов задачи 2 (раздел 15.3), не пересчитываются
    }

    rows = [
        {"period": "r4.2 тест (228 дн., как есть)", "insiders_total": 35, "insiders_caught": 18,
         "user_recall_pct": round(100*18/35, 1), "normal_total": 888, "normal_false": 21,
         "user_fpr_pct": round(100*21/888, 2),
         "false_alerts_per_user_per_month": r42_rate, "note": "из раздела 15.3/18.2, не пересчитано"},
        {"period": "r5.2 тест (396 дн., полный, как в разделе 15)", "insiders_total": 98, "insiders_caught": 30,
         "user_recall_pct": round(100*30/98, 1), "normal_total": 1865, "normal_false": 48,
         "user_fpr_pct": round(100*48/1865, 2),
         "false_alerts_per_user_per_month": r52_rate, "note": "из раздела 15.3/18.2, не пересчитано"},
        {"period": f"r5.2 тест УСЕЧЁН до {r42_len} дн. (= длина r4.2)", "insiders_total": n_ins,
         "insiders_caught": len(caught), "user_recall_pct": round(100*recall, 1),
         "normal_total": n_norm, "normal_false": len(false_users), "user_fpr_pct": round(100*fpr, 2),
         "false_alerts_per_user_per_month": "",
         "note": f"пересчитано заново на усечённом окне; {len(dropped)} инсайдеров выпало "
                 f"(окно атаки начинается после {cutoff52})"},
    ]
    with open(OUTPUT_FILE, "w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=list(rows[0].keys()))
        w.writeheader()
        w.writerows(rows)
    print(f"\nТаблица сохранена: {OUTPUT_FILE}")


if __name__ == "__main__":
    main()
