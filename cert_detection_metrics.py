"""
ЗАДАЧА 5 REVISION_PLAN.md: ДОПОЛНИТЕЛЬНЫЕ МЕТРИКИ ОБНАРУЖЕНИЯ

Для трёх замороженных конфигураций (logon, device, logon+device; tau/N/W - выбор на
валидации r4.2, тот же, что в задачах 2 и 4) считает на r4.2 И на r5.2 (задача 2 уже
сделана):

  1. Precision и F1 на уровне пользователей.
  2. PR-AUC: перебор tau при ЗАМОРОЖЕННЫХ N, W (той же конфигурации), кривая
     precision/recall на тесте, площадь под ней (ступенчатая формула, как average
     precision).
  3. Recall на уровне СОБЫТИЙ (не пользователь-дней, а отдельных строк журнала -
     то же определение "вредоносного события", что в задаче 1/3: запись без фильтра
     по activity, чей день попадает в окно атаки; "события" каждой конфигурации - из
     её журналов: logon -> logon.csv, device -> device.csv, logon+device -> оба).
  4. Задержка обнаружения: для каждого пойманного инсайдера - дни от начала его окна
     атаки до первого тревожного дня ВНУТРИ окна; медиана и разброс (мин-макс).
  5. Число ложных тревог на пользователя в месяц: суммарное число тревожных дней у
     ВСЕХ обычных пользователей теста (не только у тех, кто помечен) / число обычных
     пользователей / длина тестового периода в месяцах (30 дней = 1 месяц).
  6. Интервалы Уилсона для user FPR (как раньше, перенесено для полноты таблицы).
  7. Recall по сценариям (1/2/3, и 4 для r5.2) в одной таблице.

НИЧЕГО ИЗ МЕТОДА НЕ МЕНЯЕТСЯ: признаки, пороги новизны, веса ab.WEIGHTS, и tau/N/W
конфигураций - те же самые замороженные значения, что в задачах 2 и 4. Здесь только
считаются НОВЫЕ метрики поверх уже выбранных решающих правил, тестовые данные не
использовались для выбора этих правил.

Результат: results_revision/detection_metrics.csv, results_revision/metric_definitions.md
Запуск (из папки с CSV):  python cert_detection_metrics.py
"""

import csv
from collections import defaultdict
from datetime import datetime, timedelta
from statistics import median

import cert_ablation as ab
import cert_honest_split as hs
import cert_user_level as ul
import cert_user_level2 as u2
import cert_riskaware as ra
import cert_r52_external_test as r52

OUTPUT_CSV = "results_revision/detection_metrics.csv"
OUTPUT_DEFS = "results_revision/metric_definitions.md"
DATE_FORMAT = "%m/%d/%Y %H:%M:%S"

FROZEN = {
    "logon":        {"cfg": "logon",    "cutoff": 0.50, "N": 4, "W": 7},
    "device":       {"cfg": "device",   "cutoff": 0.65, "N": 2, "W": 7},
    "logon+device": {"cfg": "combined", "cutoff": 0.60, "N": 3, "W": 30},
}
CFG_JOURNALS = {"logon": ["logon"], "device": ["device"], "logon+device": ["logon", "device"]}
SCENARIOS = ["1", "2", "3", "4"]


def wilson(k, n, z=1.96):
    return u2.wilson(k, n, z)


def raw_events(path, split, date_format=DATE_FORMAT):
    """Читает журнал построчно, без фильтра по activity, оставляет только записи с date >= split."""
    events = []
    with open(path, encoding="utf-8") as f:
        for r in csv.DictReader(f):
            day = datetime.strptime(r["date"], date_format).date()
            if day >= split:
                events.append((r["user"], day))
    return events


def average_precision(points):
    """Ступенчатая площадь под PR-кривой (average precision): sum (R_i - R_{i-1}) * P_i,
    точки отсортированы по возрастанию recall."""
    pts = sorted(points, key=lambda x: x[0])
    ap, prev_r = 0.0, 0.0
    for r, p in pts:
        ap += (r - prev_r) * p
        prev_r = r
    return ap


def analyze_config(name, p, used, ud, prof, windows, test_keys, insiders_test, normal_test,
                    test_start, test_end, event_paths, date_format, pattern):
    """Все метрики задачи 5 для одной конфигурации на одном датасете.
    pattern - готовый кэш {key: шаблон дня}, посчитан один раз на датасет (не на конфигурацию),
    чтобы не пересчитывать day_pattern заново на каждом пороге при переборе tau (задача 5.2)."""
    n_ins = len(insiders_test)
    n_norm = len(normal_test)

    def alerts_for(cutoff):
        days = defaultdict(list)
        for k in test_keys:
            s = round(hs.pattern_score(pattern[k], ab.WEIGHTS, used), 2)
            if s >= cutoff:
                days[k[0]].append(k[1])
        for u in days:
            days[u].sort()
        return days

    alerts = alerts_for(p["cutoff"])
    fired_by_user = {u: set(ul.firing_days(alerts.get(u, []), p["N"], p["W"]))
                      for u in list(insiders_test) + list(normal_test)}

    caught, delays, by_sc, total_sc = set(), [], defaultdict(int), defaultdict(int)
    for u, (sc, start, end) in insiders_test.items():
        total_sc[sc] += 1
        inside = sorted(t for t in fired_by_user.get(u, ()) if start <= t <= end)
        if inside:
            caught.add(u)
            by_sc[sc] += 1
            delays.append((inside[0] - start).days)

    false_users = {u for u in normal_test if fired_by_user.get(u)}
    total_false_alert_days = sum(len(fired_by_user.get(u, ())) for u in normal_test)

    # --- 1. Precision, recall, F1 (пользователи) ---
    tp, fp = len(caught), len(false_users)
    precision = tp / (tp + fp) if (tp + fp) else 0.0
    recall = tp / n_ins if n_ins else 0.0
    f1 = 2 * precision * recall / (precision + recall) if (precision + recall) else 0.0
    r_lo, r_hi = wilson(tp, n_ins)
    fpr = fp / n_norm if n_norm else 0.0
    f_lo, f_hi = wilson(fp, n_norm)

    # --- 2. PR-AUC: перебор tau при тех же N, W ---
    levels = u2.score_levels(used)
    pr_points = []
    for tau in levels:
        a = alerts_for(tau)
        fb = {u: set(ul.firing_days(a.get(u, []), p["N"], p["W"])) for u in list(insiders_test) + list(normal_test)}
        c = sum(1 for u, (sc, s, e) in insiders_test.items()
                if any(s <= t <= e for t in fb.get(u, ())))
        fu = sum(1 for u in normal_test if fb.get(u))
        rr = c / n_ins if n_ins else 0.0
        pp = c / (c + fu) if (c + fu) else 0.0
        pr_points.append((rr, pp))
    pr_auc = average_precision(pr_points)

    # --- 3. Recall на уровне событий (raw-записи журналов конфигурации) ---
    ev_total = ev_bad = ev_covered = 0
    for jname in event_paths:
        for u, d in raw_events(event_paths[jname], test_start, date_format):
            ev_total += 1
            if ab.scenario_of(windows, u, d) is not None:
                ev_bad += 1
                if d in fired_by_user.get(u, ()):
                    ev_covered += 1
    event_recall = ev_covered / ev_bad if ev_bad else 0.0

    # --- 5. Ложные тревоги на пользователя в месяц ---
    months = (test_end - test_start).days / 30.0
    false_per_user_per_month = (total_false_alert_days / n_norm / months) if (n_norm and months) else 0.0

    sc_recall = {sc: (f"{by_sc.get(sc,0)}/{total_sc.get(sc,0)}" if total_sc.get(sc) else "n/a")
                 for sc in SCENARIOS}

    return {
        "config": name, "cutoff": p["cutoff"], "N": p["N"], "W": p["W"],
        "insiders_total": n_ins, "insiders_caught": tp,
        "user_recall": round(recall, 4), "recall_ci_lo": round(r_lo, 4), "recall_ci_hi": round(r_hi, 4),
        "normal_total": n_norm, "normal_false": fp,
        "user_fpr": round(fpr, 4), "fpr_ci_lo": round(f_lo, 4), "fpr_ci_hi": round(f_hi, 4),
        "user_precision": round(precision, 4), "user_f1": round(f1, 4),
        "pr_auc": round(pr_auc, 4), "pr_auc_points": len(levels),
        "event_recall": round(event_recall, 4), "malicious_events_total": ev_bad,
        "malicious_events_covered": ev_covered, "events_total": ev_total,
        "delay_days_median": median(delays) if delays else "",
        "delay_days_min": min(delays) if delays else "",
        "delay_days_max": max(delays) if delays else "",
        "delay_n": len(delays),
        "false_alerts_per_user_per_month": round(false_per_user_per_month, 4),
        "total_false_alert_days": total_false_alert_days,
        "test_period_months": round(months, 2),
        "recall_s1": sc_recall["1"], "recall_s2": sc_recall["2"],
        "recall_s3": sc_recall["3"], "recall_s4": sc_recall["4"],
    }


def main():
    rows = []

    # ================= r4.2 =================
    print("=" * 100)
    print("r4.2 (тот же протокол, что задачи 2 и 4: обучение/валидация/тест, честное разбиение)")
    print("=" * 100)
    st = u2.Setup()
    test_start, test_end = hs.TEST_START, max(d for _, d in st.ud)
    event_paths_42 = {"logon": ab.LOGON_FILE, "device": ab.DEVICE_FILE}
    for name, p in FROZEN.items():
        used = hs.CONFIG_FEATURES[p["cfg"]]
        paths = {j: event_paths_42[j] for j in CFG_JOURNALS[name]}
        m = analyze_config(name, p, used, st.ud, st.prof, st.windows,
                            st.parts["тест"][0], st.parts["тест"][1], st.normal["тест"],
                            test_start, test_end, paths, DATE_FORMAT, st.pattern)
        m["dataset"] = "r4.2"
        rows.append(m)
        print(f"{name:13} recall {m['insiders_caught']}/{m['insiders_total']}={100*m['user_recall']:.1f}% "
              f"precision {m['user_precision']:.3f} F1 {m['user_f1']:.3f} PR-AUC {m['pr_auc']:.3f} | "
              f"event recall {100*m['event_recall']:.1f}% ({m['malicious_events_covered']}/{m['malicious_events_total']}) | "
              f"задержка медиана {m['delay_days_median']} дн. (n={m['delay_n']}) | "
              f"ложных тревог/польз./мес {m['false_alerts_per_user_per_month']:.3f}")

    # ================= r5.2 =================
    print("\n" + "=" * 100)
    print("r5.2 (протокол задачи 2: обучение до 2010-05-02, всё остальное тест, один прогон)")
    print("=" * 100)
    windows52 = r52.load_labels_r52()
    ud52 = r52.load_events_r52()
    days52 = sorted({d for _, d in ud52})
    train_end52 = days52[0] + timedelta(days=ab.BASELINE_DAYS)
    prof52 = ab.build_profiles(ud52, train_end52)
    test_keys52 = [k for k in ud52 if k[1] >= train_end52]
    info_all52 = {u: min(w, key=lambda x: x[1]) for u, w in windows52.items()}
    insiders_test52 = {u: v for u, v in info_all52.items() if v[1] >= train_end52}
    normal_test52 = {k[0] for k in test_keys52} - set(windows52)
    test_end52 = max(d for _, d in ud52)
    event_paths_52 = {"logon": r52.LOGON_FILE_R52, "device": r52.DEVICE_FILE_R52}
    pattern52 = {k: hs.day_pattern(ud52[k], prof52.get(k[0])) for k in test_keys52}

    for name, p in FROZEN.items():
        used = hs.CONFIG_FEATURES[p["cfg"]]
        paths = {j: event_paths_52[j] for j in CFG_JOURNALS[name]}
        m = analyze_config(name, p, used, ud52, prof52, windows52,
                            test_keys52, insiders_test52, normal_test52,
                            train_end52, test_end52, paths, r52.DATE_FORMAT, pattern52)
        m["dataset"] = "r5.2"
        rows.append(m)
        print(f"{name:13} recall {m['insiders_caught']}/{m['insiders_total']}={100*m['user_recall']:.1f}% "
              f"precision {m['user_precision']:.3f} F1 {m['user_f1']:.3f} PR-AUC {m['pr_auc']:.3f} | "
              f"event recall {100*m['event_recall']:.1f}% ({m['malicious_events_covered']}/{m['malicious_events_total']}) | "
              f"задержка медиана {m['delay_days_median']} дн. (n={m['delay_n']}) | "
              f"ложных тревог/польз./мес {m['false_alerts_per_user_per_month']:.3f}")

    fields = ["dataset"] + [k for k in rows[0].keys() if k != "dataset"]
    with open(OUTPUT_CSV, "w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=fields)
        w.writeheader()
        w.writerows(rows)
    print(f"\nТаблица сохранена: {OUTPUT_CSV}")

    defs = """# Определения метрик (для статьи)

| Метрика | Числитель | Знаменатель | Период | Единица анализа |
|---|---|---|---|---|
| user recall | число пойманных инсайдеров (сработало внутри окна атаки) | все инсайдеры теста | тест | пользователь |
| user precision | число пойманных инсайдеров | пойманные инсайдеры + ложно помеченные обычные | тест | пользователь |
| user F1 | 2 * precision * recall | precision + recall | тест | пользователь |
| user FPR | число ложно помеченных обычных пользователей | все обычные пользователи теста | тест | пользователь |
| PR-AUC | площадь под кривой (precision, recall) при переборе tau, N и W заморожены | - | тест | пользователь (по точкам кривой) |
| event recall | число вредоносных записей журнала, чей день помечен правилом (N, W) | все вредоносные записи журнала (день записи внутри окна атаки инсайдера) | тест | событие (отдельная строка журнала: Connect/Disconnect/Logon/Logoff) |
| delay (задержка обнаружения) | (дата первого тревожного дня внутри окна атаки) - (дата начала окна) | - | тест, только пойманные инсайдеры | пользователь (одно число на инсайдера) |
| false alerts per user per month | суммарное число тревожных дней у ВСЕХ обычных пользователей теста | (число обычных пользователей) * (длина теста в месяцах, 30 дней = месяц) | тест | пользователь-месяц |
| recall по сценарию | число пойманных инсайдеров этого сценария | все инсайдеры этого сценария в тесте | тест | пользователь |

Все определения используют тот же протокол, что главная таблица: обучение (только профили) -> валидация
(выбор tau, N, W при user FPR <= 3%, для r5.2 не используется - параметры заморожены из выбора на r4.2) -> тест
(один прогон). "День" = пара (пользователь, день) с событием logon и/или device. "Событие" = отдельная запись
журнала (строка CSV), без агрегации по дню; определение вредоносного события - как в разделе 14.1 отчёта: запись
инсайдера (без фильтра по activity), чей день попадает в окно его атаки.
"""
    with open(OUTPUT_DEFS, "w", encoding="utf-8") as f:
        f.write(defs)
    print(f"Таблица определений сохранена: {OUTPUT_DEFS}")


if __name__ == "__main__":
    main()
