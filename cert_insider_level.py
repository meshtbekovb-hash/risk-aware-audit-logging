"""
ОЦЕНКА НА УРОВНЕ ИНСАЙДЕРОВ (а не дней)

Метрика "по дням" сильно зависит от сценария 2: у него 1188 из 1364
вредоносных дней, потому что окно атаки растянуто на месяцы. Поэтому общий
recall почти целиком определяется этим одним сценарием.

Здесь считаем то, что важнее для SOC: поймали ли мы ИНСАЙДЕРА хотя бы один
раз за время его атаки. Порог для каждой конфигурации тот же, что в основном
эксперименте (наибольший recall при FPR не выше 1% по дням), то есть
оценка честно продолжает прежнюю методику, а не подбирает новый порог.

Считаем по каждой конфигурации:
  - сколько инсайдеров пойманы, всего и по сценариям;
  - через сколько дней после начала атаки сработала первая тревога (медиана);
  - сколько обычных пользователей получили хотя бы одну ложную тревогу;
  - сколько тревог в день приходится на 1000 пользователей.

Результат: cert_insider_level_results.csv
Запуск (из папки с CSV):  python cert_insider_level.py
"""

import csv
from datetime import timedelta
from statistics import median

import cert_ablation as ab
import cert_file as cf

OUTPUT_FILE = "cert_insider_level_results.csv"

# Название -> набор источников (ключевые слова, которые понимает cf.score)
CONFIGS = [("logon", "logon"),
           ("device", "device"),
           ("file", "file"),
           ("logon+device", "logon device"),
           ("device+file", "device file"),
           ("logon+device+file", "logon device file")]


def insider_scenario(windows):
    """Сценарий каждого инсайдера (по его первому окну атаки) и начало атаки."""
    info = {}
    for user, wins in windows.items():
        sc, start, _ = min(wins, key=lambda w: w[1])
        info[user] = (sc, start)
    return info


def main():
    print("Загрузка данных...")
    windows = ab.load_labels()
    ud = ab.load_events()
    fd = cf.load_file_events()
    days = sorted({d for _, d in ud} | {d for _, d in fd})
    split = days[0] + timedelta(days=ab.BASELINE_DAYS)
    prof = ab.build_profiles(ud, split)
    fprof = cf.build_file_profiles(fd, split)
    test_keys = sorted({k for k in list(ud) + list(fd) if k[1] >= split})
    labels = {k: ab.scenario_of(windows, k[0], k[1]) for k in test_keys}
    info = insider_scenario(windows)
    n_days_test = len({d for _, d in test_keys})

    per_scenario_total = {}
    for sc, _ in info.values():
        per_scenario_total[sc] = per_scenario_total.get(sc, 0) + 1
    normal_users = {u for u, _ in test_keys} - set(info)
    print(f"  инсайдеров: {len(info)} "
          f"(сценарии: { {s: per_scenario_total[s] for s in sorted(per_scenario_total)} })")
    print(f"  обычных пользователей с активностью в тесте: {len(normal_users)}\n")

    out = []
    for name, cfg in CONFIGS:
        scores = {k: cf.score(k, ud, prof, fd, fprof, cfg, ab.BASELINE_DAYS)
                  for k in test_keys}
        rows = [(scores[k], labels[k]) for k in test_keys]
        cutoff, _ = ab.pick_cutoff(rows, ab.TARGET_FPR)

        first_alert = {}          # инсайдер -> первый день тревоги внутри его окна
        false_users = set()       # обычные пользователи с хотя бы одной тревогой
        alerts = 0
        for k in test_keys:
            if scores[k] < cutoff:
                continue
            alerts += 1
            user, day = k
            if labels[k]:
                if user not in first_alert or day < first_alert[user]:
                    first_alert[user] = day
            elif user not in info:
                false_users.add(user)

        caught = {}
        delays = []
        for user, day in first_alert.items():
            sc, start = info[user]
            caught[sc] = caught.get(sc, 0) + 1
            delays.append((day - max(start, split)).days)

        row = {"config": name, "cutoff": cutoff,
               "insiders_caught": len(first_alert),
               "insiders_total": len(info),
               "median_days_to_first_alert": median(delays) if delays else "",
               "false_users": len(false_users),
               "false_users_pct": round(100 * len(false_users) / len(normal_users), 1),
               "alerts_per_day_per_1000_users": round(alerts / n_days_test / (len(normal_users) + len(info)) * 1000, 2)}
        line = []
        for sc in sorted(per_scenario_total):
            c = caught.get(sc, 0)
            row[f"caught_s{sc}"] = c
            row[f"total_s{sc}"] = per_scenario_total[sc]
            line.append(f"сц.{sc}: {c}/{per_scenario_total[sc]}")
        print(f"{name:20} порог {cutoff:<5} пойманы {len(first_alert):>2}/{len(info)}  "
              f"({', '.join(line)})  медиана до 1-й тревоги "
              f"{row['median_days_to_first_alert']} дн., "
              f"ложно затронуто {len(false_users)} ({row['false_users_pct']}%), "
              f"тревог/день/1000 польз. {row['alerts_per_day_per_1000_users']}")
        out.append(row)

    with open(OUTPUT_FILE, "w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=list(out[0].keys()))
        w.writeheader()
        w.writerows(out)
    print(f"\nТаблица сохранена: {OUTPUT_FILE}")


if __name__ == "__main__":
    main()
