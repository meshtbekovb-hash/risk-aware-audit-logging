"""
ЗАДАЧА 2 REVISION_PLAN.md: НЕЗАВИСИМЫЙ ТЕСТ НА CERT r5.2

Отвечает на главное замечание ревью: тест на r4.2 не был независимым, потому что
признаки, пороги новизны и веса создавались с оглядкой на весь датасет r4.2 (включая
то, что стало тестом). r5.2 - другой релиз CERT (другие люди, другой ID-формат,
447 пользователей носителей вместо 265, 2000 логон-пользователей вместо 1000), метод
его вообще не видел ни на одном шаге подбора.

ЧТО ЗАМОРОЖЕНО (ничего из этого здесь не подбирается):
  - 5 признаков и их пороги новизны (10%, 5%, 5%, x3) - код cert_ablation.py, без правок;
  - веса ab.WEIGHTS (0.45 / 0.30 / 0.50 / 0.65 / 0.30) - без правок;
  - порог риска tau, правило накопления (N, W) для каждой конфигурации - взяты ИЗ
    ВЫБОРА, СДЕЛАННОГО НА ВАЛИДАЦИИ r4.2 (user_level2_results.csv, таблица "main"):
      logon         tau=0.50  N=4 W=7
      device        tau=0.65  N=2 W=7
      logon+device  tau=0.60  N=3 W=30

ЧТО АДАПТИРОВАНО (только чтение файлов, не метод):
  - пути к файлам данных r5.2 (data_r52/logon.csv, data_r52/device.csv);
  - фильтр insiders.csv по dataset == "5.2" вместо "4.2";
  - device.csv r5.2 имеет лишнюю колонку file_tree (id,date,user,pc,file_tree,activity
    вместо id,date,user,pc,activity в r4.2) - csv.DictReader обращается к колонкам по
    имени, лишняя колонка просто игнорируется, никакого кода менять не пришлось.
    Формат даты (%m/%d/%Y %H:%M:%S) в r5.2 тот же, что в r4.2 - проверено перед запуском.

ПРОТОКОЛ: первые 120 дней r5.2 (до 2010-05-02, датасет тоже начинается 2010-01-02) -
только для профилей пользователей (та же логика build_profiles, что и в r4.2). Всё
остальное - тест, единственный прогон, ничего не подбирается заново. Инсайдер, чьё
окно атаки НАЧИНАЕТСЯ до конца обучающего периода, из теста исключается (иначе его
поведение частично попало бы в профиль как "норма") - выводим, сколько таких.

МЕТРИКИ: user recall (доля инсайдеров, у которых правило сработало внутри окна атаки)
и user FPR - каждый с интервалом Уилсона 95%, каждый в двух версиях (по всем
неинсайдерам / по наблюдаемой популяции - только те, у кого в тесте вообще есть
событие нужного типа), плюс recall по каждому сценарию (1, 2, 3 и новый 4).

Результат: results_revision/r52_external_test.csv
Запуск (из папки с CSV):  python cert_r52_external_test.py
"""

import csv
from collections import defaultdict
from datetime import datetime, timedelta
from math import sqrt

import cert_ablation as ab
import cert_honest_split as hs
import cert_user_level as ul

OUTPUT_FILE = "results_revision/r52_external_test.csv"

LOGON_FILE_R52 = "data_r52/logon.csv"
DEVICE_FILE_R52 = "data_r52/device.csv"
DATE_FORMAT = "%m/%d/%Y %H:%M:%S"

# Параметры заморожены из выбора на валидации r4.2 (user_level2_results.csv, table=main)
FROZEN = {
    "logon":        {"cfg": "logon",    "cutoff": 0.50, "N": 4, "W": 7},
    "device":       {"cfg": "device",   "cutoff": 0.65, "N": 2, "W": 7},
    "logon+device": {"cfg": "combined", "cutoff": 0.60, "N": 3, "W": 30},
}
CFG_KIND = {"logon": ("logon",), "device": ("device",), "logon+device": ("logon", "device")}
SCENARIOS_R52 = ["1", "2", "3", "4"]

# Референс r4.2 (честное разбиение, тот же протокол, user_level2_results.csv) - для
# сравнения в одной таблице. Числа не пересчитываются здесь, только переносятся с
# указанием источника.
R42_REFERENCE = {
    "logon":        {"insiders_total": 35, "insiders_caught": 5,  "user_fpr": 0.0304,
                      "normal_total": 888, "normal_false": 27,
                      "obs_normal_total": 888, "obs_false": 27,  # у logon наблюдаемая = вся популяция
                      "recall_by_sc": {"1": "1/16", "2": "0/15", "3": "4/4"}},
    "device":       {"insiders_total": 35, "insiders_caught": 18, "user_fpr": 0.0236,
                      "normal_total": 888, "normal_false": 21,
                      "obs_normal_total": 182, "obs_false": 21,
                      "recall_by_sc": {"1": "16/16", "2": "2/15", "3": "0/4"}},
    "logon+device": {"insiders_total": 35, "insiders_caught": 17, "user_fpr": 0.0327,
                      "normal_total": 888, "normal_false": 29,
                      "obs_normal_total": 888, "obs_false": 29,
                      "recall_by_sc": {"1": "15/16", "2": "2/15", "3": "0/4"}},
}


# ---------------------------------------------------------------
# Загрузка r5.2 (адаптированы только пути; логика 1-в-1 как ab.load_events/load_labels)
# ---------------------------------------------------------------
def load_events_r52():
    """
    То же самое, что ab.load_events(), но с файлов r5.2. Признаки и пороги внутри
    build_profiles/logon_features/device_features не меняются - здесь только сырой
    подсчёт событий по (пользователь, день), как в r4.2.
    """
    ud = defaultdict(lambda: {"logon_off": 0, "logon_wknd": 0, "pcs": set(),
                              "dev": 0, "dev_off": 0})

    with open(LOGON_FILE_R52, encoding="utf-8") as f:
        for r in csv.DictReader(f):
            if r["activity"] != "Logon":
                continue
            dt = datetime.strptime(r["date"], DATE_FORMAT)
            d = ud[(r["user"], dt.date())]
            d["pcs"].add(r["pc"])
            if dt.hour < ab.WORK_START or dt.hour >= ab.WORK_END:
                d["logon_off"] += 1
            if dt.weekday() >= 5:
                d["logon_wknd"] += 1

    # device.csv r5.2 содержит лишнюю колонку file_tree - DictReader читает по имени
    # колонки, поэтому обращение к r["id"], r["date"], r["user"], r["pc"], r["activity"]
    # работает без изменений, file_tree просто не используется.
    with open(DEVICE_FILE_R52, encoding="utf-8") as f:
        for r in csv.DictReader(f):
            if r["activity"] != "Connect":
                continue
            dt = datetime.strptime(r["date"], DATE_FORMAT)
            d = ud[(r["user"], dt.date())]
            d["dev"] += 1
            if dt.hour < ab.WORK_START or dt.hour >= ab.WORK_END:
                d["dev_off"] += 1

    return ud


def load_labels_r52():
    """То же, что ab.load_labels(), но фильтр dataset == '5.2' вместо '4.2'."""
    w = defaultdict(list)
    with open(ab.INSIDERS_FILE, encoding="utf-8") as f:
        for r in csv.DictReader(f):
            if r["dataset"] != "5.2":
                continue
            w[r["user"]].append((
                r["scenario"],
                datetime.strptime(r["start"], DATE_FORMAT).date(),
                datetime.strptime(r["end"], DATE_FORMAT).date()))
    return w


def event_days(ud):
    """Для каждого пользователя и типа событий - множество дней с такими событиями."""
    days = {"logon": defaultdict(set), "device": defaultdict(set)}
    for (user, day), v in ud.items():
        if v["pcs"]:
            days["logon"][user].add(day)
        if v["dev"] > 0:
            days["device"][user].add(day)
    return days


# ---------------------------------------------------------------
# Статистика (совпадает с cert_user_level2.py: те же формулы, не меняем)
# ---------------------------------------------------------------
def wilson(k, n, z=1.96):
    if n == 0:
        return (0.0, 0.0)
    p = k / n
    d = 1 + z * z / n
    center = (p + z * z / (2 * n)) / d
    half = z * sqrt(p * (1 - p) / n + z * z / (4 * n * n)) / d
    return center - half, center + half


def fmt_pct(k, n):
    lo, hi = wilson(k, n)
    return f"{100 * k / n if n else 0:.1f}% [{100 * lo:.1f};{100 * hi:.1f}]", lo, hi


def main():
    print("=" * 100)
    print("ЗАДАЧА 2. Независимый тест на CERT r5.2 (метод заморожен из выбора на r4.2)")
    print("=" * 100)

    windows = load_labels_r52()
    ud = load_events_r52()
    days = sorted({d for _, d in ud})
    train_end = days[0] + timedelta(days=ab.BASELINE_DAYS)
    print(f"период r5.2: {days[0]} .. {days[-1]}")
    print(f"обучающий период (только профили): до {train_end} (первые {ab.BASELINE_DAYS} дней)")
    print(f"пар пользователь-день: {len(ud)}\n")

    prof = ab.build_profiles(ud, train_end)
    test_keys = [k for k in ud if k[1] >= train_end]

    # Первое (и единственное, проверено - см. results_revision/task1_clarifications.csv
    # не относится, отдельная проверка ниже) окно на пользователя
    info_all = {u: min(w, key=lambda x: x[1]) for u, w in windows.items()}
    excluded = {u: v for u, v in info_all.items() if v[1] < train_end}
    insiders_test = {u: v for u, v in info_all.items() if v[1] >= train_end}
    print(f"инсайдеров в разметке r5.2: {len(info_all)}")
    print(f"исключено (окно атаки НАЧИНАЕТСЯ до конца обучающего периода {train_end}): "
          f"{len(excluded)}")
    for u, (sc, s, e) in excluded.items():
        print(f"   исключён: {u}, сценарий {sc}, окно {s}..{e} (начало раньше обучающего среза)")
    print(f"инсайдеров в тесте: {len(insiders_test)}\n")

    normal_test = {k[0] for k in test_keys} - set(windows)   # все 99 инсайдеров вычтены
    print(f"неинсайдеров с активностью в тестовом периоде: {len(normal_test)}\n")

    ev = event_days(ud)

    def user_has(kinds, user, lo=None, hi=None):
        for kind in kinds:
            for d in ev[kind].get(user, ()):
                if d >= train_end and (lo is None or lo <= d <= hi):
                    return True
        return False

    rows_out = []
    print(f"{'конфигурация':13} {'tau,N,W':16} | recall всех | recall наблюд. | "
          f"FPR всех      | FPR наблюдаемых")

    for name, p in FROZEN.items():
        used = hs.CONFIG_FEATURES[p["cfg"]]
        kinds = CFG_KIND[name]

        alerts = defaultdict(list)
        for k in test_keys:
            pat = hs.day_pattern(ud[k], prof.get(k[0]))
            s = round(hs.pattern_score(pat, ab.WEIGHTS, used), 2)
            if s >= p["cutoff"]:
                alerts[k[0]].append(k[1])
        for u in alerts:
            alerts[u].sort()

        caught, by_sc = set(), defaultdict(int)
        total_sc = defaultdict(int)
        for u, (sc, start, end) in insiders_test.items():
            total_sc[sc] += 1
            fired = ul.firing_days(alerts.get(u, []), p["N"], p["W"])
            if any(start <= t <= end for t in fired):
                caught.add(u)
                by_sc[sc] += 1

        false_users = {u for u in normal_test if ul.firing_days(alerts.get(u, []), p["N"], p["W"])}

        # наблюдаемая популяция
        obs_ins = {u for u, (sc, s, e) in insiders_test.items() if user_has(kinds, u, s, e)}
        obs_norm = {x for x in normal_test if user_has(kinds, x)}
        caught_obs = caught & obs_ins
        false_obs = false_users & obs_norm

        n_ins = len(insiders_test)
        recall_str, r_lo, r_hi = fmt_pct(len(caught), n_ins)
        fpr_str, f_lo, f_hi = fmt_pct(len(false_users), len(normal_test))
        recall_obs_str, ro_lo, ro_hi = fmt_pct(len(caught_obs), len(obs_ins))
        fpr_obs_str, fo_lo, fo_hi = fmt_pct(len(false_obs), len(obs_norm))

        print(f"{name:13} tau={p['cutoff']} N={p['N']} W={p['W']:<3} | "
              f"{len(caught):>2}/{n_ins} {recall_str:16} | "
              f"{len(caught_obs):>2}/{len(obs_ins):<2} {recall_obs_str:14} | "
              f"{len(false_users):>3}/{len(normal_test)} {fpr_str:12} | "
              f"{len(false_obs):>3}/{len(obs_norm):<3} {fpr_obs_str}")

        sc_recall = {}
        for sc in SCENARIOS_R52:
            t = total_sc.get(sc, 0)
            c = by_sc.get(sc, 0)
            sc_recall[sc] = f"{c}/{t}" if t else "n/a"
        print("   по сценариям (r5.2): " + ", ".join(f"сц.{sc} {sc_recall[sc]}" for sc in SCENARIOS_R52))

        ref = R42_REFERENCE[name]
        ref_recall_str, _, _ = fmt_pct(ref["insiders_caught"], ref["insiders_total"])
        ref_fpr_str, _, _ = fmt_pct(ref["normal_false"], ref["normal_total"])
        print(f"   для сравнения r4.2: recall {ref['insiders_caught']}/{ref['insiders_total']} "
              f"{ref_recall_str}, FPR {ref['normal_false']}/{ref['normal_total']} {ref_fpr_str}")
        print()

        rows_out.append({
            "dataset": "r5.2", "config": name, "cutoff": p["cutoff"], "N": p["N"], "W": p["W"],
            "insiders_total": n_ins, "insiders_caught": len(caught),
            "user_recall": round(len(caught) / n_ins, 4) if n_ins else "",
            "recall_ci_lo": round(r_lo, 4), "recall_ci_hi": round(r_hi, 4),
            "normal_total": len(normal_test), "normal_false": len(false_users),
            "user_fpr": round(len(false_users) / len(normal_test), 4) if normal_test else "",
            "fpr_ci_lo": round(f_lo, 4), "fpr_ci_hi": round(f_hi, 4),
            "obs_insiders_total": len(obs_ins), "obs_insiders_caught": len(caught_obs),
            "user_recall_observed": round(len(caught_obs) / len(obs_ins), 4) if obs_ins else "",
            "recall_obs_ci_lo": round(ro_lo, 4), "recall_obs_ci_hi": round(ro_hi, 4),
            "obs_normal_total": len(obs_norm), "obs_normal_false": len(false_obs),
            "user_fpr_observed": round(len(false_obs) / len(obs_norm), 4) if obs_norm else "",
            "fpr_obs_ci_lo": round(fo_lo, 4), "fpr_obs_ci_hi": round(fo_hi, 4),
            "recall_s1": sc_recall["1"], "recall_s2": sc_recall["2"],
            "recall_s3": sc_recall["3"], "recall_s4": sc_recall["4"],
            "excluded_insiders_start_before_train_end": len(excluded),
        })

        ref = R42_REFERENCE[name]
        ref_recall_ci_lo, ref_recall_ci_hi = wilson(ref["insiders_caught"], ref["insiders_total"])
        ref_fpr_ci_lo, ref_fpr_ci_hi = wilson(ref["normal_false"], ref["normal_total"])
        ref_obs_fpr_ci_lo, ref_obs_fpr_ci_hi = wilson(ref["obs_false"], ref["obs_normal_total"])
        rows_out.append({
            "dataset": "r4.2 (reference, честное разбиение, user_level2_results.csv)",
            "config": name, "cutoff": p["cutoff"], "N": p["N"], "W": p["W"],
            "insiders_total": ref["insiders_total"], "insiders_caught": ref["insiders_caught"],
            "user_recall": round(ref["insiders_caught"] / ref["insiders_total"], 4),
            "recall_ci_lo": round(ref_recall_ci_lo, 4), "recall_ci_hi": round(ref_recall_ci_hi, 4),
            "normal_total": ref["normal_total"], "normal_false": ref["normal_false"],
            "user_fpr": ref["user_fpr"],
            "fpr_ci_lo": round(ref_fpr_ci_lo, 4), "fpr_ci_hi": round(ref_fpr_ci_hi, 4),
            "obs_insiders_total": ref["insiders_total"], "obs_insiders_caught": ref["insiders_caught"],
            "user_recall_observed": round(ref["insiders_caught"] / ref["insiders_total"], 4),
            "recall_obs_ci_lo": round(ref_recall_ci_lo, 4), "recall_obs_ci_hi": round(ref_recall_ci_hi, 4),
            "obs_normal_total": ref["obs_normal_total"], "obs_normal_false": ref["obs_false"],
            "user_fpr_observed": round(ref["obs_false"] / ref["obs_normal_total"], 4),
            "fpr_obs_ci_lo": round(ref_obs_fpr_ci_lo, 4), "fpr_obs_ci_hi": round(ref_obs_fpr_ci_hi, 4),
            "recall_s1": ref["recall_by_sc"]["1"], "recall_s2": ref["recall_by_sc"]["2"],
            "recall_s3": ref["recall_by_sc"]["3"], "recall_s4": "n/a (сценария 4 нет в r4.2)",
            "excluded_insiders_start_before_train_end": "",
        })

    fields = list(rows_out[0].keys())
    with open(OUTPUT_FILE, "w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=fields)
        w.writeheader()
        w.writerows(rows_out)
    print(f"Таблица сохранена: {OUTPUT_FILE}")


if __name__ == "__main__":
    main()
