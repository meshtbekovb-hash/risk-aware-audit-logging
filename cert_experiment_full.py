"""
ЭКСПЕРИМЕНТ НА ДАННЫХ CERT r4.2 (объединённая телеметрия)

Данные:
  logon.csv    - входы и выходы с рабочих станций (854 859 записей, 1000 пользователей)
  device.csv   - подключение съёмных носителей (405 379 записей, 265 пользователей)
  insiders.csv - официальная разметка CMU SEI: кто инсайдер и в каком окне

Метод.
Абсолютные показатели бесполезны: почти половина сотрудников хоть раз
логинится вне рабочих часов. Значение имеет отклонение от СОБСТВЕННОЙ
нормы пользователя, измеренной на обучающем периоде.

Признаки на пару (пользователь, день):
  1. вход вне рабочих часов, причём раньше пользователь так не делал
  2. вход в выходной, раньше не характерный
  3. вход с компьютера, который пользователь не использовал на обучении
  4. подключение съёмного носителя вне рабочих часов
  5. число подключений носителя сильно выше собственной нормы

Разделение обучение/тест строго по времени, чтобы не подглядывать в будущее.

Запуск (из папки с тремя CSV):  python3 cert_experiment_full.py
"""

import csv
from datetime import datetime, timedelta
from collections import defaultdict

LOGON_FILE = "logon.csv"
DEVICE_FILE = "device.csv"
INSIDERS_FILE = "insiders.csv"
OUTPUT_FILE = "cert_results_full.csv"

BASELINE_DAYS = 120
WORK_START, WORK_END = 8, 18
CUTOFFS = [0.3, 0.5, 0.6, 0.7, 0.8, 0.9]


def load_labels():
    w = defaultdict(list)
    with open(INSIDERS_FILE, encoding="utf-8") as f:
        for r in csv.DictReader(f):
            if r["dataset"] != "4.2":
                continue
            w[r["user"]].append((
                r["scenario"],
                datetime.strptime(r["start"], "%m/%d/%Y %H:%M:%S").date(),
                datetime.strptime(r["end"], "%m/%d/%Y %H:%M:%S").date()))
    return w


def scenario_of(windows, user, day):
    for sc, s, e in windows.get(user, []):
        if s <= day <= e:
            return sc
    return None


def new_day():
    return {"logons": 0, "logon_off": 0, "logon_wknd": 0, "pcs": set(),
            "dev": 0, "dev_off": 0}


def load_events():
    ud = defaultdict(new_day)

    with open(LOGON_FILE, encoding="utf-8") as f:
        for r in csv.DictReader(f):
            if r["activity"] != "Logon":
                continue
            dt = datetime.strptime(r["date"], "%m/%d/%Y %H:%M:%S")
            d = ud[(r["user"], dt.date())]
            d["logons"] += 1
            d["pcs"].add(r["pc"])
            if dt.hour < WORK_START or dt.hour >= WORK_END:
                d["logon_off"] += 1
            if dt.weekday() >= 5:
                d["logon_wknd"] += 1

    with open(DEVICE_FILE, encoding="utf-8") as f:
        for r in csv.DictReader(f):
            if r["activity"] != "Connect":
                continue
            dt = datetime.strptime(r["date"], "%m/%d/%Y %H:%M:%S")
            d = ud[(r["user"], dt.date())]
            d["dev"] += 1
            if dt.hour < WORK_START or dt.hour >= WORK_END:
                d["dev_off"] += 1

    return ud


def build_profiles(ud, split_day):
    """Норма каждого пользователя, посчитанная только на обучающем периоде."""
    p = defaultdict(lambda: {"days": 0, "off": 0, "wknd": 0,
                             "dev_off": 0, "dev_total": 0, "pcs": set()})
    for (user, day), v in ud.items():
        if day >= split_day:
            continue
        pr = p[user]
        pr["days"] += 1
        pr["pcs"] |= v["pcs"]
        pr["dev_total"] += v["dev"]
        if v["logon_off"] > 0:
            pr["off"] += 1
        if v["logon_wknd"] > 0:
            pr["wknd"] += 1
        if v["dev_off"] > 0:
            pr["dev_off"] += 1
    return p


def risk_score(v, pr):
    """Оценка риска от 0 до 1. Веса подобраны по смыслу сценариев CERT."""
    if not pr or pr["days"] == 0:
        return 0.0

    days = pr["days"]
    off_rate = pr["off"] / days
    wknd_rate = pr["wknd"] / days
    dev_off_rate = pr["dev_off"] / days
    dev_avg = pr["dev_total"] / days

    score = 0.0

    # 1. Вход вне рабочих часов, ранее не свойственный пользователю
    if v["logon_off"] > 0:
        score += 0.10
        if off_rate < 0.10:
            score += 0.30

    # 2. Вход в выходной, ранее не свойственный
    if v["logon_wknd"] > 0:
        score += 0.10
        if wknd_rate < 0.05:
            score += 0.20

    # 3. Компьютер, которого не было в обучающем периоде
    if v["pcs"] - pr["pcs"]:
        score += 0.35

    # 4. Съёмный носитель вне рабочих часов, ранее не свойственный
    if v["dev_off"] > 0:
        score += 0.15
        if dev_off_rate < 0.05:
            score += 0.30

    # 5. Резкий всплеск подключений носителя
    if dev_avg > 0 and v["dev"] > 3 * dev_avg:
        score += 0.15

    return min(score, 1.0)


def evaluate(rows, cutoff):
    tp = fn = fp = tn = 0
    caught, total = defaultdict(int), defaultdict(int)
    for score, sc in rows:
        alert = score >= cutoff
        bad = sc is not None
        if bad:
            total[sc] += 1
            if alert:
                caught[sc] += 1
        if alert and bad:
            tp += 1
        elif not alert and bad:
            fn += 1
        elif alert:
            fp += 1
        else:
            tn += 1

    prec = tp / (tp + fp) if (tp + fp) else 0.0
    rec = tp / (tp + fn) if (tp + fn) else 0.0
    f1 = 2 * prec * rec / (prec + rec) if (prec + rec) else 0.0
    fpr = fp / (fp + tn) if (fp + tn) else 0.0
    alerts_per_day = (tp + fp) / 365

    return ({"cutoff": cutoff, "TP": tp, "FN": fn, "FP": fp, "TN": tn,
             "precision": round(prec, 3), "recall": round(rec, 3),
             "f1": round(f1, 3), "fpr": round(fpr, 4),
             "alerts_per_day": round(alerts_per_day, 1)},
            caught, total)


def main():
    print("Загрузка CERT r4.2...")
    windows = load_labels()
    ud = load_events()

    days = sorted({d for _, d in ud})
    split = days[0] + timedelta(days=BASELINE_DAYS)
    print(f"  пользователей:         {len({u for u, _ in ud})}")
    print(f"  пар пользователь-день: {len(ud)}")
    print(f"  период:                {days[0]} — {days[-1]}")
    print(f"  обучение до:           {split}")
    print(f"  инсайдеров:            {len(windows)}\n")

    prof = build_profiles(ud, split)

    rows = []
    for (user, day), v in ud.items():
        if day < split:
            continue
        rows.append((risk_score(v, prof.get(user)),
                     scenario_of(windows, user, day)))

    mal = sum(1 for _, sc in rows if sc)
    print(f"Тестовых дней: {len(rows)}, вредоносных: {mal} "
          f"({100 * mal / len(rows):.2f}%)\n")

    results = []
    print(f"{'cutoff':>7} {'TP':>5} {'FN':>6} {'FP':>7} {'precision':>10} "
          f"{'recall':>8} {'F1':>7} {'FPR':>8} {'тревог/день':>12}")
    print("-" * 78)
    for c in CUTOFFS:
        res, _, _ = evaluate(rows, c)
        results.append(res)
        print(f"{res['cutoff']:>7} {res['TP']:>5} {res['FN']:>6} {res['FP']:>7} "
              f"{res['precision']:>10} {res['recall']:>8} {res['f1']:>7} "
              f"{res['fpr']:>8} {res['alerts_per_day']:>12}")

    with open(OUTPUT_FILE, "w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=list(results[0].keys()))
        w.writeheader()
        w.writerows(results)
    print(f"\nТаблица сохранена: {OUTPUT_FILE}")

    names = {"1": "ночной доступ + носитель",
             "2": "поиск работы + кража перед уходом",
             "3": "администратор под чужой учёткой"}
    print("\nПолнота по сценариям:")
    for c in [0.5, 0.7, 0.9]:
        _, caught, total = evaluate(rows, c)
        print(f"  cutoff {c}:")
        for sc in sorted(total):
            print(f"    Сценарий {sc} ({names.get(sc, '')}): "
                  f"{caught[sc]:>4} из {total[sc]:>4} "
                  f"({100 * caught[sc] / total[sc]:.1f}%)")


if __name__ == "__main__":
    main()
