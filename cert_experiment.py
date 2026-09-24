"""
ЭКСПЕРИМЕНТ НА ДАННЫХ CERT r4.2

Данные:
  device.csv  - журнал подключения съёмных носителей (405 380 записей, 265 пользователей)
  insiders.csv - официальная разметка CMU SEI: кто инсайдер и в каком временном окне

Идея метода.
Абсолютное число подключений флешки ничего не говорит: кто-то пользуется ей
каждый день по работе. Значение имеет ОТКЛОНЕНИЕ ОТ СОБСТВЕННОЙ НОРМЫ
пользователя. Поэтому мы сначала измеряем поведение каждого человека на
обучающем периоде, а потом ищем отклонения на тестовом.

Обучающий период: первые BASELINE_DAYS дней журнала.
Тестовый период:  всё остальное.
Разделение по времени, а не случайное - иначе модель подсматривает в будущее.

Запуск:  python3 cert_experiment.py
"""

import csv
from datetime import datetime, timedelta
from collections import defaultdict

DEVICE_FILE = "device.csv"
INSIDERS_FILE = "insiders.csv"
OUTPUT_FILE = "cert_detection_results.csv"

BASELINE_DAYS = 120          # сколько первых дней уходит на обучение
WORK_START, WORK_END = 8, 18  # рабочие часы


# ---------------------------------------------------------------
# 1. Загрузка официальной разметки (только версия 4.2)
# ---------------------------------------------------------------
def load_labels():
    windows = defaultdict(list)
    with open(INSIDERS_FILE, encoding="utf-8") as f:
        for r in csv.DictReader(f):
            if r["dataset"] != "4.2":
                continue
            windows[r["user"]].append((
                r["scenario"],
                datetime.strptime(r["start"], "%m/%d/%Y %H:%M:%S").date(),
                datetime.strptime(r["end"], "%m/%d/%Y %H:%M:%S").date(),
            ))
    return windows


def scenario_of(windows, user, day):
    """Возвращает номер сценария, если этот день попадает в окно атаки."""
    for sc, start, end in windows.get(user, []):
        if start <= day <= end:
            return sc
    return None


# ---------------------------------------------------------------
# 2. Агрегация журнала по парам (пользователь, день)
# ---------------------------------------------------------------
def load_user_days():
    ud = defaultdict(lambda: {"connects": 0, "off_hours": 0, "weekend": 0})
    with open(DEVICE_FILE, encoding="utf-8") as f:
        for r in csv.DictReader(f):
            if r["activity"] != "Connect":
                continue
            dt = datetime.strptime(r["date"], "%m/%d/%Y %H:%M:%S")
            key = (r["user"], dt.date())
            ud[key]["connects"] += 1
            if dt.hour < WORK_START or dt.hour >= WORK_END:
                ud[key]["off_hours"] += 1
            if dt.weekday() >= 5:
                ud[key]["weekend"] += 1
    return ud


# ---------------------------------------------------------------
# 3. Профиль нормального поведения каждого пользователя
# ---------------------------------------------------------------
def build_baselines(ud, split_day):
    """Считается только по обучающему периоду - без подглядывания в будущее."""
    prof = defaultdict(lambda: {"days": 0, "off_days": 0,
                                "wknd_days": 0, "total_connects": 0})
    for (user, day), v in ud.items():
        if day >= split_day:
            continue
        p = prof[user]
        p["days"] += 1
        p["total_connects"] += v["connects"]
        if v["off_hours"] > 0:
            p["off_days"] += 1
        if v["weekend"] > 0:
            p["wknd_days"] += 1
    return prof


# ---------------------------------------------------------------
# 4. Оценка риска
# ---------------------------------------------------------------
def risk_score(v, prof_user):
    """
    Risk = вклад признаков, значение от 0 до 1.

    Ключевой признак - новизна поведения: пользователь, который раньше
    НИКОГДА не подключал носитель вне рабочих часов, вдруг начал это делать.
    Именно так описан первый сценарий инсайдера в CERT.
    """
    score = 0.0
    days = prof_user["days"] if prof_user else 0
    off_rate = (prof_user["off_days"] / days) if days else 0.0
    wknd_rate = (prof_user["wknd_days"] / days) if days else 0.0
    avg_connects = (prof_user["total_connects"] / days) if days else 0.0

    if v["off_hours"] > 0:
        score += 0.35
        if off_rate < 0.05:          # раньше так не делал
            score += 0.40
    if v["weekend"] > 0:
        score += 0.15
        if wknd_rate < 0.02:
            score += 0.20
    if avg_connects > 0 and v["connects"] > 3 * avg_connects:
        score += 0.15

    return min(score, 1.0)


# ---------------------------------------------------------------
# 5. Подсчёт метрик
# ---------------------------------------------------------------
def evaluate(test_rows, cutoff):
    tp = fn = fp = tn = 0
    caught = defaultdict(int)
    total = defaultdict(int)

    for score, sc in test_rows:
        alert = score >= cutoff
        malicious = sc is not None
        if malicious:
            total[sc] += 1
            if alert:
                caught[sc] += 1
        if alert and malicious:
            tp += 1
        elif not alert and malicious:
            fn += 1
        elif alert and not malicious:
            fp += 1
        else:
            tn += 1

    precision = tp / (tp + fp) if (tp + fp) else 0.0
    recall = tp / (tp + fn) if (tp + fn) else 0.0
    f1 = 2 * precision * recall / (precision + recall) if (precision + recall) else 0.0
    fpr = fp / (fp + tn) if (fp + tn) else 0.0

    return {
        "cutoff": cutoff, "TP": tp, "FN": fn, "FP": fp, "TN": tn,
        "precision": round(precision, 3),
        "recall": round(recall, 3),
        "f1": round(f1, 3),
        "false_positive_rate": round(fpr, 4),
    }, caught, total


def main():
    print("Загрузка данных CERT r4.2...")
    windows = load_labels()
    ud = load_user_days()

    all_days = sorted({d for _, d in ud})
    split_day = all_days[0] + timedelta(days=BASELINE_DAYS)

    print(f"  пользователей:        {len({u for u, _ in ud})}")
    print(f"  пар пользователь-день: {len(ud)}")
    print(f"  период:               {all_days[0]} — {all_days[-1]}")
    print(f"  обучение до:          {split_day}")
    print(f"  инсайдеров в разметке: {len(windows)}\n")

    prof = build_baselines(ud, split_day)

    test_rows = []
    for (user, day), v in ud.items():
        if day < split_day:
            continue
        sc = scenario_of(windows, user, day)
        test_rows.append((risk_score(v, prof.get(user)), sc))

    mal = sum(1 for _, sc in test_rows if sc)
    print(f"Тестовых дней: {len(test_rows)}, из них вредоносных: "
          f"{mal} ({100*mal/len(test_rows):.2f}%)\n")

    results = []
    print(f"{'cutoff':>7} {'TP':>5} {'FN':>6} {'FP':>6} "
          f"{'precision':>10} {'recall':>8} {'F1':>7} {'FPR':>8}")
    print("-" * 62)
    for cutoff in [0.3, 0.5, 0.6, 0.75, 0.9]:
        res, caught, total = evaluate(test_rows, cutoff)
        results.append(res)
        print(f"{res['cutoff']:>7} {res['TP']:>5} {res['FN']:>6} {res['FP']:>6} "
              f"{res['precision']:>10} {res['recall']:>8} {res['f1']:>7} "
              f"{res['false_positive_rate']:>8}")

    with open(OUTPUT_FILE, "w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=list(results[0].keys()))
        w.writeheader()
        w.writerows(results)
    print(f"\nТаблица сохранена: {OUTPUT_FILE}")

    print("\nПолнота по сценариям (cutoff 0.75):")
    _, caught, total = evaluate(test_rows, 0.75)
    names = {
        "1": "ночной доступ + носитель",
        "2": "поиск работы + кража перед уходом",
        "3": "системный администратор",
    }
    for sc in sorted(total):
        pct = 100 * caught[sc] / total[sc]
        print(f"  Сценарий {sc} ({names.get(sc,'')}): "
              f"{caught[sc]} из {total[sc]} ({pct:.1f}%)")


if __name__ == "__main__":
    main()
