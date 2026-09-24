"""
ШАГ 2. Правила обнаружения и расчёт метрик.

Читает access_log.csv, прогоняет по нему правила детекта и считает,
насколько хорошо они работают.

Считает четыре величины:
  TP (True Positive)  - аномалия была и правило сработало  = поймали
  FN (False Negative) - аномалия была, но правило молчало   = пропустили
  FP (False Positive) - аномалии не было, а правило сработало = ложная тревога
  TN (True Negative)  - аномалии не было и правило молчало  = всё верно

Из них выводятся:
  Precision = TP / (TP + FP)  - какая доля тревог оказалась настоящей
  Recall    = TP / (TP + FN)  - какую долю атак удалось поймать
  F1        - общая оценка, среднее между ними

Прогоняет всё это при нескольких порогах, чтобы было видно,
как выбор порога влияет на результат. Это даст вам график.

Результат сохраняется в detection_results.csv

Запуск:  python3 step2_detect.py
"""

import csv
from datetime import datetime

LOG_FILE = "access_log.csv"
OUTPUT_FILE = "detection_results.csv"

# Пороги для правила "массовая выгрузка": сколько записей за раз считать подозрительным.
# Несколько значений нужны, чтобы построить график.
EXPORT_THRESHOLDS = [200, 500, 1000, 2000, 3000, 5000]

WORK_START_HOUR = 9
WORK_END_HOUR = 18

# Какие ресурсы положены каждой роли (должно совпадать со step1_generate.py)
ROLE_RESOURCES = {
    "analyst":    ["survey_results", "reports", "dashboards"],
    "operator":   ["citizen_requests", "survey_results"],
    "admin":      ["system_config", "audit_logs", "user_accounts"],
    "supervisor": ["reports", "dashboards", "audit_logs"],
}


def load_log(path):
    rows = []
    with open(path, encoding="utf-8") as f:
        for row in csv.DictReader(f):
            row["records_exported"] = int(row["records_exported"])
            row["is_anomaly"] = int(row["is_anomaly"])
            row["dt"] = datetime.strptime(row["timestamp"], "%Y-%m-%d %H:%M:%S")
            rows.append(row)
    return rows


# ---------------------------------------------------------------
# ПРАВИЛА ДЕТЕКТА
# ---------------------------------------------------------------

def rule_mass_export(row, threshold):
    """Правило 1: выгружено больше threshold записей за одно действие."""
    return row["action"] == "export" and row["records_exported"] >= threshold


def rule_off_hours(row):
    """Правило 2: обращение вне рабочих часов или в выходной день."""
    dt = row["dt"]
    if dt.weekday() >= 5:
        return True
    return dt.hour < WORK_START_HOUR or dt.hour >= WORK_END_HOUR


def rule_foreign_resource(row):
    """Правило 3: обращение к ресурсу, не положенному роли пользователя."""
    allowed = ROLE_RESOURCES.get(row["role"], [])
    return row["resource"] not in allowed


# ---------------------------------------------------------------
# RISK SCORE
# ---------------------------------------------------------------

def risk_score(row, threshold):
    """
    Простая оценка риска: каждое сработавшее правило добавляет вес.
    Значение от 0 до 1.
    Эта формула идёт в Section III статьи.
    """
    score = 0.0
    if rule_mass_export(row, threshold):
        score += 0.5
    if rule_off_hours(row):
        score += 0.3
    if rule_foreign_resource(row):
        score += 0.2
    return round(min(score, 1.0), 2)


# ---------------------------------------------------------------
# ПОДСЧЁТ МЕТРИК
# ---------------------------------------------------------------

def evaluate(rows, threshold, risk_cutoff):
    """Прогоняет все правила при заданном пороге и считает TP/FN/FP/TN."""
    tp = fn = fp = tn = 0
    for row in rows:
        alert = risk_score(row, threshold) >= risk_cutoff
        truth = row["is_anomaly"] == 1
        if alert and truth:
            tp += 1
        elif not alert and truth:
            fn += 1
        elif alert and not truth:
            fp += 1
        else:
            tn += 1

    precision = tp / (tp + fp) if (tp + fp) else 0.0
    recall = tp / (tp + fn) if (tp + fn) else 0.0
    f1 = 2 * precision * recall / (precision + recall) if (precision + recall) else 0.0

    return {
        "export_threshold": threshold,
        "risk_cutoff": risk_cutoff,
        "TP": tp, "FN": fn, "FP": fp, "TN": tn,
        "precision": round(precision, 3),
        "recall": round(recall, 3),
        "f1": round(f1, 3),
    }


def per_scenario_recall(rows, threshold, risk_cutoff):
    """Показывает, какие сценарии ловятся хорошо, а какие плохо."""
    stats = {}
    for row in rows:
        if row["is_anomaly"] != 1:
            continue
        sc = row["scenario"]
        stats.setdefault(sc, {"total": 0, "caught": 0})
        stats[sc]["total"] += 1
        if risk_score(row, threshold) >= risk_cutoff:
            stats[sc]["caught"] += 1
    return stats


def main():
    rows = load_log(LOG_FILE)
    print(f"Загружено записей: {len(rows)}")
    print(f"Из них аномальных: {sum(r['is_anomaly'] for r in rows)}\n")

    results = []
    for threshold in EXPORT_THRESHOLDS:
        for cutoff in [0.3, 0.5]:
            results.append(evaluate(rows, threshold, cutoff))

    print(f"{'порог':>7} {'cutoff':>7} {'TP':>5} {'FN':>5} {'FP':>6} "
          f"{'precision':>10} {'recall':>8} {'F1':>7}")
    print("-" * 62)
    for r in results:
        print(f"{r['export_threshold']:>7} {r['risk_cutoff']:>7} "
              f"{r['TP']:>5} {r['FN']:>5} {r['FP']:>6} "
              f"{r['precision']:>10} {r['recall']:>8} {r['f1']:>7}")

    with open(OUTPUT_FILE, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=list(results[0].keys()))
        writer.writeheader()
        writer.writerows(results)
    print(f"\nТаблица сохранена: {OUTPUT_FILE}")

    # Разбор по сценариям при среднем пороге
    print("\nЧто ловится, а что нет (порог 1000, cutoff 0.5):")
    for sc, st in sorted(per_scenario_recall(rows, 1000, 0.5).items()):
        pct = 100 * st["caught"] / st["total"] if st["total"] else 0
        print(f"  {sc:<15} поймано {st['caught']:>3} из {st['total']:>3}  ({pct:.0f}%)")


if __name__ == "__main__":
    main()
