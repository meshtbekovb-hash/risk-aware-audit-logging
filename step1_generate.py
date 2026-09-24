"""
ШАГ 1. Генератор синтетического журнала доступа.

Создаёт файл access_log.csv - журнал обращений пользователей к
государственной аналитической платформе.

Большая часть записей - нормальная работа.
Примерно 2% записей - действия инсайдера (три сценария).
Колонка is_anomaly хранит правильный ответ: 0 = норма, 1 = аномалия.
Колонка scenario показывает, какой именно сценарий.

Запуск:  python3 step1_generate.py
"""

import csv
import random
from datetime import datetime, timedelta

# ---------------------------------------------------------------
# НАСТРОЙКИ. Меняй только эти значения.
# ---------------------------------------------------------------
TOTAL_RECORDS = 10000      # сколько всего записей в журнале
ANOMALY_SHARE = 0.02       # доля аномальных записей (0.02 = 2%)
OUTPUT_FILE = "access_log.csv"
RANDOM_SEED = 42           # фиксируем случайность, чтобы результат повторялся

random.seed(RANDOM_SEED)

# Роли сотрудников и ресурсы, к которым они обращаются в норме
ROLES = {
    "analyst":    ["survey_results", "reports", "dashboards"],
    "operator":   ["citizen_requests", "survey_results"],
    "admin":      ["system_config", "audit_logs", "user_accounts"],
    "supervisor": ["reports", "dashboards", "audit_logs"],
}

ALL_RESOURCES = sorted({r for lst in ROLES.values() for r in lst})

# Пользователи: 40 человек, каждому назначена роль
USERS = []
for i in range(1, 41):
    role = random.choice(list(ROLES.keys()))
    USERS.append({"user_id": f"user_{i:03d}", "role": role})

START_DATE = datetime(2026, 3, 1, 0, 0, 0)
DAYS = 30


def random_work_time():
    """Случайное время в рабочие часы (пн-пт, 09:00-18:00)."""
    while True:
        day = random.randint(0, DAYS - 1)
        moment = START_DATE + timedelta(days=day)
        if moment.weekday() < 5:          # 0-4 = пн-пт
            break
    hour = random.randint(9, 17)
    return moment.replace(hour=hour,
                          minute=random.randint(0, 59),
                          second=random.randint(0, 59))


def random_off_hours_time():
    """Случайное время вне рабочих часов (ночь или выходной)."""
    day = random.randint(0, DAYS - 1)
    moment = START_DATE + timedelta(days=day)
    if moment.weekday() >= 5:             # выходной - любое время
        hour = random.randint(0, 23)
    else:                                 # будний день - ночь
        hour = random.choice([0, 1, 2, 3, 4, 5, 22, 23])
    return moment.replace(hour=hour,
                          minute=random.randint(0, 59),
                          second=random.randint(0, 59))


def make_ip(internal=True):
    if internal:
        return f"10.0.{random.randint(1, 20)}.{random.randint(2, 254)}"
    return f"85.{random.randint(10, 250)}.{random.randint(1, 254)}.{random.randint(2, 254)}"


def normal_record():
    """
    Обычное рабочее действие сотрудника.

    ВАЖНО: в нормальный трафик специально добавлен шум.
    В реальной организации сотрудники иногда задерживаются вечером,
    иногда выгружают большой отчёт по заданию руководства,
    иногда им дают временный доступ к чужому ресурсу.
    Без этого шума правила давали бы нулевое количество ложных
    срабатываний, а это нереалистично и сразу вызовет вопросы
    у рецензента.
    """
    user = random.choice(USERS)
    resource = random.choice(ROLES[user["role"]])
    timestamp = random_work_time()
    exported = random.randint(1, 80)

    roll = random.random()
    if roll < 0.03:
        # 3%: легальная переработка вечером или выход в выходной
        timestamp = random_off_hours_time()
    elif roll < 0.05:
        # 2%: законная выгрузка крупного отчёта
        exported = random.randint(400, 2500)
    elif roll < 0.07:
        # 2%: временный доступ к ресурсу вне своей роли
        foreign = [r for r in ALL_RESOURCES if r not in ROLES[user["role"]]]
        resource = random.choice(foreign)

    return {
        "timestamp": timestamp,
        "user_id": user["user_id"],
        "role": user["role"],
        "resource": resource,
        "action": random.choices(["view", "search", "export"],
                                 weights=[60, 30, 10])[0],
        "records_exported": exported,
        "ip": make_ip(internal=True),
        "is_anomaly": 0,
        "scenario": "normal",
    }


def mass_export_record():
    """Сценарий 1: массовая выгрузка. Инсайдер тянет тысячи записей сразу."""
    user = random.choice(USERS)
    return {
        "timestamp": random_work_time(),
        "user_id": user["user_id"],
        "role": user["role"],
        "resource": random.choice(ROLES[user["role"]]),
        "action": "export",
        "records_exported": random.randint(3000, 25000),
        "ip": make_ip(internal=True),
        "is_anomaly": 1,
        "scenario": "mass_export",
    }


def off_hours_record():
    """Сценарий 2: работа вне рабочего времени, ночью или в выходной."""
    user = random.choice(USERS)
    return {
        "timestamp": random_off_hours_time(),
        "user_id": user["user_id"],
        "role": user["role"],
        "resource": random.choice(ROLES[user["role"]]),
        "action": random.choice(["export", "search"]),
        "records_exported": random.randint(200, 1500),
        "ip": make_ip(internal=random.random() < 0.5),
        "is_anomaly": 1,
        "scenario": "off_hours",
    }


def low_and_slow_record():
    """
    Сценарий 3: медленная утечка (low-and-slow).
    Объём каждой выгрузки небольшой и по отдельности не выделяется,
    но пользователь обращается к ресурсу вне своей роли.
    Этот сценарий специально сделан трудным для простых порогов -
    он даст вам пропуски (FN) и покажет пределы метода.
    """
    user = random.choice(USERS)
    foreign = [r for r in ALL_RESOURCES if r not in ROLES[user["role"]]]
    return {
        "timestamp": random_work_time(),
        "user_id": user["user_id"],
        "role": user["role"],
        "resource": random.choice(foreign),
        "action": "export",
        "records_exported": random.randint(90, 400),
        "ip": make_ip(internal=True),
        "is_anomaly": 1,
        "scenario": "low_and_slow",
    }


def main():
    anomaly_count = int(TOTAL_RECORDS * ANOMALY_SHARE)
    normal_count = TOTAL_RECORDS - anomaly_count

    records = [normal_record() for _ in range(normal_count)]

    # Аномалии делим примерно поровну между тремя сценариями
    per_scenario = anomaly_count // 3
    for _ in range(per_scenario):
        records.append(mass_export_record())
    for _ in range(per_scenario):
        records.append(off_hours_record())
    for _ in range(anomaly_count - 2 * per_scenario):
        records.append(low_and_slow_record())

    # Сортируем по времени, чтобы журнал выглядел как настоящий
    records.sort(key=lambda r: r["timestamp"])

    for i, r in enumerate(records, start=1):
        r["event_id"] = i
        r["timestamp"] = r["timestamp"].strftime("%Y-%m-%d %H:%M:%S")

    fields = ["event_id", "timestamp", "user_id", "role", "resource",
              "action", "records_exported", "ip", "is_anomaly", "scenario"]

    with open(OUTPUT_FILE, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=fields)
        writer.writeheader()
        writer.writerows(records)

    print(f"Готово: {OUTPUT_FILE}")
    print(f"Всего записей:      {len(records)}")
    print(f"Из них аномальных:  {anomaly_count}")
    print(f"  mass_export:      {sum(1 for r in records if r['scenario'] == 'mass_export')}")
    print(f"  off_hours:        {sum(1 for r in records if r['scenario'] == 'off_hours')}")
    print(f"  low_and_slow:     {sum(1 for r in records if r['scenario'] == 'low_and_slow')}")


if __name__ == "__main__":
    main()
