"""
ШАГ 3. Tamper-evident логирование: хеш-цепочка.

Идея. Каждая запись журнала содержит хеш предыдущей записи.
Получается цепочка, как в блокчейне. Если кто-то изменит запись
в середине журнала, её хеш перестанет совпадать с тем, что записан
в следующей записи, и подделка обнаружится.

Скрипт делает три вещи:
  1. Записывает журнал двумя способами - обычным и с хеш-цепочкой,
     и замеряет время и размер файла. Это накладные расходы (overhead).
  2. Повторяет замер на разных объёмах, чтобы получился график.
  3. Подделывает одну запись в середине и показывает, что проверка
     обнаруживает это и указывает точное место.

Результат: overhead_results.csv

Запуск:  python3 step3_tamper.py
"""

import csv
import hashlib
import os
import time

LOG_FILE = "access_log.csv"
OUTPUT_FILE = "overhead_results.csv"

# Объёмы, на которых меряем. Даёт ось X для графика.
SIZES = [1000, 2500, 5000, 7500, 10000]

REPEATS = 5          # сколько раз повторить замер и усреднить
GENESIS = "0" * 64   # хеш "нулевой" записи, с которой начинается цепочка


def load_rows(path, limit):
    rows = []
    with open(path, encoding="utf-8") as f:
        for i, row in enumerate(csv.DictReader(f)):
            if i >= limit:
                break
            rows.append(row)
    return rows


def record_to_text(row):
    """Превращает запись в строку, от которой считается хеш."""
    return "|".join([
        row["event_id"], row["timestamp"], row["user_id"], row["role"],
        row["resource"], row["action"], row["records_exported"], row["ip"],
    ])


def write_plain(rows, path):
    """Обычная запись журнала, без защиты."""
    with open(path, "w", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        w.writerow(["event_id", "timestamp", "user_id", "role",
                    "resource", "action", "records_exported", "ip"])
        for r in rows:
            w.writerow([r["event_id"], r["timestamp"], r["user_id"], r["role"],
                        r["resource"], r["action"], r["records_exported"], r["ip"]])


def write_chained(rows, path):
    """Запись журнала с хеш-цепочкой."""
    prev_hash = GENESIS
    with open(path, "w", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        w.writerow(["event_id", "timestamp", "user_id", "role", "resource",
                    "action", "records_exported", "ip", "prev_hash", "entry_hash"])
        for r in rows:
            payload = record_to_text(r) + "|" + prev_hash
            entry_hash = hashlib.sha256(payload.encode("utf-8")).hexdigest()
            w.writerow([r["event_id"], r["timestamp"], r["user_id"], r["role"],
                        r["resource"], r["action"], r["records_exported"],
                        r["ip"], prev_hash, entry_hash])
            prev_hash = entry_hash


def verify_chain(path):
    """
    Проверяет целостность цепочки.
    Возвращает (True, None) если всё цело,
    или (False, номер первой битой записи).
    """
    prev_hash = GENESIS
    with open(path, encoding="utf-8") as f:
        for row in csv.DictReader(f):
            if row["prev_hash"] != prev_hash:
                return False, int(row["event_id"])
            payload = record_to_text(row) + "|" + prev_hash
            expected = hashlib.sha256(payload.encode("utf-8")).hexdigest()
            if expected != row["entry_hash"]:
                return False, int(row["event_id"])
            prev_hash = row["entry_hash"]
    return True, None


def measure(rows):
    """Замеряет среднее время записи двумя способами."""
    plain_times, chained_times = [], []

    for _ in range(REPEATS):
        t0 = time.perf_counter()
        write_plain(rows, "tmp_plain.csv")
        plain_times.append(time.perf_counter() - t0)

        t0 = time.perf_counter()
        write_chained(rows, "tmp_chained.csv")
        chained_times.append(time.perf_counter() - t0)

    plain_ms = 1000 * sum(plain_times) / REPEATS
    chained_ms = 1000 * sum(chained_times) / REPEATS
    plain_kb = os.path.getsize("tmp_plain.csv") / 1024
    chained_kb = os.path.getsize("tmp_chained.csv") / 1024

    return {
        "records": len(rows),
        "plain_time_ms": round(plain_ms, 2),
        "chained_time_ms": round(chained_ms, 2),
        "time_overhead_pct": round(100 * (chained_ms - plain_ms) / plain_ms, 1),
        "plain_size_kb": round(plain_kb, 1),
        "chained_size_kb": round(chained_kb, 1),
        "size_overhead_pct": round(100 * (chained_kb - plain_kb) / plain_kb, 1),
    }


def tamper_test():
    """
    Проверка обнаружения подделки.
    Берём защищённый журнал, меняем в середине объём выгрузки
    (как будто инсайдер заметает следы) и запускаем проверку.
    """
    rows = load_rows(LOG_FILE, 10000)
    write_chained(rows, "tamper_demo.csv")

    ok, where = verify_chain("tamper_demo.csv")
    print(f"  До подделки:    цепочка цела = {ok}")

    # Подделываем запись номер 5000
    with open("tamper_demo.csv", encoding="utf-8") as f:
        lines = f.readlines()
    target_line = 5000
    parts = lines[target_line].rstrip("\r\n").split(",")
    old_value = parts[6]
    parts[6] = "1"                       # прячем массовую выгрузку
    lines[target_line] = ",".join(parts) + "\n"
    with open("tamper_demo.csv", "w", encoding="utf-8") as f:
        f.writelines(lines)

    ok, where = verify_chain("tamper_demo.csv")
    print(f"  После подделки: цепочка цела = {ok}, сбой на записи № {where}")
    print(f"  (значение records_exported подменено с {old_value} на 1)")


def main():
    print("Замер накладных расходов хеш-цепочки\n")
    results = []
    for size in SIZES:
        rows = load_rows(LOG_FILE, size)
        res = measure(rows)
        results.append(res)
        print(f"  {size:>6} записей: "
              f"обычно {res['plain_time_ms']:>6.2f} мс, "
              f"с цепочкой {res['chained_time_ms']:>6.2f} мс "
              f"(+{res['time_overhead_pct']}%), "
              f"объём +{res['size_overhead_pct']}%")

    with open(OUTPUT_FILE, "w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=list(results[0].keys()))
        w.writeheader()
        w.writerows(results)
    print(f"\nТаблица сохранена: {OUTPUT_FILE}")

    print("\nПроверка обнаружения подделки:")
    tamper_test()

    for tmp in ["tmp_plain.csv", "tmp_chained.csv"]:
        if os.path.exists(tmp):
            os.remove(tmp)


if __name__ == "__main__":
    main()
