"""
ХЕШ-ЦЕПОЧКА НА РЕАЛЬНЫХ ДАННЫХ CERT (device.csv)

Это адаптация step3_tamper.py: вместо синтетического журнала берём
настоящие события из device.csv.

Идея хеш-цепочки. Каждая запись хранит хеш предыдущей. Если изменить,
удалить или переставить запись, цепочка ломается в этом месте.

Скрипт делает три вещи:
  1. Замеряет время записи и размер файла: обычный журнал против журнала
     с хеш-цепочкой, на объёмах 1k / 5k / 10k / 50k / 100k записей.
  2. Замеряет время проверки цепочки (верификации).
  3. Проверяет обнаружение подделки: изменение, удаление, перестановка.

Результат: chain_overhead_results.csv
Запуск (из папки с device.csv):  python cert_chain.py
"""

import csv
import hashlib
import os
import tempfile
import time

DEVICE_FILE = "device.csv"
OUTPUT_FILE = "chain_overhead_results.csv"

SIZES = [1000, 5000, 10000, 50000, 100000]
# Временные файлы пишем в системную temp-папку, а не в облачную папку:
# синхронизация облака добавляет случайные задержки и искажает замер.
TMP_DIR = tempfile.gettempdir()
TMP_PLAIN = os.path.join(TMP_DIR, "chain_tmp_plain.csv")
TMP_CHAINED = os.path.join(TMP_DIR, "chain_tmp_chained.csv")
TMP_TAMPER = os.path.join(TMP_DIR, "chain_tmp_tamper.csv")

REPEATS = 5            # сколько раз повторить замер и взять среднее
GENESIS = "0" * 64     # "нулевой" хеш, с которого начинается цепочка
FIELDS = ["id", "date", "user", "pc", "activity"]   # колонки device.csv


def load_rows(path, limit):
    """Читает первые limit записей построчно (файл целиком в память не грузим)."""
    rows = []
    with open(path, encoding="utf-8") as f:
        for i, row in enumerate(csv.DictReader(f)):
            if i >= limit:
                break
            rows.append(row)
    return rows


def record_to_text(row):
    """Превращает запись в строку, от которой считается хеш."""
    return "|".join(row[k] for k in FIELDS)


def entry_hash(row, prev_hash):
    """Хеш записи = SHA-256 от (содержимое записи + хеш предыдущей)."""
    payload = record_to_text(row) + "|" + prev_hash
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


def write_plain(rows, path):
    """Обычный журнал, без защиты."""
    with open(path, "w", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        w.writerow(FIELDS)
        for r in rows:
            w.writerow([r[k] for k in FIELDS])


def write_chained(rows, path):
    """Журнал с хеш-цепочкой: к каждой записи добавляются prev_hash и entry_hash."""
    prev_hash = GENESIS
    with open(path, "w", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        w.writerow(FIELDS + ["prev_hash", "entry_hash"])
        for r in rows:
            h = entry_hash(r, prev_hash)
            w.writerow([r[k] for k in FIELDS] + [prev_hash, h])
            prev_hash = h


def verify_chain(path):
    """
    Проверяет целостность цепочки.
    Возвращает (True, None), если всё цело,
    или (False, номер первой битой записи), нумерация с 1.
    """
    prev_hash = GENESIS
    with open(path, encoding="utf-8") as f:
        for n, row in enumerate(csv.DictReader(f), start=1):
            if row["prev_hash"] != prev_hash:
                return False, n          # ссылка на предыдущую не совпала
            if entry_hash(row, prev_hash) != row["entry_hash"]:
                return False, n          # содержимое записи изменено
            prev_hash = row["entry_hash"]
    return True, None


def avg_time_ms(func, repeats):
    """Среднее время выполнения func() в миллисекундах."""
    total = 0.0
    for _ in range(repeats):
        t0 = time.perf_counter()
        func()
        total += time.perf_counter() - t0
    return 1000 * total / repeats


def measure(rows):
    """Замер одного объёма: время записи, время проверки, размер файла."""
    plain_ms = avg_time_ms(lambda: write_plain(rows, TMP_PLAIN), REPEATS)
    chained_ms = avg_time_ms(lambda: write_chained(rows, TMP_CHAINED), REPEATS)
    verify_ms = avg_time_ms(lambda: verify_chain(TMP_CHAINED), REPEATS)
    plain_kb = os.path.getsize(TMP_PLAIN) / 1024
    chained_kb = os.path.getsize(TMP_CHAINED) / 1024
    return {
        "records": len(rows),
        "plain_time_ms": round(plain_ms, 2),
        "chained_time_ms": round(chained_ms, 2),
        "time_overhead_pct": round(100 * (chained_ms - plain_ms) / plain_ms, 1),
        "verify_time_ms": round(verify_ms, 2),
        "plain_size_kb": round(plain_kb, 1),
        "chained_size_kb": round(chained_kb, 1),
        "size_overhead_pct": round(100 * (chained_kb - plain_kb) / plain_kb, 1),
    }


def read_lines(path):
    with open(path, encoding="utf-8") as f:
        return f.readlines()


def write_lines(path, lines):
    with open(path, "w", encoding="utf-8") as f:
        f.writelines(lines)


def tamper_test(rows):
    """
    Три вида подделки на журнале из 10 000 записей.
    Строка 1 файла - заголовок, поэтому запись № n лежит в lines[n].
    """
    path = TMP_TAMPER
    target = 5000
    results = []

    # 1. Изменение: инсайдер меняет тип события в записи 5000 (Connect -> Disconnect)
    write_chained(rows, path)
    lines = read_lines(path)
    old = lines[target]
    lines[target] = old.replace("Connect", "Disconnect", 1) if "Disconnect" not in old \
        else old.replace("Disconnect", "Connect", 1)
    write_lines(path, lines)
    ok, where = verify_chain(path)
    results.append(("изменение записи", target, ok, where))

    # 2. Удаление: запись 5000 целиком вырезана (заметание следов)
    write_chained(rows, path)
    lines = read_lines(path)
    del lines[target]
    write_lines(path, lines)
    ok, where = verify_chain(path)
    results.append(("удаление записи", target, ok, where))

    # 3. Перестановка: записи 5000 и 5001 поменяли местами
    write_chained(rows, path)
    lines = read_lines(path)
    lines[target], lines[target + 1] = lines[target + 1], lines[target]
    write_lines(path, lines)
    ok, where = verify_chain(path)
    results.append(("перестановка 5000 и 5001", target, ok, where))

    # Контроль: нетронутый журнал должен проходить проверку
    write_chained(rows, path)
    ok, where = verify_chain(path)
    print(f"  контроль (без подделки): цепочка цела = {ok}")

    for name, at, ok, where in results:
        print(f"  {name}: цела = {ok}, сбой на записи № {where} "
              f"(подделано на № {at})")
    os.remove(path)


def main():
    print("Замер хеш-цепочки на device.csv (реальные данные CERT r4.2)\n")
    rows_all = load_rows(DEVICE_FILE, max(SIZES))
    print(f"  загружено записей: {len(rows_all)}\n")

    results = []
    for size in SIZES:
        res = measure(rows_all[:size])
        results.append(res)
        print(f"  {size:>6} записей: "
              f"обычно {res['plain_time_ms']:>8.2f} мс, "
              f"с цепочкой {res['chained_time_ms']:>8.2f} мс "
              f"(+{res['time_overhead_pct']}%), "
              f"проверка {res['verify_time_ms']:>8.2f} мс, "
              f"объём +{res['size_overhead_pct']}%")

    with open(OUTPUT_FILE, "w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=list(results[0].keys()))
        w.writeheader()
        w.writerows(results)
    print(f"\nТаблица сохранена: {OUTPUT_FILE}")

    print("\nПроверка обнаружения подделки (журнал из 10 000 записей):")
    tamper_test(rows_all[:10000])

    for tmp in [TMP_PLAIN, TMP_CHAINED, TMP_TAMPER]:
        if os.path.exists(tmp):
            os.remove(tmp)


if __name__ == "__main__":
    main()
