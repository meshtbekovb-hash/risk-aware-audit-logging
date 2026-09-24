"""
ЗАЩИЩЁННАЯ ХЕШ-ЦЕПОЧКА: HMAC-ключ + внешние контрольные точки

Проблема простой цепочки (cert_chain.py). Она ловит грубую подделку, но
нарушитель с правом записи (администратор) может изменить запись и заново
пересчитать все хеши после неё: цепочка останется "целой". Он же может
обрезать хвост журнала, и это тоже не заметно.

Что добавляем:
  1. HMAC вместо простого SHA-256. Метка записи = HMAC(ключ, запись + метка
     предыдущей записи). Без секретного ключа пересчитать цепочку нельзя.
     Ключ хранится отдельно от журнала (например, в HSM или у службы ИБ).
  2. Контрольные точки. Каждые CHECKPOINT_EVERY записей пара
     (число записей, метка) уходит во ВНЕШНЕЕ хранилище (в тесте - отдельный
     файл, в реальной системе - WORM-хранилище или другая система).
     Это ловит обрезку хвоста и подмену даже тем, кто знает ключ, если
     подмена затрагивает уже зафиксированную часть.
  3. Колонка prev_hash убрана: она равна метке предыдущей строки и только
     раздувала журнал. Метка одна на запись.

Скрипт:
  - проверяет обнаружение семи видов атак (три из них старая цепочка
    пропускала);
  - замеряет накладные расходы новой схемы рядом с обычным журналом и
    простой цепочкой.

Результаты: chain_hmac_overhead_results.csv
Запуск (из папки с device.csv):  python cert_chain_hmac.py
"""

import csv
import hashlib
import hmac
import os

import cert_chain as ch

OUTPUT_FILE = "chain_hmac_overhead_results.csv"
CHECKPOINT_EVERY = 1000
# Ключ для теста. В реальной системе он секретный и лежит вне журнала.
KEY = b"test-key-not-a-real-secret"
ATTACKER_KEY = b"attacker-guessed-key"

TMP_LOG = os.path.join(ch.TMP_DIR, "hmac_log.csv")
TMP_ANCHOR = os.path.join(ch.TMP_DIR, "hmac_anchor.csv")
MAC_FIELDS = ch.FIELDS + ["mac"]


def mac_of(row, prev_mac, key):
    """Метка записи = HMAC-SHA256(ключ, запись + метка предыдущей записи)."""
    payload = ch.record_to_text(row) + "|" + prev_mac
    return hmac.new(key, payload.encode("utf-8"), hashlib.sha256).hexdigest()


def write_hmac_chain(rows, log_path, anchor_path, key):
    """
    Пишет журнал с HMAC-цепочкой и отдельный файл контрольных точек.
    Контрольная точка: (сколько записей уже записано, метка последней записи).
    Последняя точка ставится всегда, чтобы зафиксировать общую длину журнала.
    """
    prev = ch.GENESIS
    with open(log_path, "w", newline="", encoding="utf-8") as f, \
            open(anchor_path, "w", newline="", encoding="utf-8") as a:
        w, wa = csv.writer(f), csv.writer(a)
        w.writerow(MAC_FIELDS)
        wa.writerow(["count", "mac"])
        for n, r in enumerate(rows, start=1):
            prev = mac_of(r, prev, key)
            w.writerow([r[k] for k in ch.FIELDS] + [prev])
            if n % CHECKPOINT_EVERY == 0 or n == len(rows):
                wa.writerow([n, prev])


def read_anchors(anchor_path):
    """Контрольные точки в виде словаря {число записей: метка}."""
    with open(anchor_path, encoding="utf-8") as a:
        return {int(r["count"]): r["mac"] for r in csv.DictReader(a)}


def verify_hmac_chain(log_path, anchor_path, key):
    """
    Проверка журнала. Возвращает (True, "") или (False, причина).
      - метка каждой записи пересчитывается с ключом;
      - в местах контрольных точек метка сверяется с внешним хранилищем;
      - если записей меньше, чем зафиксировано в последней точке, значит
        хвост обрезан.
    """
    anchors = read_anchors(anchor_path)
    prev, n = ch.GENESIS, 0
    with open(log_path, encoding="utf-8") as f:
        for n, row in enumerate(csv.DictReader(f), start=1):
            expected = mac_of(row, prev, key)
            if not hmac.compare_digest(expected, row["mac"]):
                return False, f"метка записи № {n} не сходится"
            prev = row["mac"]
            if n in anchors and anchors[n] != prev:
                return False, f"запись № {n} не совпадает с контрольной точкой"
    if n < max(anchors):
        return False, f"журнал обрезан: {n} записей, зафиксировано {max(anchors)}"
    return True, ""


def flip_activity(row):
    """Подменяем тип события (как будто нарушитель заметает следы)."""
    row = dict(row)
    row["activity"] = "Disconnect" if row["activity"] == "Connect" else "Connect"
    return row


def attack_tests(rows):
    """Семь сценариев атак; для каждого сравниваем старую цепочку и новую схему."""
    target = 5000                       # атакуем запись № 5000 из 10 000
    print(f"  {'атака':58} {'старая цепочка':16} новая схема")

    def old_verdict(make_bad_log):
        """Как ту же атаку увидела бы простая SHA-256 цепочка (cert_chain)."""
        make_bad_log(TMP_LOG)
        ok, _ = ch.verify_chain(TMP_LOG)
        return "пропущена" if ok else "обнаружена"

    def new_verdict(log_path, anchors, key=KEY):
        ok, why = verify_hmac_chain(log_path, anchors, key)
        return ("пропущена" if ok else "обнаружена") + ("" if ok else f" ({why})")

    # 1. Изменение записи без пересчёта хешей
    def plain_bad(path):
        ch.write_chained(rows, path)
        lines = ch.read_lines(path)
        lines[target] = lines[target].replace("Connect", "Disconnect", 1) \
            if "Disconnect" not in lines[target] else lines[target].replace("Disconnect", "Connect", 1)
        ch.write_lines(path, lines)
    write_hmac_chain(rows, TMP_LOG, TMP_ANCHOR, KEY)
    lines = ch.read_lines(TMP_LOG)
    lines[target] = lines[target].replace("Disconnect", "Connect", 1) \
        if "Disconnect" in lines[target] else lines[target].replace("Connect", "Disconnect", 1)
    ch.write_lines(TMP_LOG, lines)
    new = new_verdict(TMP_LOG, TMP_ANCHOR)
    print(f"  {'1. изменить запись, хеши не трогать':58} {old_verdict(plain_bad):16} {new}")

    # 2. Изменить запись и пересчитать всю цепочку (без ключа)
    def recompute_plain(path):
        changed = list(rows)
        changed[target - 1] = flip_activity(rows[target - 1])
        ch.write_chained(changed, path)
    changed = list(rows)
    changed[target - 1] = flip_activity(rows[target - 1])
    # Атакующий не знает ключа, поэтому пересчитывает цепочку "своим" ключом
    write_hmac_chain(changed, TMP_LOG, ch.TMP_TAMPER, ATTACKER_KEY)
    write_hmac_chain(rows, ch.TMP_TAMPER + ".real", TMP_ANCHOR, KEY)  # настоящие точки
    new = new_verdict(TMP_LOG, TMP_ANCHOR)
    print(f"  {'2. изменить запись и пересчитать всю цепочку (без ключа)':58} "
          f"{old_verdict(recompute_plain):16} {new}")

    # 3. Обрезать хвост журнала на 100 записей
    def truncate_plain(path):
        ch.write_chained(rows, path)
        ch.write_lines(path, ch.read_lines(path)[:-100])
    write_hmac_chain(rows, TMP_LOG, TMP_ANCHOR, KEY)
    ch.write_lines(TMP_LOG, ch.read_lines(TMP_LOG)[:-100])
    new = new_verdict(TMP_LOG, TMP_ANCHOR)
    print(f"  {'3. обрезать последние 100 записей':58} {old_verdict(truncate_plain):16} {new}")

    # 4. Удалить запись
    def delete_plain(path):
        ch.write_chained(rows, path)
        lines = ch.read_lines(path)
        del lines[target]
        ch.write_lines(path, lines)
    write_hmac_chain(rows, TMP_LOG, TMP_ANCHOR, KEY)
    lines = ch.read_lines(TMP_LOG)
    del lines[target]
    ch.write_lines(TMP_LOG, lines)
    new = new_verdict(TMP_LOG, TMP_ANCHOR)
    print(f"  {'4. удалить запись':58} {old_verdict(delete_plain):16} {new}")

    # 5. Поменять две записи местами
    def swap_plain(path):
        ch.write_chained(rows, path)
        lines = ch.read_lines(path)
        lines[target], lines[target + 1] = lines[target + 1], lines[target]
        ch.write_lines(path, lines)
    write_hmac_chain(rows, TMP_LOG, TMP_ANCHOR, KEY)
    lines = ch.read_lines(TMP_LOG)
    lines[target], lines[target + 1] = lines[target + 1], lines[target]
    ch.write_lines(TMP_LOG, lines)
    new = new_verdict(TMP_LOG, TMP_ANCHOR)
    print(f"  {'5. поменять записи 5000 и 5001 местами':58} {old_verdict(swap_plain):16} {new}")

    # 6. Худший случай: нарушитель УКРАЛ ключ и пересчитал цепочку
    changed = list(rows)
    changed[target - 1] = flip_activity(rows[target - 1])
    write_hmac_chain(changed, TMP_LOG, ch.TMP_TAMPER, KEY)       # ключ известен
    write_hmac_chain(rows, ch.TMP_TAMPER + ".real", TMP_ANCHOR, KEY)
    new = new_verdict(TMP_LOG, TMP_ANCHOR)
    print(f"  {'6. изменить запись, ключ украден, пересчитал цепочку':58} "
          f"{'пропущена':16} {new}")

    # 7. Ключ украден, а подмена в НЕзафиксированной части (после последней точки)
    # Для этого берём журнал из 10 500 записей: точки на 1000, 2000, ..., 10000 и 10500
    long_rows = ch.load_rows(ch.DEVICE_FILE, 10500)
    write_hmac_chain(long_rows, TMP_LOG, TMP_ANCHOR, KEY)
    # Нарушитель переписывает записи после последней "круглой" точки и добавляет свою
    tail_changed = list(long_rows)
    tail_changed[10499] = flip_activity(long_rows[10499])
    write_hmac_chain(tail_changed, TMP_LOG, ch.TMP_TAMPER, KEY)
    # внешнее хранилище получило только точки до 10 000: последняя точка ещё не выгружена
    anchors = read_anchors(TMP_ANCHOR)
    with open(TMP_ANCHOR, "w", newline="", encoding="utf-8") as a:
        wa = csv.writer(a)
        wa.writerow(["count", "mac"])
        for cnt, m in sorted(anchors.items()):
            if cnt <= 10000:
                wa.writerow([cnt, m])
    new = new_verdict(TMP_LOG, TMP_ANCHOR)
    print(f"  {'7. ключ украден, подмена после последней контрольной точки':58} "
          f"{'пропущена':16} {new}")


def measure(rows):
    """Замер: обычный журнал, простая цепочка, HMAC-цепочка с контрольными точками."""
    plain_ms = ch.avg_time_ms(lambda: ch.write_plain(rows, ch.TMP_PLAIN), ch.REPEATS)
    sha_ms = ch.avg_time_ms(lambda: ch.write_chained(rows, ch.TMP_CHAINED), ch.REPEATS)
    hm_ms = ch.avg_time_ms(lambda: write_hmac_chain(rows, TMP_LOG, TMP_ANCHOR, KEY), ch.REPEATS)
    ver_ms = ch.avg_time_ms(lambda: verify_hmac_chain(TMP_LOG, TMP_ANCHOR, KEY), ch.REPEATS)
    kb = lambda p: os.path.getsize(p) / 1024
    plain_kb, sha_kb = kb(ch.TMP_PLAIN), kb(ch.TMP_CHAINED)
    hm_kb = kb(TMP_LOG) + kb(TMP_ANCHOR)
    pct = lambda a, b: round(100 * (a - b) / b, 1)
    return {
        "records": len(rows),
        "plain_ms": round(plain_ms, 2),
        "sha_chain_ms": round(sha_ms, 2),
        "hmac_chain_ms": round(hm_ms, 2),
        "hmac_verify_ms": round(ver_ms, 2),
        "sha_time_overhead_pct": pct(sha_ms, plain_ms),
        "hmac_time_overhead_pct": pct(hm_ms, plain_ms),
        "plain_kb": round(plain_kb, 1),
        "sha_chain_kb": round(sha_kb, 1),
        "hmac_chain_kb": round(hm_kb, 1),
        "sha_size_overhead_pct": pct(sha_kb, plain_kb),
        "hmac_size_overhead_pct": pct(hm_kb, plain_kb),
    }


def main():
    print("HMAC-цепочка с контрольными точками на device.csv\n")
    rows_all = ch.load_rows(ch.DEVICE_FILE, max(ch.SIZES))

    print("Проверка обнаружения атак (журнал 10 000 записей, контрольная точка каждые "
          f"{CHECKPOINT_EVERY}):")
    attack_tests(rows_all[:10000])

    print("\nНакладные расходы:")
    results = []
    for size in ch.SIZES:
        res = measure(rows_all[:size])
        results.append(res)
        print(f"  {size:>6}: простая цепочка +{res['sha_time_overhead_pct']}% времени, "
              f"+{res['sha_size_overhead_pct']}% объёма | "
              f"HMAC-схема +{res['hmac_time_overhead_pct']}% времени, "
              f"+{res['hmac_size_overhead_pct']}% объёма, "
              f"проверка {res['hmac_verify_ms']} мс")

    with open(OUTPUT_FILE, "w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=list(results[0].keys()))
        w.writeheader()
        w.writerows(results)
    print(f"\nТаблица сохранена: {OUTPUT_FILE}")

    for p in [TMP_LOG, TMP_ANCHOR, ch.TMP_PLAIN, ch.TMP_CHAINED,
              ch.TMP_TAMPER, ch.TMP_TAMPER + ".real"]:
        if os.path.exists(p):
            os.remove(p)


if __name__ == "__main__":
    main()
