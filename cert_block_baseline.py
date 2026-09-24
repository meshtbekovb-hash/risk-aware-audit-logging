"""
БЛОЧНАЯ СХЕМА КАК ЕСТЕСТВЕННАЯ АЛЬТЕРНАТИВА RISK-AWARE

Замечание рецензента: "выборочная защита" оправдывалась экономией, но блочная схема
(один HMAC на блок из B записей) экономит ещё больше и покрывает ВСЕ записи. Проверяем это.

Сравниваем на одном и том же журнале device тестового периода (168 392 записи):
  1. обычный журнал (без защиты);
  2. полная поэлементная HMAC-цепочка (каждая запись, контрольная точка каждые 1000);
  3. БЛОЧНАЯ схема: один HMAC на блок из B записей, метка каждого блока уходит во
     внешнее хранилище; покрыты ВСЕ записи, но локализация только до блока;
  4. risk-aware поэлементная цепочка ТОЛЬКО для записей дней с r >= tau (как раньше);
  5. ГИБРИД: блочная схема для всего журнала + поэлементная цепочка для записей дней с r >= tau.
     Все записи защищены на уровне блока, рискованные ещё и с точностью до одной записи.

Считаем: время записи, объём файлов, покрытие, локализацию подделки; проверяем атаки
на блочную схему тем же набором из семи атак.

Результат: block_baseline_results.csv
Запуск (из папки с CSV):  python cert_block_baseline.py
"""

import csv
import hashlib
import hmac
import os
from datetime import timedelta

import cert_ablation as ab
import cert_chain as ch
import cert_chain_hmac as chm
import cert_honest_split as hs
import cert_riskaware as ra
import cert_user_level2 as u2

OUTPUT_FILE = "block_baseline_results.csv"
KEY = chm.KEY
ATTACKER_KEY = chm.ATTACKER_KEY
TMP = ch.TMP_DIR
P_PLAIN = os.path.join(TMP, "bb_plain.csv")
P_BLOCKLOG = os.path.join(TMP, "bb_blocklog.csv")
P_BLOCKTAGS = os.path.join(TMP, "bb_blocktags.csv")
P_CHAINLOG = os.path.join(TMP, "bb_chainlog.csv")
P_CHAINANCH = os.path.join(TMP, "bb_chainanch.csv")


def write_block_hmac(rows, log_path, tags_path, key, block):
    """
    Блочная схема. Записи пишутся обычным журналом, а на каждые block записей считается
    ОДИН HMAC: метка блока j = HMAC(K, метка блока j-1 + тексты всех записей блока).
    Метки блоков (номер блока, число записей, метка) идут в отдельный файл: это то,
    что уходит во внешнее хранилище. Хеш обновляется по записи, но новая метка создаётся
    только раз на блок, поэтому такая схема дешевле поэлементной цепочки.
    """
    prev = ch.GENESIS
    with open(log_path, "w", newline="", encoding="utf-8") as f, \
            open(tags_path, "w", newline="", encoding="utf-8") as t:
        w, wt = csv.writer(f), csv.writer(t)
        w.writerow(ch.FIELDS)
        wt.writerow(["block", "count", "tag"])
        h = hmac.new(key, prev.encode("utf-8"), hashlib.sha256)
        in_block = count = idx = 0
        for r in rows:
            w.writerow([r[k] for k in ch.FIELDS])
            h.update(ch.record_to_text(r).encode("utf-8") + b"\n")
            in_block += 1
            count += 1
            if in_block == block:                       # блок закрыт: фиксируем метку
                prev = h.hexdigest()
                idx += 1
                wt.writerow([idx, count, prev])
                h = hmac.new(key, prev.encode("utf-8"), hashlib.sha256)
                in_block = 0
        if in_block:                                    # неполный последний блок
            idx += 1
            wt.writerow([idx, count, h.hexdigest()])


def read_tags(tags_path):
    with open(tags_path, encoding="utf-8") as t:
        return [(int(r["block"]), int(r["count"]), r["tag"]) for r in csv.DictReader(t)]


def verify_block(log_path, tags_path, key, block):
    """
    Проверка блочной схемы. Возвращает (True, "") или (False, причина).
    Локализация: только номер блока (до block записей), а не одна запись.
    """
    tags = {b: (c, tag) for b, c, tag in read_tags(tags_path)}
    prev = ch.GENESIS
    h = hmac.new(key, prev.encode("utf-8"), hashlib.sha256)
    in_block = count = idx = 0
    with open(log_path, encoding="utf-8") as f:
        for row in csv.DictReader(f):
            h.update(ch.record_to_text(row).encode("utf-8") + b"\n")
            in_block += 1
            count += 1
            if in_block == block:
                idx += 1
                tag = h.hexdigest()
                if idx in tags and tags[idx][1] != tag:
                    return False, f"блок {idx} (записи {count - block + 1}..{count}) не совпал с внешней меткой"
                prev = tag
                h = hmac.new(key, prev.encode("utf-8"), hashlib.sha256)
                in_block = 0
    if in_block:
        idx += 1
        if idx in tags and tags[idx][1] != h.hexdigest():
            return False, f"последний блок {idx} не совпал с внешней меткой"
    if tags and count < max(c for c, _ in tags.values()):
        return False, f"журнал обрезан: {count} записей, зафиксировано {max(c for c, _ in tags.values())}"
    return True, ""


def flip(row):
    row = dict(row)
    row["activity"] = "Disconnect" if row["activity"] == "Connect" else "Connect"
    return row


def attack_tests(rows, block):
    """Те же семь атак на блочную схему (журнал 10 000 записей, блок block записей)."""
    target = 5000
    print(f"Блочная схема, блок {block} записей: та же серия атак (журнал из 10 000 записей)")

    def verdict(log, tags, key=KEY):
        ok, why = verify_block(log, tags, key, block)
        return "ПРОПУЩЕНА" if ok else "обнаружена (" + why + ")"

    def fresh(rs=rows):
        write_block_hmac(rs, P_BLOCKLOG, P_BLOCKTAGS, KEY, block)

    fresh()
    lines = ch.read_lines(P_BLOCKLOG)
    lines[target] = lines[target].replace("Connect", "Disconnect", 1) if "Disconnect" not in lines[target] \
        else lines[target].replace("Disconnect", "Connect", 1)
    ch.write_lines(P_BLOCKLOG, lines)
    print(f"  1. изменить запись 5000:                  {verdict(P_BLOCKLOG, P_BLOCKTAGS)}")

    changed = list(rows)
    changed[target - 1] = flip(rows[target - 1])
    write_block_hmac(changed, P_BLOCKLOG, os.path.join(TMP, "bb_attacker.csv"), ATTACKER_KEY, block)
    fresh()  # внешние метки настоящие
    write_block_hmac(changed, P_BLOCKLOG, os.path.join(TMP, "bb_attacker.csv"), ATTACKER_KEY, block)
    print(f"  2. изменить и пересчитать (ключа нет):     {verdict(P_BLOCKLOG, P_BLOCKTAGS)}")

    fresh()
    ch.write_lines(P_BLOCKLOG, ch.read_lines(P_BLOCKLOG)[:-100])
    print(f"  3. обрезать последние 100 записей:         {verdict(P_BLOCKLOG, P_BLOCKTAGS)}")

    fresh()
    lines = ch.read_lines(P_BLOCKLOG)
    del lines[target]
    ch.write_lines(P_BLOCKLOG, lines)
    print(f"  4. удалить запись 5000:                    {verdict(P_BLOCKLOG, P_BLOCKTAGS)}")

    fresh()
    lines = ch.read_lines(P_BLOCKLOG)
    lines[target], lines[target + 1] = lines[target + 1], lines[target]
    ch.write_lines(P_BLOCKLOG, lines)
    print(f"  5. поменять записи 5000 и 5001:            {verdict(P_BLOCKLOG, P_BLOCKTAGS)}")

    fresh()
    write_block_hmac(changed, P_BLOCKLOG, os.path.join(TMP, "bb_stolen.csv"), KEY, block)
    print(f"  6. ключ украден, изменить и пересчитать:   {verdict(P_BLOCKLOG, P_BLOCKTAGS)}")

    long_rows = ch.load_rows(ch.DEVICE_FILE, 10500)          # блок 11 (записи 10001..10500) ещё не закрыт
    write_block_hmac(long_rows, P_BLOCKLOG, P_BLOCKTAGS, KEY, block)
    tags = [t for t in read_tags(P_BLOCKTAGS) if t[1] <= 10000]   # во внешнее хранилище ушли только закрытые блоки
    with open(P_BLOCKTAGS, "w", newline="", encoding="utf-8") as t:
        wt = csv.writer(t)
        wt.writerow(["block", "count", "tag"])
        wt.writerows(tags)
    bad = list(long_rows)
    bad[10499] = flip(long_rows[10499])
    write_block_hmac(bad, P_BLOCKLOG, os.path.join(TMP, "bb_open.csv"), KEY, block)
    print(f"  7. ключ украден, подмена в открытом блоке: {verdict(P_BLOCKLOG, P_BLOCKTAGS)}")


def main():
    # ---- 1. Атаки на блочную схему ----
    rows_all = ch.load_rows(ch.DEVICE_FILE, 10500)
    for block in (1000,):
        attack_tests(rows_all[:10000], block)

    # ---- 2. Стоимость на журнале device тестового периода ----
    windows = ab.load_labels()
    ud = ab.load_events()
    days = sorted({d for _, d in ud})
    train_end = days[0] + timedelta(days=ab.BASELINE_DAYS)
    prof = ab.build_profiles(ud, train_end)
    test_keys = [k for k in ud if k[1] >= hs.TEST_START]
    events = ra.load_test_events(hs.TEST_START)
    total = len(events)
    is_bad = [ab.scenario_of(windows, u, d) is not None for _, u, d in events]
    total_bad = sum(is_bad)
    all_rows = [r for r, _, _ in events]
    print(f"\nЖурнал device тестового периода: {total} записей, вредоносных по разметке {total_bad}\n")

    def cost(write_fn, paths):
        """Среднее время записи (мс) и суммарный объём файлов (КБ)."""
        ms = ch.avg_time_ms(write_fn, ra.REPEATS)
        kb = sum(os.path.getsize(p) / 1024 for p in paths if os.path.exists(p))
        return ms, kb

    results = []

    def add(name, ms, kb, covered_pct, malicious_pct, local):
        results.append({"scheme": name, "time_ms": round(ms, 1), "size_kb": round(kb, 1),
                        "records_covered_pct": round(covered_pct, 2),
                        "malicious_covered_pct": round(malicious_pct, 1), "localization": local})

    plain_ms, plain_kb = cost(lambda: ch.write_plain(all_rows, P_PLAIN), [P_PLAIN])
    add("plain log", plain_ms, plain_kb, 0, 0, "-")

    full_ms, full_kb = cost(lambda: chm.write_hmac_chain(all_rows, P_CHAINLOG, P_CHAINANCH, KEY),
                            [P_CHAINLOG, P_CHAINANCH])
    add("full per-record HMAC chain", full_ms, full_kb, 100, 100, "exact record")

    for block in (100, 1000, 10000):
        ms, kb = cost(lambda b=block: write_block_hmac(all_rows, P_BLOCKLOG, P_BLOCKTAGS, KEY, b),
                      [P_BLOCKLOG, P_BLOCKTAGS])
        add(f"block HMAC, B={block}", ms, kb, 100, 100, f"block of {block} records")

    for cutoff in u2.score_levels(hs.CONFIG_FEATURES["device"]):
        flagged = ra.flagged_days(ud, prof, test_keys, cutoff)
        in_chain = [r for (r, u, d) in events if (u, d) in flagged]
        bad_prot = sum(1 for (e, b) in zip(events, is_bad) if b and (e[1], e[2]) in flagged)
        share = 100 * len(in_chain) / total
        mal = 100 * bad_prot / total_bad

        def write_ra():
            ch.write_plain(all_rows, P_PLAIN)
            chm.write_hmac_chain(in_chain, P_CHAINLOG, P_CHAINANCH, KEY)
        ms, kb = cost(write_ra, [P_PLAIN, P_CHAINLOG, P_CHAINANCH])
        add(f"risk-aware per-record chain only, tau={cutoff}", ms, kb, share, mal, "exact record (risky only)")

        def write_hybrid():
            write_block_hmac(all_rows, P_BLOCKLOG, P_BLOCKTAGS, KEY, 1000)
            chm.write_hmac_chain(in_chain, P_CHAINLOG, P_CHAINANCH, KEY)
        ms, kb = cost(write_hybrid, [P_BLOCKLOG, P_BLOCKTAGS, P_CHAINLOG, P_CHAINANCH])
        add(f"hybrid: block B=1000 for all + per-record chain tau={cutoff}", ms, kb, 100, 100,
            f"block for all, exact record for {share:.2f}% risky")

    print(f"{'scheme':66} {'time, ms':>9} {'x plain':>8} {'size, MB':>9} {'records covered':>16} {'malicious covered':>18}")
    for r in results:
        print(f"{r['scheme']:66} {r['time_ms']:>9.1f} {r['time_ms'] / plain_ms:>7.2f}x {r['size_kb'] / 1024:>9.1f} "
              f"{r['records_covered_pct']:>15.2f}% {r['malicious_covered_pct']:>17.1f}%   {r['localization']}")
    print("\n(В строке 'risk-aware only' покрытие записей = доля записей в цепочке; для схем, защищающих весь журнал = 100%.)")

    with open(OUTPUT_FILE, "w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=list(results[0].keys()))
        w.writeheader()
        w.writerows(results)
    print(f"Таблица сохранена: {OUTPUT_FILE}")
    for p in (P_PLAIN, P_BLOCKLOG, P_BLOCKTAGS, P_CHAINLOG, P_CHAINANCH,
              os.path.join(TMP, "bb_attacker.csv"), os.path.join(TMP, "bb_stolen.csv"), os.path.join(TMP, "bb_open.csv")):
        if os.path.exists(p):
            os.remove(p)


if __name__ == "__main__":
    main()
