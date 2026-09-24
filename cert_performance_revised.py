"""
ЗАДАЧА 7 REVISION_PLAN.md: ВОСПРОИЗВОДИМОСТЬ ЗАМЕРОВ И РАЗБИВКА ОБЪЁМА

Прежние замеры (разделы 4.5, 6.8a) делались как среднее из 3-5 запусков без разброса.
Здесь для каждой схемы (обычный журнал, SHA-256 цепочка, HMAC-цепочка с контрольными
точками, блочная HMAC B=1000) на журнале в N=10000 записей device.csv:

  1. 20 засчитываемых повторов + 3 прогревочных (не считаются) - среднее, стандартное
     отклонение, 95% доверительный интервал (t-распределение, т.к. n=20 - не Z).
  2. Хранение тегов hex (как сейчас) против бинарного - показано изменение объёма.
  3. Обычная запись против записи с принудительным fsync (флеш ОС + физический сброс
     на диск) - для каждой схемы и обоих режимов отдельные 20 повторов.
  4. Проверка, входит ли запись контрольных точек в замер времени: у HMAC- и блочной
     схемы это заложено в тот же вызов (один and тот же `with open(...) as f, open(...)
     as a:`), поэтому время контрольных точек УЖЕ внутри общего замера. Чтобы показать
     явно, сколько это стоит, отдельно замеряется запись ТОЛЬКО записей без внешнего
     файла и ТОЛЬКО внешнего файла (контрольных точек/меток блоков) отдельно от записей.
  5. Разбивка итогового объёма на части: сами записи, теги HMAC, метаданные блоков,
     контрольные точки - по факту записанных байт, не по оценке.
  6. Характеристики машины - через platform (Python/ОС) и заранее считанные системные
     данные (см. запись в CSV; сверено PowerShell-командами перед запуском).

НИЧЕГО В САМИХ СХЕМАХ НЕ МЕНЯЕТСЯ (cert_chain.py, cert_chain_hmac.py,
cert_block_baseline.py не трогаются). fsync и бинарные теги - НОВЫЕ, отдельные функции
записи в этом файле, для сравнения, а не замена существующих.

Результаты: results_revision/performance_revised.csv, results_revision/storage_breakdown.csv
Запуск (из папки с device.csv):  python cert_performance_revised.py
"""

import csv
import hashlib
import hmac
import os
import platform
import sys
import time
from statistics import mean, stdev

import cert_chain as ch
import cert_chain_hmac as chm
import cert_block_baseline as bb

N = 10000
BLOCK = 1000
WARMUP = 3
REPEATS = 20
TMP = ch.TMP_DIR
KEY = chm.KEY

PERF_CSV = "results_revision/performance_revised.csv"
STORAGE_CSV = "results_revision/storage_breakdown.csv"

P_PLAIN = os.path.join(TMP, "pr_plain.csv")
P_SHA = os.path.join(TMP, "pr_sha.csv")
P_HLOG = os.path.join(TMP, "pr_hlog.csv")
P_HANCH = os.path.join(TMP, "pr_hanch.csv")
P_BLOG = os.path.join(TMP, "pr_blog.csv")
P_BTAGS = os.path.join(TMP, "pr_btags.csv")
# для варианта "только записи, без внешнего файла" / "только внешний файл"
P_HLOG_ONLY = os.path.join(TMP, "pr_hlog_only.csv")
P_HANCH_ONLY = os.path.join(TMP, "pr_hanch_only.csv")
P_BLOG_ONLY = os.path.join(TMP, "pr_blog_only.csv")
P_BTAGS_ONLY = os.path.join(TMP, "pr_btags_only.csv")
# бинарные варианты (новые, отдельные функции - см. ниже)
P_HLOG_BIN_REC = os.path.join(TMP, "pr_hlog_bin_records.csv")   # записи без тега (текст)
P_HLOG_BIN_TAGS = os.path.join(TMP, "pr_hlog_bin_tags.bin")     # теги отдельным бинарным файлом
P_BTAGS_BIN = os.path.join(TMP, "pr_btags_bin.bin")


def fsync_path(path):
    """Принудительно сбрасывает файл на диск: flush буфера ОС + физический fsync."""
    fd = os.open(path, os.O_RDWR)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def timed(write_fn, paths, sync):
    """Время одного прогона: сама запись + (если sync) принудительный fsync каждого файла."""
    t0 = time.perf_counter()
    write_fn()
    if sync:
        for p in paths:
            fsync_path(p)
    return time.perf_counter() - t0


def run_repeated(write_fn, paths, sync, warmup=WARMUP, repeats=REPEATS):
    for _ in range(warmup):
        timed(write_fn, paths, sync)
    times = [1000 * timed(write_fn, paths, sync) for _ in range(repeats)]
    m = mean(times)
    sd = stdev(times) if len(times) > 1 else 0.0
    # 95% ДИ по t-распределению (n=20, df=19, t=2.093) - не Z, выборка небольшая
    T_995_DF19 = 2.093
    half = T_995_DF19 * sd / (repeats ** 0.5)
    return {"mean_ms": round(m, 2), "std_ms": round(sd, 2),
            "ci95_lo_ms": round(m - half, 2), "ci95_hi_ms": round(m + half, 2),
            "times_ms": times}


# ---------------------------------------------------------------
# Бинарное хранение тегов (новые функции, только для сравнения)
# ---------------------------------------------------------------
def write_hmac_chain_binary_tags(rows, records_path, tags_path, key):
    """
    То же самое, что chm.write_hmac_chain, но теги хранятся не hex-строкой в той же
    CSV-строке (64 символа), а сырыми 32 байтами в ОТДЕЛЬНОМ бинарном файле, один тег
    за другим, в порядке записей. records_path содержит только сами записи (без тега) -
    хранить бинарные байты внутри CSV-строки напрямую нельзя (запятые/переводы строк
    в теге сломали бы формат), поэтому теги физически отделены от текста.
    """
    prev = ch.GENESIS
    with open(records_path, "w", newline="", encoding="utf-8") as f, open(tags_path, "wb") as t:
        w = csv.writer(f)
        w.writerow(ch.FIELDS)
        for r in rows:
            prev = chm.mac_of(r, prev, key)          # то же самое вычисление тега, что в оригинале
            w.writerow([r[k] for k in ch.FIELDS])
            t.write(bytes.fromhex(prev))              # 32 байта вместо 64 символов hex


def write_block_tags_binary(tags_hex_path, tags_bin_path):
    """Перекодирует уже посчитанные метки блоков (block,count,tag-hex) в бинарный файл:
    для каждого блока - 4 байта номер блока, 4 байта число записей, 32 байта тег."""
    import struct
    rows = bb.read_tags(tags_hex_path)
    with open(tags_bin_path, "wb") as out:
        for b, c, tag in rows:
            out.write(struct.pack(">II", b, c) + bytes.fromhex(tag))


def strip_tag_column_size(tags_hex_path):
    """Точный (не оценочный) размер файла меток блоков БЕЗ колонки tag - записывает
    временный файл с колонками block,count и меряет его реальный размер в байтах."""
    tmp = tags_hex_path + ".notag.tmp"
    rows = bb.read_tags(tags_hex_path)
    with open(tmp, "w", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        w.writerow(["block", "count"])
        for b, c, _ in rows:
            w.writerow([b, c])
    size = os.path.getsize(tmp)
    os.remove(tmp)
    return size


def main():
    print("Загрузка device.csv...")
    rows = ch.load_rows(ch.DEVICE_FILE, N)
    print(f"записей: {len(rows)}\n")

    perf_rows = []

    # =================================================================
    # 1 + 3. Сравнение схем: 20 повторов, 2 режима (обычно / fsync)
    # =================================================================
    print("=" * 100)
    print(f"1+3. Сравнение схем: {REPEATS} повторов (+{WARMUP} прогревочных, не считаются), "
          f"обычная запись и запись с fsync")
    print("=" * 100)

    schemes = [
        ("обычный журнал", lambda: ch.write_plain(rows, P_PLAIN), [P_PLAIN]),
        ("SHA-256 цепочка", lambda: ch.write_chained(rows, P_SHA), [P_SHA]),
        ("HMAC поэлементная", lambda: chm.write_hmac_chain(rows, P_HLOG, P_HANCH, KEY), [P_HLOG, P_HANCH]),
        ("блочная HMAC B=1000", lambda: bb.write_block_hmac(rows, P_BLOG, P_BTAGS, KEY, BLOCK), [P_BLOG, P_BTAGS]),
    ]

    for name, fn, paths in schemes:
        for sync, sync_name in [(False, "обычная"), (True, "fsync")]:
            r = run_repeated(fn, paths, sync)
            print(f"  {name:22} {sync_name:8}: {r['mean_ms']:8.2f} мс  "
                  f"std {r['std_ms']:6.2f}  95% ДИ [{r['ci95_lo_ms']:.2f}; {r['ci95_hi_ms']:.2f}]")
            perf_rows.append({
                "metric": "scheme_comparison", "scheme": name, "write_mode": sync_name,
                "records": N, "warmup": WARMUP, "repeats": REPEATS,
                "mean_ms": r["mean_ms"], "std_ms": r["std_ms"],
                "ci95_lo_ms": r["ci95_lo_ms"], "ci95_hi_ms": r["ci95_hi_ms"], "note": "",
            })
    print()

    # =================================================================
    # 4. Входит ли время контрольных точек в замер? Изолированный замер.
    # =================================================================
    print("=" * 100)
    print("4. Контрольные точки внутри общего замера или нет - проверка изоляцией")
    print("=" * 100)
    print("По коду (cert_chain_hmac.py, cert_block_baseline.py): и записи, и внешний файл "
          "пишутся ВНУТРИ одного вызова (один 'with open(...) as f, open(...) as a:'), поэтому "
          "время контрольных точек УЖЕ включено в замер выше. Ниже - оценка ИХ ДОЛИ отдельно.\n")

    def hmac_records_only():
        prev = ch.GENESIS
        with open(P_HLOG_ONLY, "w", newline="", encoding="utf-8") as f:
            w = csv.writer(f)
            w.writerow(chm.MAC_FIELDS)
            for r in rows:
                prev = chm.mac_of(r, prev, KEY)
                w.writerow([r[k] for k in ch.FIELDS] + [prev])

    def hmac_anchor_only():
        prev = ch.GENESIS
        with open(P_HANCH_ONLY, "w", newline="", encoding="utf-8") as a:
            wa = csv.writer(a)
            wa.writerow(["count", "mac"])
            for n, r in enumerate(rows, start=1):
                prev = chm.mac_of(r, prev, KEY)
                if n % chm.CHECKPOINT_EVERY == 0 or n == len(rows):
                    wa.writerow([n, prev])

    r_full = run_repeated(lambda: chm.write_hmac_chain(rows, P_HLOG, P_HANCH, KEY), [P_HLOG, P_HANCH], False)
    r_rec = run_repeated(hmac_records_only, [P_HLOG_ONLY], False)
    r_anch = run_repeated(hmac_anchor_only, [P_HANCH_ONLY], False)
    print(f"  HMAC поэлементная: полный замер {r_full['mean_ms']:.2f} мс = записи-без-точек "
          f"{r_rec['mean_ms']:.2f} мс + (пересчёт для точек, отдельно) {r_anch['mean_ms']:.2f} мс")
    print(f"  Доля, объяснимая контрольными точками (грубая оценка сверху, т.к. HMAC "
          f"пересчитывается дважды в отдельных прогонах): {max(0, r_full['mean_ms'] - r_rec['mean_ms']):.2f} мс "
          f"({100 * max(0, r_full['mean_ms'] - r_rec['mean_ms']) / r_full['mean_ms']:.1f}%)")
    perf_rows.append({"metric": "checkpoint_time_isolated", "scheme": "HMAC поэлементная",
                       "write_mode": "только записи (без внеш. файла)", "records": N,
                       "warmup": WARMUP, "repeats": REPEATS, "mean_ms": r_rec["mean_ms"],
                       "std_ms": r_rec["std_ms"], "ci95_lo_ms": r_rec["ci95_lo_ms"],
                       "ci95_hi_ms": r_rec["ci95_hi_ms"],
                       "note": "контрольные точки НЕ пишутся вовсе"})
    perf_rows.append({"metric": "checkpoint_time_isolated", "scheme": "HMAC поэлементная",
                       "write_mode": "только внешний файл (точки)", "records": N,
                       "warmup": WARMUP, "repeats": REPEATS, "mean_ms": r_anch["mean_ms"],
                       "std_ms": r_anch["std_ms"], "ci95_lo_ms": r_anch["ci95_lo_ms"],
                       "ci95_hi_ms": r_anch["ci95_hi_ms"],
                       "note": "HMAC пересчитывается (нужен для точек), сама запись журнала - нет"})

    def block_records_only():
        with open(P_BLOG_ONLY, "w", newline="", encoding="utf-8") as f:
            w = csv.writer(f)
            w.writerow(ch.FIELDS)
            for r in rows:
                w.writerow([r[k] for k in ch.FIELDS])

    def block_tags_only():
        prev = ch.GENESIS
        h = hmac.new(KEY, prev.encode("utf-8"), hashlib.sha256)
        in_block = count = idx = 0
        with open(P_BTAGS_ONLY, "w", newline="", encoding="utf-8") as t:
            wt = csv.writer(t)
            wt.writerow(["block", "count", "tag"])
            for r in rows:
                h.update(ch.record_to_text(r).encode("utf-8") + b"\n")
                in_block += 1
                count += 1
                if in_block == BLOCK:
                    prev = h.hexdigest()
                    idx += 1
                    wt.writerow([idx, count, prev])
                    h = hmac.new(KEY, prev.encode("utf-8"), hashlib.sha256)
                    in_block = 0
            if in_block:
                idx += 1
                wt.writerow([idx, count, h.hexdigest()])

    r_bfull = run_repeated(lambda: bb.write_block_hmac(rows, P_BLOG, P_BTAGS, KEY, BLOCK), [P_BLOG, P_BTAGS], False)
    r_brec = run_repeated(block_records_only, [P_BLOG_ONLY], False)
    r_btag = run_repeated(block_tags_only, [P_BTAGS_ONLY], False)
    print(f"  Блочная HMAC: полный замер {r_bfull['mean_ms']:.2f} мс = записи-без-меток "
          f"{r_brec['mean_ms']:.2f} мс + (пересчёт для меток, отдельно) {r_btag['mean_ms']:.2f} мс")
    print(f"  Доля, объяснимая метками блоков: "
          f"{max(0, r_bfull['mean_ms'] - r_brec['mean_ms']):.2f} мс "
          f"({100 * max(0, r_bfull['mean_ms'] - r_brec['mean_ms']) / r_bfull['mean_ms']:.1f}%)\n")
    perf_rows.append({"metric": "checkpoint_time_isolated", "scheme": "блочная HMAC B=1000",
                       "write_mode": "только записи (без внеш. файла)", "records": N,
                       "warmup": WARMUP, "repeats": REPEATS, "mean_ms": r_brec["mean_ms"],
                       "std_ms": r_brec["std_ms"], "ci95_lo_ms": r_brec["ci95_lo_ms"],
                       "ci95_hi_ms": r_brec["ci95_hi_ms"],
                       "note": "метки блоков НЕ пишутся вовсе"})
    perf_rows.append({"metric": "checkpoint_time_isolated", "scheme": "блочная HMAC B=1000",
                       "write_mode": "только внешний файл (метки)", "records": N,
                       "warmup": WARMUP, "repeats": REPEATS, "mean_ms": r_btag["mean_ms"],
                       "std_ms": r_btag["std_ms"], "ci95_lo_ms": r_btag["ci95_lo_ms"],
                       "ci95_hi_ms": r_btag["ci95_hi_ms"],
                       "note": "HMAC блоков считается (нужен для меток), запись самих строк - нет"})

    fields = ["metric", "scheme", "write_mode", "records", "warmup", "repeats",
              "mean_ms", "std_ms", "ci95_lo_ms", "ci95_hi_ms", "note"]
    with open(PERF_CSV, "w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=fields)
        w.writeheader()
        w.writerows(perf_rows)
    print(f"Таблица времени сохранена: {PERF_CSV}\n")

    # =================================================================
    # 2 + 5. Хранение тегов hex/бинарно + разбивка объёма на части
    # =================================================================
    print("=" * 100)
    print("2+5. Хранение тегов (hex/бинарно) и разбивка объёма по частям")
    print("=" * 100)

    storage_rows = []

    def add_storage(scheme, tag_encoding, records_b, tags_b, block_meta_b, checkpoints_b, total_actual, note=""):
        computed = records_b + tags_b + block_meta_b + checkpoints_b
        storage_rows.append({
            "scheme": scheme, "tag_encoding": tag_encoding, "records": N,
            "records_bytes": records_b, "tags_bytes": tags_b,
            "block_metadata_bytes": block_meta_b, "checkpoints_bytes": checkpoints_b,
            "total_bytes_computed": computed, "total_bytes_actual": total_actual,
            "matches": computed == total_actual, "note": note,
        })
        print(f"  {scheme:22} ({tag_encoding:7}): записи {records_b:>9}  теги {tags_b:>9}  "
              f"метаданные блоков {block_meta_b:>7}  точки {checkpoints_b:>7}  "
              f"итого (расчёт={computed}, факт={total_actual}, "
              f"{'совпало' if computed == total_actual else 'РАСХОЖДЕНИЕ'})")

    # Все размеры ниже - ТОЧНЫЕ (разность реальных файлов на диске), не оценка по формуле.

    # обычный журнал - точка отсчёта для "чистых записей"
    ch.write_plain(rows, P_PLAIN)
    plain_bytes = os.path.getsize(P_PLAIN)
    add_storage("обычный журнал", "-", plain_bytes, 0, 0, 0, plain_bytes)

    # SHA-256 цепочка: записи + 2 hex-хеша (prev_hash, entry_hash). tags_bytes = точная
    # разница между файлом цепочки и обычным журналом (та же построчная структура,
    # отличаются только добавленными полями).
    ch.write_chained(rows, P_SHA)
    sha_bytes = os.path.getsize(P_SHA)
    sha_tags_exact = sha_bytes - plain_bytes
    add_storage("SHA-256 цепочка", "hex", plain_bytes, sha_tags_exact, 0, 0, sha_bytes,
                "tags_bytes = точная разность файлов (sha_bytes - plain_bytes), не формула")

    # HMAC поэлементная, hex (как сейчас): аналогично, точная разница за счёт добавленной
    # колонки mac; контрольные точки - отдельный файл, размер известен точно.
    chm.write_hmac_chain(rows, P_HLOG, P_HANCH, KEY)
    hlog_bytes, hanch_bytes = os.path.getsize(P_HLOG), os.path.getsize(P_HANCH)
    hmac_tags_exact = hlog_bytes - plain_bytes
    add_storage("HMAC поэлементная", "hex", plain_bytes, hmac_tags_exact, 0, hanch_bytes,
                hlog_bytes + hanch_bytes,
                "tags_bytes = точная разность файлов (hlog_bytes - plain_bytes)")

    # HMAC поэлементная, бинарные теги (новый вариант, только для сравнения): записи и
    # теги физически в разных файлах, оба размера измерены напрямую (не разность, не оценка).
    write_hmac_chain_binary_tags(rows, P_HLOG_BIN_REC, P_HLOG_BIN_TAGS, KEY)
    rec_bin_bytes = os.path.getsize(P_HLOG_BIN_REC)
    tags_bin_bytes = os.path.getsize(P_HLOG_BIN_TAGS)
    add_storage("HMAC поэлементная", "бинарно", rec_bin_bytes, tags_bin_bytes, 0, hanch_bytes,
                rec_bin_bytes + tags_bin_bytes + hanch_bytes,
                "точки (checkpoints) оставлены hex для этого сравнения - меняются только теги записей; "
                f"записи без тегов = {rec_bin_bytes} Б (сверка: обычный журнал = {plain_bytes} Б)")

    # Блочная HMAC, hex: записи (файл БЕЗ тегов вообще, формат идентичен обычному журналу) +
    # метаданные блока (номер, count) + сам тег - метаданные и тег разделены точным
    # вычитанием (файл меток без колонки tag, реально записанный и измеренный).
    bb.write_block_hmac(rows, P_BLOG, P_BTAGS, KEY, BLOCK)
    blog_bytes, btags_bytes = os.path.getsize(P_BLOG), os.path.getsize(P_BTAGS)
    n_blocks = -(-N // BLOCK)
    block_meta_exact = strip_tag_column_size(P_BTAGS)
    block_tag_hex_exact = btags_bytes - block_meta_exact
    add_storage("блочная HMAC B=1000", "hex", blog_bytes, block_tag_hex_exact, block_meta_exact, 0,
                blog_bytes + btags_bytes,
                f"{n_blocks} блоков на {N} записей - тегов на 3 порядка меньше, чем у поэлементной; "
                f"записи блочной схемы = {blog_bytes} Б (сверка: обычный журнал = {plain_bytes} Б)")

    # Блочная HMAC, бинарные метки блоков: формат struct('>II')+32 байта известен точно,
    # поэтому метаданные/тег разделены без вычитания - по факту упаковки.
    write_block_tags_binary(P_BTAGS, P_BTAGS_BIN)
    btags_bin_bytes = os.path.getsize(P_BTAGS_BIN)
    block_tag_bin = n_blocks * 32
    block_meta_bin = btags_bin_bytes - block_tag_bin
    add_storage("блочная HMAC B=1000", "бинарно", blog_bytes, block_tag_bin, block_meta_bin, 0,
                blog_bytes + btags_bin_bytes,
                "номер блока и count упакованы как 4+4 байта (struct '>II') вместо текста")

    with open(STORAGE_CSV, "w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=list(storage_rows[0].keys()))
        w.writeheader()
        w.writerows(storage_rows)
    print(f"\nТаблица объёма сохранена: {STORAGE_CSV}")

    # =================================================================
    # 6. Характеристики машины (для справки, сверено PowerShell перед запуском)
    # =================================================================
    print("\n6. Характеристики машины:")
    print(f"   Процессор: AMD Ryzen 7 250 (mobile, Zen 4), 8 ядер / 16 потоков (Get-CimInstance Win32_Processor)")
    print(f"   ОЗУ: 23.3 ГБ (24 995 295 232 байт, Get-CimInstance Win32_ComputerSystem)")
    print(f"   Диск: SSD (SAMSUNG MZVMX1T0HCLD, Get-PhysicalDisk MediaType)")
    print(f"   ОС: {platform.platform()}")
    print(f"   Python: {sys.version.split()[0]}")

    for p in (P_PLAIN, P_SHA, P_HLOG, P_HANCH, P_BLOG, P_BTAGS, P_HLOG_ONLY, P_HANCH_ONLY,
              P_BLOG_ONLY, P_BTAGS_ONLY, P_HLOG_BIN_REC, P_HLOG_BIN_TAGS, P_BTAGS_BIN):
        if os.path.exists(p):
            os.remove(p)


if __name__ == "__main__":
    main()
