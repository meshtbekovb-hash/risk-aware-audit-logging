"""
ЗАДАЧА 6 REVISION_PLAN.md: РАСШИРЕННЫЕ АТАКИ НА ЖУРНАЛ

К семи прежним атакам (cert_chain_hmac.py) добавляются девять новых, прогнанных на
всех трёх схемах: простая SHA-256 цепочка (cert_chain.py), поэлементная HMAC-цепочка
с контрольными точками (cert_chain_hmac.py), блочная HMAC-схема B=1000
(cert_block_baseline.py). Журнал - тот же device.csv, 10 000 записей (плюс отдельные
1000 записей "другого журнала" для атаки 5).

КЛЮЧЕВАЯ ИДЕЯ ПРОВЕРКИ (одна и та же для всех девяти атак): у нарушителя может быть
или не быть секретный ключ.
  - БЕЗ ключа он не может вычислить новый верный тег ни для одной записи/блока -
    может только переставлять, удалять, копировать УЖЕ подписанные куски журнала как
    есть, не трогая их теги. Проверяется: ломается ли цепочка/блок сразу же в точке
    вмешательства (без ключа это первое, что видно).
  - С КЛЮЧОМ (украден - наш худший случай, раздел 4.4) нарушитель может пересчитать
    журнал заново с любого места. Простая SHA-256 цепочка ключа не использует вообще,
    поэтому для неё "с ключом" и "без ключа" - одно и то же: пересчитать может
    ЛЮБОЙ, у кого есть право записи. У HMAC-схем при пересчитанном журнале
    внутренняя цепочка снова целая - единственное, что может её выдать, это ВНЕШНЯЯ
    контрольная точка/метка блока, которую нарушитель не контролирует (вынесена из
    журнала). Проверяется: пересчитанный нарушителем журнал сверяется с ПОДЛИННЫМИ
    (не тронутыми) внешними точками исходного прогона.

Результат: results_revision/tamper_extended.csv
Запуск (из папки с device.csv):  python cert_tamper_extended.py
"""

import csv
import hashlib
import hmac
import os

import cert_chain as ch
import cert_chain_hmac as chm
import cert_block_baseline as bb

OUTPUT_FILE = "results_revision/tamper_extended.csv"
N = 10000                      # записей в основном журнале
BLOCK = 1000
TMP = ch.TMP_DIR
LOG = os.path.join(TMP, "te_log.csv")
ANCH = os.path.join(TMP, "te_anchor.csv")
LOG2 = os.path.join(TMP, "te_log2.csv")
ANCH2 = os.path.join(TMP, "te_anchor2.csv")
SHA_PATH = os.path.join(TMP, "te_sha.csv")
BLOG = os.path.join(TMP, "te_blog.csv")
BTAGS = os.path.join(TMP, "te_btags.csv")
BLOG2 = os.path.join(TMP, "te_blog2.csv")
BTAGS2 = os.path.join(TMP, "te_btags2.csv")
# ВЫБРОСНЫЕ пути для тестов "с ключом": нарушитель пишет свой пересчитанный журнал СЮДА,
# а не поверх настоящей точки (ANCH/BTAGS) - иначе проверка сравнивала бы подделку саму
# с собой и всегда бы "проходила". Настоящая точка ANCH/BTAGS перед каждым таким тестом
# восстанавливается заново из подлинных rows функциями refresh_true_anchor()/refresh_true_tags().
ATTACKER_ANCH = os.path.join(TMP, "te_attacker_anchor.csv")
ATTACKER_BTAGS = os.path.join(TMP, "te_attacker_btags.csv")
THROWAWAY_LOG = os.path.join(TMP, "te_throwaway_log.csv")


# ---------------------------------------------------------------
# Обёртки над тремя схемами - без изменения их кода, только вызовы
# ---------------------------------------------------------------
def sha_write(rows, path=SHA_PATH):
    ch.write_chained(rows, path)
    return path


def sha_verify(path=SHA_PATH):
    ok, where = ch.verify_chain(path)
    return (not ok), (f"запись № {where}" if where else "-")   # (detected, где)


def hmac_write(rows, log=LOG, anchor=ANCH, key=chm.KEY):
    chm.write_hmac_chain(rows, log, anchor, key)


def hmac_verify(log=LOG, anchor=ANCH, key=chm.KEY):
    ok, why = chm.verify_hmac_chain(log, anchor, key)
    return (not ok), (why if why else "-")


def hmac_verify_all(log, anchor, key=chm.KEY):
    """Диагностика для атаки 7 (несколько подмен сразу): в отличие от chm.verify_hmac_chain
    (останавливается на первой ошибке), проходит журнал ДО КОНЦА и собирает ВСЕ записи,
    не совпавшие с ожидаемой меткой, чтобы честно ответить, сколько из подмен обнаружены
    за один проход. Сама схема (chm.py) не меняется - это только диагностика для отчёта."""
    anchors = chm.read_anchors(anchor)
    bad = []
    prev = ch.GENESIS
    with open(log, encoding="utf-8") as f:
        for n, row in enumerate(csv.DictReader(f), start=1):
            expected = chm.mac_of(row, prev, key)
            if not hmac.compare_digest(expected, row["mac"]):
                bad.append(n)
                prev = row["mac"]          # идём дальше от факта, как есть в файле, чтобы не потерять след
            else:
                prev = row["mac"]
            if n in anchors and anchors[n] != prev and n not in bad:
                bad.append(n)
    return bad


def block_write(rows, log=BLOG, tags=BTAGS, key=chm.KEY, block=BLOCK):
    bb.write_block_hmac(rows, log, tags, key, block)


def block_verify(log=BLOG, tags=BTAGS, key=chm.KEY, block=BLOCK):
    ok, why = bb.verify_block(log, tags, key, block)
    return (not ok), (why if why else "-")


def refresh_true_anchor(rows):
    """Восстанавливает ПОДЛИННУЮ контрольную точку ANCH из настоящих rows (журнал пишем в
    выбрасываемый файл - для этого шага важна только точка)."""
    chm.write_hmac_chain(rows, THROWAWAY_LOG, ANCH, chm.KEY)


def refresh_true_tags(rows):
    """То же для блочной схемы: восстанавливает подлинные метки блоков BTAGS."""
    bb.write_block_hmac(rows, THROWAWAY_LOG, BTAGS, chm.KEY, BLOCK)


def hmac_write_attacker(rows, log=LOG, key=chm.KEY):
    """Нарушитель пересчитывает журнал с ключом: пишет журнал в log, а СВОЮ точку - в
    выбрасываемый ATTACKER_ANCH (не в ANCH, чтобы не подменить подлинную)."""
    chm.write_hmac_chain(rows, log, ATTACKER_ANCH, key)


def block_write_attacker(rows, log=BLOG, key=chm.KEY, block=BLOCK):
    bb.write_block_hmac(rows, log, ATTACKER_BTAGS, key, block)


def cleanup():
    for p in (LOG, ANCH, LOG2, ANCH2, SHA_PATH, BLOG, BTAGS, BLOG2, BTAGS2,
              ATTACKER_ANCH, ATTACKER_BTAGS, THROWAWAY_LOG):
        if os.path.exists(p):
            os.remove(p)


# ---------------------------------------------------------------
# Загрузка и базовые (нетронутые) прогоны
# ---------------------------------------------------------------
def main():
    print("Загрузка device.csv (11 500 записей: 10 000 основной журнал + 1 000 'другой журнал')...")
    rows_all = ch.load_rows(ch.DEVICE_FILE, 11500)
    rows = rows_all[:N]
    rows_b = rows_all[N:N + 1000]         # "другой журнал", тот же ключ, своя цепочка с нуля

    # подлинные (нетронутые) версии - эталон, с которым сверяется всё дальше
    sha_write(rows)
    hmac_write(rows)
    block_write(rows)
    hmac_write(rows_b, LOG2, ANCH2)       # "другой журнал" сам по себе
    block_write(rows_b, BLOG2, BTAGS2)
    print("Базовые прогоны построены (3 схемы на основном журнале + HMAC/блочная на 'другом').\n")

    results = []

    def record(attack_id, attack_name, key_assump, scheme, detected, where, note=""):
        results.append({"attack_id": attack_id, "attack_name": attack_name,
                         "key_assumption": key_assump, "scheme": scheme,
                         "detected": detected, "where": where, "note": note})
        mark = "ОБНАРУЖЕНА" if detected else "ПРОПУЩЕНА"
        print(f"  [{attack_id}] {scheme:28} ({key_assump:12}) -> {mark:10} {where}")

    # =================================================================
    # 1. Вставка новой записи в середину
    # =================================================================
    print("1. Вставка новой записи в середину (позиция 5000)")
    fake_row = dict(rows[5000])
    fake_row["id"] = "{FAKE-INSERTED-RECORD}"
    rows_ins = rows[:5000] + [fake_row] + rows[5000:]

    def insert_naive_row(path, fieldnames, tag_fields, pos, new_row):
        """Вставляет новую строку в позицию pos (после заголовка) через csv-модуль (без ручной
        склейки строк - безопасно к запятым/кавычкам). Поля тегов (tag_fields) нарушитель без
        ключа заполнить не может - копирует значения соседней (уже подписанной) записи."""
        with open(path, encoding="utf-8", newline="") as f:
            all_rows = list(csv.reader(f))
        header, body = all_rows[0], all_rows[1:]
        neighbor = body[pos]                                 # сосед, у которого "занимаем" тег
        new_line = [new_row.get(c, neighbor[header.index(c)] if c in tag_fields else "")
                    for c in header]
        body.insert(pos + 1, new_line)
        with open(path, "w", newline="", encoding="utf-8") as f:
            w_ = csv.writer(f)
            w_.writerow(header)
            w_.writerows(body)

    # без ключа: физически вставляем строку в УЖЕ подписанный файл; поля тегов нарушитель
    # без ключа вычислить не может - копирует их у соседней записи (единственное, что под рукой)
    sha_write(rows, SHA_PATH)
    insert_naive_row(SHA_PATH, ch.FIELDS + ["prev_hash", "entry_hash"], ["prev_hash", "entry_hash"],
                      5000, fake_row)
    d, w = sha_verify()
    record("1", "вставка записи", "без ключа", "SHA-256 цепочка", d, w)

    hmac_write(rows, LOG)
    insert_naive_row(LOG, chm.MAC_FIELDS, ["mac"], 5000, fake_row)
    d, w = hmac_verify(LOG, ANCH)
    record("1", "вставка записи", "без ключа", "HMAC поэлементная", d, w)

    block_write(rows, BLOG)
    insert_naive_row(BLOG, ch.FIELDS, [], 5000, fake_row)
    d, w = block_verify(BLOG, BTAGS)
    record("1", "вставка записи", "без ключа", "блочная HMAC B=1000", d, w)

    # с ключом: нарушитель пересобирает журнал заново поверх 10001 строки и сверяется
    # с ПОДЛИННЫМИ внешними точками исходного (10000-строчного) прогона
    sha_write(rows_ins, SHA_PATH)               # то же самое: пересчёт без ключа не нужен вообще
    d, w = sha_verify()
    record("1", "вставка записи", "с ключом*", "SHA-256 цепочка", d, w,
           "*ключа нет вообще - пересчёт доступен любому с правом записи")

    refresh_true_anchor(rows)                     # восстановить подлинную точку перед тестом
    hmac_write_attacker(rows_ins, LOG)             # нарушитель пересчитывает с ключом, точка своя (выброс)
    d, w = hmac_verify(LOG, ANCH)                 # сверка с ПОДЛИННЫМИ точками (не тронуты)
    record("1", "вставка записи", "с ключом", "HMAC поэлементная", d, w)

    refresh_true_tags(rows)
    block_write_attacker(rows_ins, BLOG)
    d, w = block_verify(BLOG, BTAGS)
    record("1", "вставка записи", "с ключом", "блочная HMAC B=1000", d, w)
    print()

    # =================================================================
    # 2. Удаление целого блока (блок 5: записи 4001..5000)
    # =================================================================
    print("2. Удаление целого блока (блок 5, записи 4001..5000)")
    rows_del = rows[:4000] + rows[5000:]

    sha_write(rows, SHA_PATH)
    lines = ch.read_lines(SHA_PATH)
    ch.write_lines(SHA_PATH, lines[:4001] + lines[5001:])
    d, w = sha_verify()
    record("2", "удаление блока", "без ключа", "SHA-256 цепочка", d, w)

    hmac_write(rows, LOG)
    lines = ch.read_lines(LOG)
    ch.write_lines(LOG, lines[:4001] + lines[5001:])
    d, w = hmac_verify(LOG, ANCH)
    record("2", "удаление блока", "без ключа", "HMAC поэлементная", d, w)

    block_write(rows, BLOG)
    lines = ch.read_lines(BLOG)
    ch.write_lines(BLOG, lines[:4001] + lines[5001:])
    d, w = block_verify(BLOG, BTAGS)
    record("2", "удаление блока", "без ключа", "блочная HMAC B=1000", d, w)

    sha_write(rows_del, SHA_PATH)
    d, w = sha_verify()
    record("2", "удаление блока", "с ключом*", "SHA-256 цепочка", d, w,
           "*ключа нет вообще")

    refresh_true_anchor(rows)
    hmac_write_attacker(rows_del, LOG)
    d, w = hmac_verify(LOG, ANCH)
    record("2", "удаление блока", "с ключом", "HMAC поэлементная", d, w)

    refresh_true_tags(rows)
    block_write_attacker(rows_del, BLOG)
    d, w = block_verify(BLOG, BTAGS)
    record("2", "удаление блока", "с ключом", "блочная HMAC B=1000", d, w)
    print()

    # =================================================================
    # 3. Перестановка двух целых блоков (блок 3 <-> блок 7)
    # =================================================================
    print("3. Перестановка блоков 3 (2001..3000) и 7 (6001..7000)")
    b3, b7 = rows[2000:3000], rows[6000:7000]
    rows_swap = rows[:2000] + b7 + rows[3000:6000] + b3 + rows[7000:]

    sha_write(rows, SHA_PATH)
    lines = ch.read_lines(SHA_PATH)
    new_lines = lines[:2001] + lines[6001:7001] + lines[3001:6001] + lines[2001:3001] + lines[7001:]
    ch.write_lines(SHA_PATH, new_lines)
    d, w = sha_verify()
    record("3", "перестановка блоков", "без ключа", "SHA-256 цепочка", d, w)

    hmac_write(rows, LOG)
    lines = ch.read_lines(LOG)
    new_lines = lines[:2001] + lines[6001:7001] + lines[3001:6001] + lines[2001:3001] + lines[7001:]
    ch.write_lines(LOG, new_lines)
    d, w = hmac_verify(LOG, ANCH)
    record("3", "перестановка блоков", "без ключа", "HMAC поэлементная", d, w)

    block_write(rows, BLOG)
    lines = ch.read_lines(BLOG)
    new_lines = lines[:2001] + lines[6001:7001] + lines[3001:6001] + lines[2001:3001] + lines[7001:]
    ch.write_lines(BLOG, new_lines)
    d, w = block_verify(BLOG, BTAGS)
    record("3", "перестановка блоков", "без ключа", "блочная HMAC B=1000", d, w)

    sha_write(rows_swap, SHA_PATH)
    d, w = sha_verify()
    record("3", "перестановка блоков", "с ключом*", "SHA-256 цепочка", d, w, "*ключа нет вообще")

    refresh_true_anchor(rows)
    hmac_write_attacker(rows_swap, LOG)
    d, w = hmac_verify(LOG, ANCH)
    record("3", "перестановка блоков", "с ключом", "HMAC поэлементная", d, w)

    refresh_true_tags(rows)
    block_write_attacker(rows_swap, BLOG)
    d, w = block_verify(BLOG, BTAGS)
    record("3", "перестановка блоков", "с ключом", "блочная HMAC B=1000", d, w)
    print()

    # =================================================================
    # 4. Повтор старого блока вместо текущего (replay): блок 2 вместо блока 9
    # =================================================================
    print("4. Replay: содержимое блока 2 (1001..2000) подставлено вместо блока 9 (8001..9000)")
    b2 = rows[1000:2000]
    rows_replay = rows[:8000] + b2 + rows[9000:]

    sha_write(rows, SHA_PATH)
    lines = ch.read_lines(SHA_PATH)
    new_lines = lines[:8001] + lines[1001:2001] + lines[9001:]
    ch.write_lines(SHA_PATH, new_lines)
    d, w = sha_verify()
    record("4", "replay блока", "без ключа", "SHA-256 цепочка", d, w)

    hmac_write(rows, LOG)
    lines = ch.read_lines(LOG)
    new_lines = lines[:8001] + lines[1001:2001] + lines[9001:]
    ch.write_lines(LOG, new_lines)
    d, w = hmac_verify(LOG, ANCH)
    record("4", "replay блока", "без ключа", "HMAC поэлементная", d, w)

    block_write(rows, BLOG)
    lines = ch.read_lines(BLOG)
    new_lines = lines[:8001] + lines[1001:2001] + lines[9001:]
    ch.write_lines(BLOG, new_lines)
    d, w = block_verify(BLOG, BTAGS)
    record("4", "replay блока", "без ключа", "блочная HMAC B=1000", d, w)

    sha_write(rows_replay, SHA_PATH)
    d, w = sha_verify()
    record("4", "replay блока", "с ключом*", "SHA-256 цепочка", d, w, "*ключа нет вообще")

    refresh_true_anchor(rows)
    hmac_write_attacker(rows_replay, LOG)
    d, w = hmac_verify(LOG, ANCH)
    record("4", "replay блока", "с ключом", "HMAC поэлементная", d, w)

    refresh_true_tags(rows)
    block_write_attacker(rows_replay, BLOG)
    d, w = block_verify(BLOG, BTAGS)
    record("4", "replay блока", "с ключом", "блочная HMAC B=1000", d, w)
    print()

    # =================================================================
    # 5. Подмена блока блоком из ДРУГОГО журнала, подписанного тем же ключом
    # =================================================================
    print("5. Подмена блока 9 блоком из другого журнала (rows_b, 1000 записей, тот же ключ)")
    rows_cross = rows[:8000] + rows_b + rows[9000:]

    hmac_write(rows, LOG)      # журнал A заново (после прошлых атак файл перезаписан)
    lines_a = ch.read_lines(LOG)
    lines_b = ch.read_lines(LOG2)                   # уже посчитан выше (своя цепочка с нуля)
    new_lines = lines_a[:8001] + lines_b[1:1001] + lines_a[9001:]
    ch.write_lines(LOG, new_lines)
    d, w = hmac_verify(LOG, ANCH)
    record("5", "блок из другого журнала", "без ключа", "HMAC поэлементная", d, w)

    block_write(rows, BLOG)
    lines_a = ch.read_lines(BLOG)
    lines_b = ch.read_lines(BLOG2)
    new_lines = lines_a[:8001] + lines_b[1:1001] + lines_a[9001:]
    ch.write_lines(BLOG, new_lines)
    d, w = block_verify(BLOG, BTAGS)
    record("5", "блок из другого журнала", "без ключа", "блочная HMAC B=1000", d, w)

    sha_write(rows_cross, SHA_PATH)   # SHA: ключа нет, пересчёт тривиален для любого содержимого
    d, w = sha_verify()
    record("5", "блок из другого журнала", "с ключом*", "SHA-256 цепочка", d, w, "*ключа нет вообще")

    refresh_true_anchor(rows)
    hmac_write_attacker(rows_cross, LOG)           # с ключом: пересчитать весь журнал A поверх чужого блока
    d, w = hmac_verify(LOG, ANCH)
    record("5", "блок из другого журнала", "с ключом", "HMAC поэлементная", d, w)

    refresh_true_tags(rows)
    block_write_attacker(rows_cross, BLOG)
    d, w = block_verify(BLOG, BTAGS)
    record("5", "блок из другого журнала", "с ключом", "блочная HMAC B=1000", d, w)
    print()

    # =================================================================
    # 6. Изменение только временной метки записи (запись 5000)
    # =================================================================
    print("6. Изменение только даты записи № 5000 (остальные поля не трогаем)")

    def bump_date(row):
        r = dict(row)
        d_, t_ = r["date"].split(" ")
        r["date"] = d_ + " 23:59:59" if t_ != "23:59:59" else d_ + " 00:00:01"
        return r

    rows_ts = list(rows)
    rows_ts[4999] = bump_date(rows[4999])

    def patch_date_naive(path, pos, new_date):
        """Меняет только поле date записи № pos+1 (csv-модулем, теги/остальные поля не трогает)."""
        with open(path, encoding="utf-8", newline="") as f:
            all_rows = list(csv.reader(f))
        header = all_rows[0]
        all_rows[pos + 1][header.index("date")] = new_date
        with open(path, "w", newline="", encoding="utf-8") as f:
            csv.writer(f).writerows(all_rows)

    new_date = bump_date(rows[4999])["date"]

    sha_write(rows, SHA_PATH)
    patch_date_naive(SHA_PATH, 4999, new_date)
    d, w = sha_verify()
    record("6", "изменена только дата", "без ключа", "SHA-256 цепочка", d, w)

    hmac_write(rows, LOG)
    patch_date_naive(LOG, 4999, new_date)
    d, w = hmac_verify(LOG, ANCH)
    record("6", "изменена только дата", "без ключа", "HMAC поэлементная", d, w)

    block_write(rows, BLOG)
    patch_date_naive(BLOG, 4999, new_date)
    d, w = block_verify(BLOG, BTAGS)
    record("6", "изменена только дата", "без ключа", "блочная HMAC B=1000", d, w)

    sha_write(rows_ts, SHA_PATH)
    d, w = sha_verify()
    record("6", "изменена только дата", "с ключом*", "SHA-256 цепочка", d, w, "*ключа нет вообще")

    refresh_true_anchor(rows)
    hmac_write_attacker(rows_ts, LOG)
    d, w = hmac_verify(LOG, ANCH)
    record("6", "изменена только дата", "с ключом", "HMAC поэлементная", d, w)

    refresh_true_tags(rows)
    block_write_attacker(rows_ts, BLOG)
    d, w = block_verify(BLOG, BTAGS)
    record("6", "изменена только дата", "с ключом", "блочная HMAC B=1000", d, w)
    print()

    # =================================================================
    # 7. Одновременное изменение нескольких записей в разных блоках (1500, 4500, 8500)
    # =================================================================
    print("7. Одновременно изменены записи № 1500 (блок 2), 4500 (блок 5), 8500 (блок 9)")
    targets7 = [1500, 4500, 8500]

    def flip(row):
        r = dict(row)
        r["activity"] = "Disconnect" if r["activity"] == "Connect" else "Connect"
        return r

    rows_multi = list(rows)
    for t in targets7:
        rows_multi[t - 1] = flip(rows[t - 1])

    hmac_write(rows, LOG)
    lines = ch.read_lines(LOG)
    for t in targets7:
        lines[t] = lines[t].replace("Connect", "Disconnect", 1) if "Disconnect" not in lines[t] \
            else lines[t].replace("Disconnect", "Connect", 1)
    ch.write_lines(LOG, lines)
    bad = hmac_verify_all(LOG, ANCH)
    d = bool(bad)
    record("7", "3 подмены в разных блоках (без пересчёта)", "без ключа", "HMAC поэлементная", d,
           f"записи № {bad}", note=f"продолженная проверка (не останавливается на первой ошибке): "
           f"из 3 подмен обнаружено {len(bad)}")

    block_write(rows, BLOG)
    lines = ch.read_lines(BLOG)
    for t in targets7:
        lines[t] = lines[t].replace("Connect", "Disconnect", 1) if "Disconnect" not in lines[t] \
            else lines[t].replace("Disconnect", "Connect", 1)
    ch.write_lines(BLOG, lines)
    # Блочная схема: verify_block тоже останавливается на первом расхождении. Чтобы честно
    # проверить все 3 подмены за один проход, продолжаем счёт от ВНЕШНЕГО (эталонного) тега
    # блока, а не от пересчитанного - иначе одна испорченная запись в блоке 2 "заражает" цепочку
    # состояний для ВСЕХ блоков после неё (каждый следующий блок стартует от чужого prev и тоже
    # не совпадёт с эталоном), и отчёт покажет 9 плохих блоков вместо реальных 3. Продолжение от
    # эталона - это ровно то, что сделал бы аналитик: зафиксировал факт "блок X испорчен",
    # доверился внешнему хранилищу для этого блока и пошёл искать дальше.
    bb_blocks_bad = []
    tags = {b: (c, tag) for b, c, tag in bb.read_tags(BTAGS)}
    prev, h, in_block, count, idx = ch.GENESIS, None, 0, 0, 0
    h = hmac.new(chm.KEY, prev.encode("utf-8"), hashlib.sha256)
    with open(BLOG, encoding="utf-8") as f:
        for row in csv.DictReader(f):
            h.update(ch.record_to_text(row).encode("utf-8") + b"\n")
            in_block += 1
            count += 1
            if in_block == BLOCK:
                idx += 1
                tag = h.hexdigest()
                if idx in tags and tags[idx][1] != tag:
                    bb_blocks_bad.append(idx)
                prev = tags[idx][1] if idx in tags else tag   # эталон, не пересчитанное значение
                h = hmac.new(chm.KEY, prev.encode("utf-8"), hashlib.sha256)
                in_block = 0
    d = bool(bb_blocks_bad)
    record("7", "3 подмены в разных блоках (без пересчёта)", "без ключа", "блочная HMAC B=1000", d,
           f"блоки {bb_blocks_bad}", note=f"продолженная проверка (от эталонного тега, не каскадом): "
           f"из 3 затронутых блоков (2,5,9) обнаружено {len(bb_blocks_bad)}")

    sha_write(rows, SHA_PATH)
    lines = ch.read_lines(SHA_PATH)
    for t in targets7:
        lines[t] = lines[t].replace("Connect", "Disconnect", 1) if "Disconnect" not in lines[t] \
            else lines[t].replace("Disconnect", "Connect", 1)
    ch.write_lines(SHA_PATH, lines)
    d, w = sha_verify()
    record("7", "3 подмены в разных блоках", "без ключа", "SHA-256 цепочка", d, w,
           "первая же подмена рвёт цепочку; verify_chain останавливается на первой ошибке")

    sha_write(rows_multi, SHA_PATH)
    d, w = sha_verify()
    record("7", "3 подмены в разных блоках", "с ключом*", "SHA-256 цепочка", d, w, "*ключа нет вообще")

    refresh_true_anchor(rows)
    hmac_write_attacker(rows_multi, LOG)
    d, w = hmac_verify(LOG, ANCH)
    record("7", "3 подмены в разных блоках", "с ключом", "HMAC поэлементная", d, w)

    refresh_true_tags(rows)
    block_write_attacker(rows_multi, BLOG)
    d, w = block_verify(BLOG, BTAGS)
    record("7", "3 подмены в разных блоках", "с ключом", "блочная HMAC B=1000", d, w)
    print()

    # =================================================================
    # 8. Порча контрольной точки (внешнее хранилище), журнал не трогаем
    # =================================================================
    print("8. Порча контрольной точки: искажена метка в внешнем хранилище на отметке 5000")
    hmac_write(rows, LOG)
    anchors = chm.read_anchors(ANCH)
    bad_tag = ("0" if anchors[5000][0] != "0" else "1") + anchors[5000][1:]
    with open(ANCH, "w", newline="", encoding="utf-8") as f:
        w_ = csv.writer(f)
        w_.writerow(["count", "mac"])
        for cnt in sorted(anchors):
            w_.writerow([cnt, bad_tag if cnt == 5000 else anchors[cnt]])
    d, w = hmac_verify(LOG, ANCH)
    record("8", "порча контрольной точки", "-", "HMAC поэлементная", d, w,
           "испорчена именно точка на отметке 5000 (не журнал)")

    block_write(rows, BLOG)
    tags = bb.read_tags(BTAGS)
    with open(BTAGS, "w", newline="", encoding="utf-8") as f:
        w_ = csv.writer(f)
        w_.writerow(["block", "count", "tag"])
        for b, c, tag in tags:
            bad = ("0" if tag[0] != "0" else "1") + tag[1:] if b == 5 else tag
            w_.writerow([b, c, bad])
    d, w = block_verify(BLOG, BTAGS)
    record("8", "порча контрольной точки", "-", "блочная HMAC B=1000", d, w,
           "испорчена метка блока № 5 во внешнем хранилище")

    record("8", "порча контрольной точки", "-", "SHA-256 цепочка", False, "н/п (нет контрольных точек)",
           "у простой цепочки нет внешнего хранилища вообще - атака неприменима")
    print()

    # =================================================================
    # 9. Откат: журнал и контрольная точка ВМЕСТЕ возвращаются к более раннему
    #    согласованному состоянию (нарушитель, по предположению, добрался и до
    #    внешнего хранилища - выход за пределы базовой модели угроз, раздел 4.4)
    # =================================================================
    print("9. Откат журнала + контрольной точки вместе к состоянию 'после 8000 записей'")
    rows_rb = rows[:8000]
    hmac_write(rows_rb, LOG2, ANCH2)             # честно пересобранная пара "откаченного" состояния
    d, w = hmac_verify(LOG2, ANCH2)
    record("9", "откат журнала+точки вместе", "ключ не нужен - только доступ к обеим частям",
           "HMAC поэлементная", d, w,
           "внутренне полностью согласованная пара - неотличима от 'журнал легитимно был короче'; "
           "граница схемы без монотонного счётчика во внешнем хранилище, не зависящего от самого файла")

    block_write(rows_rb, BLOG2, BTAGS2)
    d, w = block_verify(BLOG2, BTAGS2)
    record("9", "откат журнала+точки вместе", "ключ не нужен - только доступ к обеим частям",
           "блочная HMAC B=1000", d, w, "то же самое: согласованная более ранняя пара проходит")

    sha_write(rows_rb, SHA_PATH)
    d, w = sha_verify()
    record("9", "откат журнала+точки вместе", "ключа нет вообще", "SHA-256 цепочка", d, w,
           "у простой цепочки это то же самое, что обрезка хвоста (раздел 4.4, атака 3) - уже известная брешь")
    print()

    cleanup()

    fields = list(results[0].keys())
    with open(OUTPUT_FILE, "w", newline="", encoding="utf-8") as f:
        w_ = csv.DictWriter(f, fieldnames=fields)
        w_.writeheader()
        w_.writerows(results)
    print(f"Таблица сохранена: {OUTPUT_FILE} ({len(results)} строк)")


if __name__ == "__main__":
    main()
