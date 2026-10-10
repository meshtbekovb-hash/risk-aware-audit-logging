"""
ВОСПРОИЗВЕДЕНИЕ ДВУХ ОШИБОК, НАЙДЕННЫХ ВНЕШНЕЙ ПРОВЕРКОЙ (и проверка после исправления)

Скрипт ничего не исправляет сам: он запускает одни и те же сценарии против текущего кода
проверок. До исправления он должен показать «прошло», после исправления «обнаружено».

Ошибка 1. Неподписанное продолжение журнала. К подлинному журналу из 10 000 записей
дописываются 2000 записей без меток. Проверяются блочная схема и поэлементная HMAC-цепочка.
Дополнительно для цепочки: 2000 записей, дописанных С ПРАВИЛЬНЫМИ метками (нарушитель с
ключом), при завершённом журнале, у которого последняя внешняя точка стоит на записи 10 000.

Ошибка 2. Неоднозначная склейка полей. Запись с user="U", pc="P" заменяется записью с
user="U|<начало P>", pc="<конец P>": при склейке через "|" получается та же строка, значит,
тот же тег. Проверяются SHA-256 цепочка, HMAC-цепочка и блочная схема.

Результат: results_revision/bugfix_repro.csv (одна строка на сценарий, с меткой запуска)
Запуск:  python cert_bugfix_repro.py before   (или after)
"""

import csv
import os
import sys

import cert_chain as ch
import cert_chain_hmac as chm
import cert_block_baseline as bb

OUT = "results_revision/bugfix_repro.csv"
N, EXTRA, BLOCK = 10000, 2000, 1000
T = ch.TMP_DIR
LOG, ANCH = os.path.join(T, "rp_log.csv"), os.path.join(T, "rp_anch.csv")
BLOG, BTAGS = os.path.join(T, "rp_blog.csv"), os.path.join(T, "rp_btags.csv")
SHA = os.path.join(T, "rp_sha.csv")
JUNK = os.path.join(T, "rp_junk.csv")


def append_rows(path, rows, header, tail_values):
    """Дописывает строки в конец CSV-журнала. tail_values(row, i) даёт значения служебных
    колонок (метки) для каждой строки; для «без меток» возвращает пустые строки."""
    with open(path, "a", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        for i, r in enumerate(rows):
            w.writerow([r[k] for k in ch.FIELDS] + tail_values(r, i))


def run_check(fn, *args):
    """Вызывает проверку и превращает любой результат (в том числе падение) в текст."""
    try:
        ok, why = fn(*args)
        return ("ПРОШЛО (не обнаружено)" if ok else "обнаружено"), (why or "-")
    except Exception as e:                        # падение проверки тоже результат, фиксируем
        return "ПРОВЕРКА УПАЛА", f"{type(e).__name__}: {e}"


def ambiguous_pair(row):
    """Пара записей из примера рецензента: исходная user="U|ext", pc="P" и подмена
    user="U", pc="ext|P". Склейка через '|' у обеих даёт "...|U|ext|P|...".
    Подмена возможна, только если в исходной записи уже есть '|' (у записей CERT его нет,
    поэтому исходную запись с '|' приходится создать: так выглядело бы поле, которое
    может заполнить сам пользователь)."""
    orig = dict(row)
    orig["user"] = row["user"] + "|ext"
    twin = dict(row)
    twin["pc"] = "ext|" + row["pc"]
    return orig, twin


def main():
    stage = sys.argv[1] if len(sys.argv) > 1 else "before"
    rows = ch.load_rows(ch.DEVICE_FILE, N + EXTRA)
    base, extra = rows[:N], rows[N:]
    results = []

    def add(bug, scheme, scenario, verdict, detail):
        results.append({"stage": stage, "bug": bug, "scheme": scheme, "scenario": scenario,
                        "verdict": verdict, "detail": detail})
        print(f"[{bug}] {scheme:22} {scenario:58} -> {verdict}  ({detail})")

    # ---------- Ошибка 1: дописанный хвост ----------
    bb.write_block_hmac(base, BLOG, BTAGS, chm.KEY, BLOCK)
    append_rows(BLOG, extra, ch.FIELDS, lambda r, i: [])
    v, d = run_check(bb.verify_block, BLOG, BTAGS, chm.KEY, BLOCK)
    add(1, "block tags B=1000", "дописаны 2000 записей без меток", v, d)

    chm.write_hmac_chain(base, LOG, ANCH, chm.KEY)
    append_rows(LOG, extra, None, lambda r, i: [""])
    v, d = run_check(chm.verify_hmac_chain, LOG, ANCH, chm.KEY)
    add(1, "per-record HMAC chain", "дописаны 2000 записей с пустой меткой", v, d)

    # нарушитель с ключом продолжает цепочку правильными метками, внешние точки не трогает
    chm.write_hmac_chain(base, LOG, ANCH, chm.KEY)
    chm.write_hmac_chain(base + extra, JUNK, os.path.join(T, "rp_junk_anch.csv"), chm.KEY)
    with open(JUNK, encoding="utf-8") as f:
        tail_macs = [r["mac"] for r in csv.DictReader(f)][N:]
    append_rows(LOG, extra, None, lambda r, i: [tail_macs[i]])
    v, d = run_check(chm.verify_hmac_chain, LOG, ANCH, chm.KEY)
    add(1, "per-record HMAC chain", "дописаны 2000 записей с верными метками (ключ), журнал завершён", v, d)

    # ---------- Ошибка 2: неоднозначная склейка ----------
    pos = 5000                                    # номер записи (с 1), которую подменяем
    orig, twin = ambiguous_pair(base[pos - 1])
    base = list(base)
    base[pos - 1] = orig                          # подлинный журнал содержит запись с '|'
    twin_rows = list(base)
    twin_rows[pos - 1] = twin
    print(f"\nподмена записи {pos}: user={orig['user']!r}, pc={orig['pc']!r}  ->  "
          f"user={twin['user']!r}, pc={twin['pc']!r}")

    def rewrite_keeping_tags(path, tag_cols):
        """Меняет в файле только поля записи pos, служебные колонки (старые метки) оставляет."""
        with open(path, encoding="utf-8") as f:
            rd = csv.DictReader(f)
            header, data = rd.fieldnames, list(rd)
        for k in ch.FIELDS:
            data[pos - 1][k] = twin_rows[pos - 1][k]
        with open(path, "w", newline="", encoding="utf-8") as f:
            w = csv.DictWriter(f, fieldnames=header)
            w.writeheader()
            w.writerows(data)

    ch.write_chained(base, SHA)
    rewrite_keeping_tags(SHA, ["prev_hash", "entry_hash"])
    ok, where = ch.verify_chain(SHA)
    add(2, "SHA-256 chain", "подмена user=U|ext,pc=P на user=U,pc=ext|P, старые хеши", "ПРОШЛО (не обнаружено)" if ok else "обнаружено", f"запись {where}" if where else "-")

    chm.write_hmac_chain(base, LOG, ANCH, chm.KEY)
    rewrite_keeping_tags(LOG, ["mac"])
    v, d = run_check(chm.verify_hmac_chain, LOG, ANCH, chm.KEY)
    add(2, "per-record HMAC chain", "подмена user=U|ext,pc=P на user=U,pc=ext|P, старые метки и точки", v, d)

    bb.write_block_hmac(base, BLOG, BTAGS, chm.KEY, BLOCK)
    rewrite_keeping_tags(BLOG, [])
    v, d = run_check(bb.verify_block, BLOG, BTAGS, chm.KEY, BLOCK)
    add(2, "block tags B=1000", "подмена user=U|ext,pc=P на user=U,pc=ext|P, старые метки блоков", v, d)

    # сохраняем, дописывая к прежним запускам (before и after в одном файле)
    exists = os.path.exists(OUT)
    old = []
    if exists:
        with open(OUT, encoding="utf-8") as f:
            old = [r for r in csv.DictReader(f) if r["stage"] != stage]
    with open(OUT, "w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=list(results[0].keys()))
        w.writeheader()
        w.writerows(old + results)
    for p in (LOG, ANCH, BLOG, BTAGS, SHA, JUNK, os.path.join(T, "rp_junk_anch.csv")):
        if os.path.exists(p):
            os.remove(p)
    print(f"\nсохранено: {OUT}")


if __name__ == "__main__":
    main()
