"""
ТЕСТЫ ОБНАРУЖЕНИЯ ПОДДЕЛКИ ЖУРНАЛА

Проверяются три схемы защиты из статьи:
  sha   - простая SHA-256 цепочка            (cert_chain.py)
  hmac  - поэлементная HMAC-цепочка с внешними контрольными точками (cert_chain_hmac.py)
  block - блочные HMAC-теги, блок 1000 записей (cert_block_baseline.py)

Журнал искусственный: 10 000 записей в формате device.csv, данные CERT не нужны.
В каждом тесте журнал пишется заново, портится одним способом и проверяется.

Первые два теста - две ошибки, найденные внешней проверкой и исправленные в коммите
f53e178. На старом коде (ветка main на GitHub) они должны ПАДАТЬ, на исправленном - проходить.

Запуск из корня проекта:  python -m pytest tests -v
"""

import csv

import pytest

import cert_block_baseline as bb
import cert_chain as ch
import cert_chain_hmac as chm

N = 10000        # записей в журнале
EXTRA = 2000     # сколько записей дописывает нарушитель
BLOCK = 1000     # размер блока для блочной схемы
TARGET = 5000    # номер записи, которую портим (нумерация с 1)
KEY = chm.KEY


def make_rows(n, start=1):
    """Искусственные записи в формате device.csv. Все записи разные."""
    return [{"id": f"{{EV-{i:08d}}}",
             "date": f"10/{1 + i % 28:02d}/2010 {i % 24:02d}:{i % 60:02d}:00",
             "user": f"USR{i % 265:04d}",
             "pc": f"PC-{i % 500:04d}",
             "activity": "Connect" if i % 2 else "Disconnect"}
            for i in range(start, start + n)]


class Scheme:
    """Одна схема защиты: как записать журнал и как его проверить.
    extra - файл, который в реальной системе лежит во внешнем хранилище
    (контрольные точки или теги блоков)."""

    def __init__(self, name, folder):
        self.name = name
        self.log = str(folder / f"{name}_log.csv")
        self.extra = str(folder / f"{name}_external.csv")

    def write(self, rows):
        if self.name == "sha":
            ch.write_chained(rows, self.log)
        elif self.name == "hmac":
            chm.write_hmac_chain(rows, self.log, self.extra, KEY)
        else:
            bb.write_block_hmac(rows, self.log, self.extra, KEY, BLOCK)

    def verify(self, **kw):
        """Возвращает (статус, причина). Статус True означает «журнал цел»."""
        if self.name == "sha":
            return ch.verify_chain(self.log)
        if self.name == "hmac":
            return chm.verify_hmac_chain(self.log, self.extra, KEY, **kw)
        return bb.verify_block(self.log, self.extra, KEY, BLOCK, **kw)


def read_lines(path):
    """Строки файла вместе с переводами строк. lines[0] - заголовок, lines[n] - запись № n."""
    with open(path, encoding="utf-8", newline="") as f:
        return f.readlines()


def write_lines(path, lines):
    with open(path, "w", encoding="utf-8", newline="") as f:
        f.writelines(lines)


def append_untagged(path, rows, empty_columns):
    """Дописывает записи в конец журнала без меток (пустые служебные колонки)."""
    with open(path, "a", encoding="utf-8", newline="") as f:
        w = csv.writer(f)
        for r in rows:
            w.writerow([r[k] for k in ch.FIELDS] + [""] * empty_columns)


# ---------------------------------------------------------------
# 1 и 2. Две ошибки, исправленные в f53e178
# ---------------------------------------------------------------
@pytest.mark.parametrize("name", ["hmac", "block"])
def test_appended_untagged_lines_are_detected(name, tmp_path):
    """К закрытому журналу из 10 000 записей дописаны 2000 строк без меток."""
    s = Scheme(name, tmp_path)
    s.write(make_rows(N))
    append_untagged(s.log, make_rows(EXTRA, start=N + 1), empty_columns=1 if name == "hmac" else 0)

    ok, why = s.verify()

    assert ok is False, f"дописанные записи не обнаружены: {why!r}"


@pytest.mark.parametrize("name", ["sha", "hmac", "block"])
def test_ambiguous_field_split_is_detected(name, tmp_path):
    """Запись user="a|b", pc="c" подменена на user="a", pc="b|c", метки не тронуты.
    При склейке полей через "|" обе записи давали одну и ту же строку и один тег."""
    rows = make_rows(N)
    rows[TARGET - 1]["user"], rows[TARGET - 1]["pc"] = "a|b", "c"
    s = Scheme(name, tmp_path)
    s.write(rows)
    lines = read_lines(s.log)
    assert ",a|b,c," in lines[TARGET]
    lines[TARGET] = lines[TARGET].replace(",a|b,c,", ",a,b|c,")
    write_lines(s.log, lines)

    ok, why = s.verify()

    assert ok is False, f"подмена полей не обнаружена: {why!r}"


def test_appended_lines_in_growing_log_are_not_confirmed(tmp_path):
    """Растущий журнал (complete=False): записи после последнего внешнего тега нельзя
    отличить от новых честных записей, но проверка обязана сообщить, что они не
    подтверждены, а не вернуть «всё в порядке»."""
    s = Scheme("block", tmp_path)
    s.write(make_rows(N))
    append_untagged(s.log, make_rows(EXTRA, start=N + 1), empty_columns=0)

    ok, why = s.verify(complete=False)

    assert ok is not True
    assert "10001..12000" in why


# ---------------------------------------------------------------
# Контроль: нетронутый журнал проходит проверку
# ---------------------------------------------------------------
@pytest.mark.parametrize("name", ["sha", "hmac", "block"])
def test_untouched_log_verifies(name, tmp_path):
    s = Scheme(name, tmp_path)
    s.write(make_rows(N))

    ok, _ = s.verify()

    assert ok is True


# ---------------------------------------------------------------
# Изменение, удаление, вставка, перестановка, обрезка
# ---------------------------------------------------------------
def modify(lines):
    """Меняет тип события в записи TARGET (Connect <-> Disconnect)."""
    old = lines[TARGET]
    lines[TARGET] = old.replace("Disconnect", "Connect") if "Disconnect" in old \
        else old.replace("Connect", "Disconnect")
    assert lines[TARGET] != old


def delete(lines):
    del lines[TARGET]


def insert(lines):
    """Вставляет копию записи TARGET сразу после неё."""
    lines.insert(TARGET + 1, lines[TARGET])


def reorder(lines):
    lines[TARGET], lines[TARGET + 1] = lines[TARGET + 1], lines[TARGET]


def truncate(lines):
    """Обрезает последние 100 записей."""
    del lines[-100:]


ATTACKS = {"modify": modify, "delete": delete, "insert": insert, "reorder": reorder,
           "truncate": truncate}


@pytest.mark.parametrize("attack", list(ATTACKS))
@pytest.mark.parametrize("name", ["hmac", "block"])
def test_keyed_schemes_detect_structural_attacks(name, attack, tmp_path):
    """Нарушитель без ключа правит файл журнала, внешнее хранилище ему недоступно."""
    s = Scheme(name, tmp_path)
    s.write(make_rows(N))
    lines = read_lines(s.log)
    ATTACKS[attack](lines)
    write_lines(s.log, lines)

    ok, why = s.verify()

    assert ok is False, f"атака {attack} не обнаружена схемой {name}"


@pytest.mark.parametrize("attack", ["modify", "delete", "insert", "reorder"])
def test_sha_chain_detects_edits_without_recomputation(attack, tmp_path):
    """Простая цепочка ловит правку, только если хеши после неё не пересчитаны."""
    s = Scheme("sha", tmp_path)
    s.write(make_rows(N))
    lines = read_lines(s.log)
    ATTACKS[attack](lines)
    write_lines(s.log, lines)

    ok, _ = s.verify()

    assert ok is False


# ---------------------------------------------------------------
# Точность локализации и известная слабость простой цепочки (как в статье)
# ---------------------------------------------------------------
def test_hmac_chain_points_to_the_exact_record(tmp_path):
    s = Scheme("hmac", tmp_path)
    s.write(make_rows(N))
    lines = read_lines(s.log)
    modify(lines)
    write_lines(s.log, lines)

    _, why = s.verify()

    assert str(TARGET) in why


def test_block_tags_point_to_the_block_only(tmp_path):
    s = Scheme("block", tmp_path)
    s.write(make_rows(N))
    lines = read_lines(s.log)
    modify(lines)
    write_lines(s.log, lines)

    _, why = s.verify()

    assert "4001..5000" in why


def test_recomputed_sha_chain_is_not_detected(tmp_path):
    """Граница простой цепочки: нарушитель с правом записи меняет запись и пересчитывает
    все хеши. Ключа нет, внешней опоры нет, поэтому подделка проходит проверку."""
    rows = make_rows(N)
    rows[TARGET - 1]["activity"] = "Connect"          # запись 5000 была Disconnect
    s = Scheme("sha", tmp_path)
    s.write(rows)                                     # цепочка пересчитана целиком

    ok, _ = s.verify()

    assert ok is True


def test_recomputed_hmac_chain_without_key_is_detected(tmp_path):
    """То же для HMAC-цепочки: без ключа пересчитать метки нельзя, подделка видна."""
    s = Scheme("hmac", tmp_path)
    s.write(make_rows(N))                             # настоящие внешние контрольные точки
    rows = make_rows(N)
    rows[TARGET - 1]["activity"] = "Connect"
    chm.write_hmac_chain(rows, s.log, str(tmp_path / "attacker_points.csv"), chm.ATTACKER_KEY)

    ok, _ = s.verify()

    assert ok is False
