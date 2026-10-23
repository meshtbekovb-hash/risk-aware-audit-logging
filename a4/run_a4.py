"""
ASSIGNMENT 4: ОДНА КОМАНДА ДЛЯ ВСЕГО ЭМПИРИЧЕСКОГО ИССЛЕДОВАНИЯ (tamper-evidence)

Запуск (из папки lit-review):   python a4/run_a4.py
Если прототип лежит не в ~/audit-paper:  python a4/run_a4.py --proto D:/path/to/audit-paper
Быстрая проверка без бенчмарка (на защите, если мало времени):  python a4/run_a4.py --attacks-only

Что делает по шагам (всё пишется в a4/evidence/, метка запуска <run> = дата_время):
  1. environment_<run>.txt  ОС, CPU, ОЗУ, питание, версии - всё считывается с системы;
                            git HEAD прототипа и сверка с коммитом d753388 (a4/reference_d753388/);
                            SHA-256 входного device.csv и его первых 10 000 / 11 500 записей.
                            Если файлы механизмов отличаются от d753388, скрипт останавливается.
  2. pytest_<run>.log       тесты прототипа; если хоть один не прошёл, дальше не идём.
  3. attack_run_<run>.log   17 атак: функции прототипа вызываются как есть (cert_chain_hmac.attack_tests,
                            cert_block_baseline.attack_tests, cert_tamper_extended.main).
     attack_matrix_<run>.csv  атака x схема x класс нарушителя: ожидаемый и наблюдаемый исход.
  4. bench_run_<run>.log    бенчмарк записи: 4 схемы, 3 прогревочных + 20 замеряемых кругов, порядок схем
                            в круге по латинскому квадрату; потом без изменений cert_performance_revised.py.
     bench_runs_<run>.csv     время каждой схемы в каждом круге;
     bench_summary_<run>.csv  среднее, 95% ДИ, отношение к обычному журналу; сравнение с оригинальным скриптом;
     bench_tests_<run>.csv    Wilcoxon signed-rank на 20 парах, поправка Холма, медианное отношение;
     storage_<run>.csv        объём хранилища (из cert_performance_revised.py).
  5. a4/figures/run_<run>/  рисунки этого прогона (make_figures.py).
  6. В текстовых файлах прогона имя пользователя и компьютера заменяются на <user>/<host>
     (anonymize_evidence.py). На экране они видны как есть.

Логика механизмов НЕ меняется: скрипт только вызывает функции прототипа и разбирает их вывод.
"""

import argparse
import csv
import datetime as dt
import difflib
import hashlib
import importlib.metadata as im
import io
import json
import os
import platform
import subprocess
import sys
import time
from contextlib import redirect_stdout
from statistics import mean, median, stdev

A4 = os.path.dirname(os.path.abspath(__file__))
EVIDENCE = os.path.join(A4, "evidence")
REFERENCE = os.path.join(A4, "reference_d753388")

N = 10000          # записей в журнале (как в cert_performance_revised.py)
WARMUP = 3         # прогревочных кругов (как в оригинале)
REPEATS = 20       # замеряемых кругов (как в оригинале)

# Порядок схем в круге: латинский квадрат 4x4 (схема Уильямса). Каждая схема ровно один раз
# стоит на каждом месте, и каждая схема одинаково часто идёт сразу после каждой другой.
# 20 кругов = каждая строка квадрата 5 раз. Так ни одна схема не получает систематически
# «первое место» (холодный кеш) или «последнее» (нагретый процессор).
SCHEMES = ["ordinary", "sha256_chain", "hmac_chain", "block_hmac"]
LATIN_SQUARE = [[0, 1, 3, 2],
                [1, 2, 0, 3],
                [2, 3, 1, 0],
                [3, 0, 2, 1]]

# Сравнения для Wilcoxon (H3): первая схема против второй
COMPARISONS = [("hmac_chain", "block_hmac"),
               ("hmac_chain", "ordinary"),
               ("block_hmac", "ordinary")]


# =====================================================================
# Вывод в консоль и в лог одновременно, с меткой времени в начале строки
# =====================================================================
class TimestampTee(io.TextIOBase):
    """Всё, что печатается (в том числе функциями прототипа), идёт и на экран, и в лог-файл.
    В начале каждой строки ставится время [ЧЧ:ММ:СС.ммм]."""

    def __init__(self, path, screen):
        self.file = open(path, "w", encoding="utf-8")
        self.screen = screen
        self.at_line_start = True

    def write(self, text):
        out = []
        for ch_ in text:
            if self.at_line_start and ch_ != "\n":
                out.append(dt.datetime.now().strftime("[%H:%M:%S.%f")[:-3] + "] ")
                self.at_line_start = False
            out.append(ch_)
            if ch_ == "\n":
                self.at_line_start = True
        s = "".join(out)
        self.file.write(s)
        self.screen.write(text)
        return len(text)

    def flush(self):
        if not self.file.closed:
            self.file.flush()
        self.screen.flush()

    def close_log(self):
        self.file.close()


class Both(io.TextIOBase):
    """Пишет в два места сразу: в лог с экраном (TimestampTee) и в буфер для разбора вердиктов."""

    def __init__(self, a, b):
        self.a, self.b = a, b

    def write(self, text):
        self.a.write(text)
        self.b.write(text)
        return len(text)

    def flush(self):
        self.a.flush()


def say(text=""):
    print(text, flush=True)


# =====================================================================
# Шаг 1. Окружение и сверка кода с d753388
# =====================================================================
def run_cmd(args, cwd=None):
    """Выполняет команду и возвращает её вывод (или текст ошибки)."""
    try:
        r = subprocess.run(args, cwd=cwd, capture_output=True, text=True, timeout=60,
                           encoding="utf-8", errors="replace")
        return (r.stdout or r.stderr).strip()
    except Exception as e:  # команды может не быть на этой ОС
        return f"<не удалось: {e}>"


def powershell(cmd):
    return run_cmd(["powershell", "-NoProfile", "-Command",
                    "[Console]::OutputEncoding = [Text.Encoding]::UTF8; " + cmd])


def sha256_file(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def sha256_first_lines(path, n_lines):
    """SHA-256 первых n_lines строк файла (байты как на диске). Заголовок CSV - это строка 1."""
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for _ in range(n_lines):
            line = f.readline()
            if not line:
                break
            h.update(line)
    return h.hexdigest()


def normalized_text(path):
    with open(path, "rb") as f:
        return f.read().replace(b"\r\n", b"\n").decode("utf-8")


def compare_with_reference(proto):
    """Сверка локального кода прототипа с d753388. Возвращает (строки отчёта, можно_ли_продолжать)."""
    code = os.path.join(proto, "code")
    with open(os.path.join(REFERENCE, "files.json"), encoding="utf-8") as f:
        ref = json.load(f)
    lines = [f"Reference commit (GitHub): {ref['commit']}",
             "  https://github.com/meshtbekovb-hash/risk-aware-audit-logging"]
    ok = True

    # 1) Пять файлов, которые использует A4: построчный diff с эталоном.
    #    Механизмы и бенчмарк должны совпадать полностью. Разрешены только два известных отличия:
    #    в cert_chain.py путь к device.csv берётся из paths.py, в cert_tamper_extended.py добавлен
    #    вызов E3 (только добавленные строки, ни одна строка атак не удалена и не изменена).
    allowed = {"cert_chain.py": "путь к device.csv", "cert_tamper_extended.py": "добавлен вызов E3"}
    lines.append("A4 files vs d753388 (line endings normalised):")
    for name in sorted(os.listdir(REFERENCE)):
        if not name.endswith(".py"):
            continue
        ref_t = normalized_text(os.path.join(REFERENCE, name)).splitlines()
        loc_t = normalized_text(os.path.join(code, name)).splitlines()
        diff = [d for d in difflib.unified_diff(ref_t, loc_t, lineterm="", n=0)
                if d[:1] in "+-" and not d.startswith(("+++", "---"))]
        if not diff:
            lines.append(f"  {name}: identical")
            continue
        removed = [d for d in diff if d.startswith("-")]
        if name == "cert_chain.py":
            known = all("DEVICE_FILE" in d or "import paths" in d or d.strip() in "+-" for d in diff)
        elif name == "cert_tamper_extended.py":
            known = not removed
        else:
            known = False
        status = f"differs, known difference ({allowed[name]})" if known else "DIFFERS (not allowed)"
        lines.append(f"  {name}: {status}; {len(diff)} changed lines:")
        lines += [f"      {d}" for d in diff]
        ok = ok and known

    # 2) Остальные файлы: какие отличаются, каких нет в d753388 (тесты и пр.)
    local_files = {}
    for sub in ("code", "tests"):
        for name in sorted(os.listdir(os.path.join(proto, sub))):
            p = os.path.join(proto, sub, name)
            if os.path.isfile(p):
                local_files[f"{sub}/{name}"] = p
    same, differ, local_only = [], [], []
    for rel, p in local_files.items():
        base = os.path.basename(rel)
        if rel.startswith("code/") and base in ref["files"]:
            h = hashlib.sha256(normalized_text(p).encode("utf-8")).hexdigest()
            (same if h == ref["files"][base] else differ).append(rel)
        else:
            local_only.append(rel)
    lines.append(f"Other local files: {len(same)} identical to d753388, {len(differ)} differ, "
                 f"{len(local_only)} not in d753388")
    lines.append("  differ: " + ", ".join(differ))
    lines.append("  not in d753388: " + ", ".join(local_only))
    return lines, ok


def write_environment(path, proto, device):
    say("Step 1. Environment and code check")
    e = []
    e.append(f"Run started: {dt.datetime.now().isoformat(timespec='seconds')}")
    e.append(f"Command: {' '.join([sys.executable] + sys.argv)}")
    e.append("")
    e.append("== System (read from the machine)")
    e.append(f"platform.platform(): {platform.platform()}")
    e.append(f"platform.machine(): {platform.machine()}")
    if os.name == "nt":
        e.append("OS: " + powershell("(Get-CimInstance Win32_OperatingSystem | "
                                     "ForEach-Object { $_.Caption + ' ' + $_.Version + ' build ' + $_.BuildNumber })"))
        e.append("CPU: " + powershell("(Get-CimInstance Win32_Processor | ForEach-Object { $_.Name.Trim() + "
                                      "', cores ' + $_.NumberOfCores + ', logical ' + $_.NumberOfLogicalProcessors + "
                                      "', max MHz ' + $_.MaxClockSpeed })"))
        e.append("RAM bytes: " + powershell("(Get-CimInstance Win32_ComputerSystem).TotalPhysicalMemory"))
        e.append("Disks: " + powershell("(Get-PhysicalDisk | ForEach-Object { $_.FriendlyName + ' (' + $_.MediaType + ')' }) -join '; '"))
        bat = powershell("(Get-CimInstance Win32_Battery | ForEach-Object { 'BatteryStatus=' + $_.BatteryStatus + "
                         "', charge=' + $_.EstimatedChargeRemaining + '%' }) -join '; '")
        e.append("Battery: " + (bat or "no battery found") + "   (BatteryStatus 2 = on AC power, 1 = on battery)")
        e.append("Power plan: " + powershell("powercfg /getactivescheme"))
    else:
        e.append("uname: " + run_cmd(["uname", "-a"]))
        e.append("CPU: " + run_cmd(["sh", "-c", "grep -m1 'model name' /proc/cpuinfo || sysctl -n machdep.cpu.brand_string"]))
    e.append(f"Temp dir used by the prototype for log files: {os.environ.get('TEMP', '/tmp')}")
    e.append("")
    e.append("== Python and libraries")
    e.append(f"Python: {sys.version}")
    e.append(f"Executable: {sys.executable}")
    for lib in ("pandas", "numpy", "scipy", "matplotlib", "pytest"):
        try:
            e.append(f"{lib}: {im.version(lib)}")
        except im.PackageNotFoundError:
            e.append(f"{lib}: not installed")
    e.append("hashlib, hmac, time.perf_counter, csv: Python standard library "
             f"(perf_counter resolution {time.get_clock_info('perf_counter').resolution} s)")
    e.append("")
    e.append("== Prototype code")
    e.append(f"Path: {proto}")
    e.append("Local HEAD: " + run_cmd(["git", "log", "-1", "--format=%H %ad %s", "--date=iso"], cwd=proto))
    status = run_cmd(["git", "status", "--porcelain"], cwd=proto)
    e.append("git status --porcelain: " + (status if status else "clean"))
    ref_lines, ok = compare_with_reference(proto)
    e.append("Local HEAD is not the GitHub commit d753388: the local repository was restructured "
             "(code/, tests/, results/) and has later commits. Comparison by file content:")
    e += ref_lines
    e.append(f"Mechanism check result: {'PASS - mechanisms identical to d753388' if ok else 'FAIL'}")
    e.append("")
    e.append("== Input data")
    e.append(f"device.csv: {device}")
    e.append(f"size bytes: {os.path.getsize(device)}")
    e.append(f"SHA-256 whole file: {sha256_file(device)}")
    e.append(f"SHA-256 header + first 10,000 records (the benchmark/attack log): {sha256_first_lines(device, 10001)}")
    e.append(f"SHA-256 header + first 11,500 records (incl. 'other log' and appended tail): {sha256_first_lines(device, 11501)}")
    with open(path, "w", encoding="utf-8") as f:
        f.write("\n".join(e) + "\n")
    for line in e:
        if line.startswith(("CPU", "OS", "Python:", "Local HEAD", "Mechanism", "Battery", "SHA-256 header + first 10")):
            say("  " + line)
    return ok


# =====================================================================
# Шаг 3. Атаки
# =====================================================================
# Колонки матрицы: схема и класс нарушителя.
#   sha_asis    SHA-256 цепочка, нарушитель правит файл и НЕ пересчитывает хеши
#   sha_recomp  SHA-256 цепочка пересчитана нарушителем (ключ не нужен никому)
#   hmac_A1 / hmac_A2    поэлементная HMAC-цепочка, без ключа / с украденным ключом
#   block_A1 / block_A2  блочные HMAC-метки B=1000, без ключа / с ключом
COLUMNS = ["sha_asis", "sha_recomp", "hmac_A1", "hmac_A2", "block_A1", "block_A2"]

# Коды исхода: R - до записи, B - до блока, C - на ближайшей контрольной точке, D - обнаружено,
# место не указано или не локализует атаку, M - пропущено, U - неподтверждённый хвост,
# NA - неприменимо, "" - не тестируется.
# Ожидания записаны ДО запуска (inventory.md, п. 4; уточнены по коду verify_* до запуска, см. там).
# Атаки 15 и 16 направлены на внешнее хранилище (A4) и показаны в колонках A1.
CATALOGUE = [
    # id, атака (англ.), класс для заметок, {колонка: ожидаемый код}
    (1, "Modify one record", {"sha_asis": "D", "hmac_A1": "R", "block_A1": "B"}),
    (2, "Modify and recompute without key", {"sha_recomp": "M", "hmac_A1": "R", "block_A1": "B"}),
    (3, "Truncate last 100 records", {"sha_asis": "M", "hmac_A1": "D", "block_A1": "B"}),
    (4, "Delete one record", {"sha_asis": "D", "hmac_A1": "R", "block_A1": "B"}),
    (5, "Swap two records", {"sha_asis": "D", "hmac_A1": "R", "block_A1": "B"}),
    (6, "Modify and recompute with stolen key", {"hmac_A2": "C", "block_A2": "B"}),
    (7, "Change after last checkpoint, stolen key", {"hmac_A2": "U", "block_A2": "U"}),
    (8, "Insert a record", {"sha_asis": "R", "sha_recomp": "M", "hmac_A1": "R", "hmac_A2": "C", "block_A1": "B", "block_A2": "B"}),
    (9, "Delete a block", {"sha_asis": "R", "sha_recomp": "M", "hmac_A1": "R", "hmac_A2": "C", "block_A1": "B", "block_A2": "B"}),
    (10, "Swap two blocks", {"sha_asis": "R", "sha_recomp": "M", "hmac_A1": "R", "hmac_A2": "C", "block_A1": "B", "block_A2": "B"}),
    (11, "Replay an old block", {"sha_asis": "R", "sha_recomp": "M", "hmac_A1": "R", "hmac_A2": "C", "block_A1": "B", "block_A2": "B"}),
    (12, "Splice block from other log, same key", {"sha_recomp": "M", "hmac_A1": "R", "hmac_A2": "C", "block_A1": "B", "block_A2": "B"}),
    (13, "Change timestamp only", {"sha_asis": "R", "sha_recomp": "M", "hmac_A1": "R", "hmac_A2": "C", "block_A1": "B", "block_A2": "B"}),
    (14, "Modify three records in three blocks", {"sha_asis": "R", "sha_recomp": "M", "hmac_A1": "R", "hmac_A2": "C", "block_A1": "B", "block_A2": "B"}),
    (15, "Corrupt one checkpoint (store only)", {"sha_asis": "NA", "hmac_A1": "C", "block_A1": "B"}),
    (16, "Roll back log and checkpoints (A1+A4)", {"sha_recomp": "M", "hmac_A1": "M", "block_A1": "M"}),
    (17, "Append 1000 records to closed log", {"sha_asis": "R", "sha_recomp": "M", "hmac_A1": "R", "hmac_A2": "D", "block_A1": "D", "block_A2": "D"}),
]
DETECTED = {"R", "B", "C", "D"}


def classify(detected, where):
    """Переводит вердикт прототипа (его текст на русском) в код исхода."""
    w = (where or "").strip()
    if w.startswith("н/п"):
        return "NA"
    if "неподтверждённый хвост" in w:
        return "U"
    if not detected:
        return "M"
    if "не совпадает с контрольной точкой" in w:
        return "C"
    if "метка записи №" in w or w.startswith("записи № [") or w.startswith("запись № "):
        return "R"
    if w.startswith("блок") or w.startswith("у блока"):
        return "B"
    return "D"       # журнал обрезан, дописанные записи, число меток и т.п.


def outcome_group(code):
    if code in DETECTED:
        return "detected"
    return {"M": "missed", "U": "unconfirmed tail", "NA": "n/a", "": "not tested"}.get(code, code)


def run_attacks(proto, workdir, log_path, matrix_path):
    import cert_chain as ch
    import cert_chain_hmac as chm
    import cert_block_baseline as bb
    import cert_tamper_extended as te

    observed = {}     # (id, колонка) -> (код, текст вердикта прототипа)
    rows = ch.load_rows(ch.DEVICE_FILE, N)
    say(f"Loaded {len(rows)} records from device.csv")

    # --- 3a. Семь базовых атак: HMAC-цепочка и SHA-цепочка (cert_chain_hmac.attack_tests) ---
    say("\n--- 3a. cert_chain_hmac.attack_tests (7 basic attacks, SHA-256 chain vs per-record HMAC) ---")
    buf = io.StringIO()
    with redirect_stdout(Both(sys.stdout, buf)):
        chm.attack_tests(rows)
    text = buf.getvalue()
    for line in text.splitlines():
        s = line.strip()
        if not (s[:1].isdigit() and s[1:3] == ". "):
            continue
        k = int(s[0])
        # строка: "<номер>. <название>   <вердикт SHA>   <вердикт HMAC>"
        # вердикт SHA - это ПЕРВОЕ из двух слов после названия (дальше идёт вердикт HMAC)
        found = [(s.find(wd), wd) for wd in (" обнаружена ", " пропущена ") if s.find(wd) > 0]
        pos, word = min(found)
        sha_word = s[pos:pos + len(word)].strip()
        hmac_part = s[pos + len(word):].strip()
        if hmac_part.startswith("обнаружена"):
            h_det, h_where = True, hmac_part[len("обнаружена"):].strip(" ()")
        elif hmac_part.startswith("ПОДМЕНА ПРОПУЩЕНА"):
            h_det, h_where = False, hmac_part.split(",", 1)[1].strip()
        else:
            h_det, h_where = False, ""
        hcol = "hmac_A2" if k in (6, 7) else "hmac_A1"
        observed[(k, hcol)] = (classify(h_det, h_where), hmac_part)
        # Вердикт SHA в атаках 6 и 7 в прототипе напечатан константой («пропущена»), а не получен
        # проверкой, поэтому в матрицу не идёт. В атаках 1-5 место ошибки SHA не печатается -> код D.
        if k in (1, 3, 4, 5):
            observed[(k, "sha_asis")] = ("D" if sha_word == "обнаружена" else "M", sha_word)
        elif k == 2:
            observed[(k, "sha_recomp")] = ("D" if sha_word == "обнаружена" else "M", sha_word)

    # --- 3b. Те же семь атак на блочную схему (cert_block_baseline.attack_tests) ---
    say("\n--- 3b. cert_block_baseline.attack_tests (same 7 attacks, block HMAC B=1000) ---")
    buf = io.StringIO()
    with redirect_stdout(Both(sys.stdout, buf)):
        bb.attack_tests(rows, 1000)
    text = buf.getvalue()
    for line in text.splitlines():
        s = line.strip()
        if not (s[:1].isdigit() and s[1:3] == ". "):
            continue
        k = int(s[0])
        verdict = s.split(":", 1)[1].strip()
        if verdict.startswith("обнаружена"):
            det, where = True, verdict[len("обнаружена"):].strip(" ()")
        elif verdict.startswith("ПОДМЕНА ПРОПУЩЕНА"):
            det, where = False, verdict.split(",", 1)[1].strip()
        else:
            det, where = False, ""
        observed[(k, "block_A2" if k in (6, 7) else "block_A1")] = (classify(det, where), verdict)

    # --- 3c. Десять расширенных атак (cert_tamper_extended.main), как есть ---
    say("\n--- 3c. cert_tamper_extended.main (10 extended attacks on all three schemes; "
        "also runs the E3 hybrid rows, which A4 does not use) ---")
    te.main()
    with open(os.path.join(workdir, "results_revision", "tamper_extended.csv"), encoding="utf-8") as f:
        ext = list(csv.DictReader(f))
    scheme_col = {"SHA-256 цепочка": "sha", "HMAC поэлементная": "hmac", "блочная HMAC B=1000": "block"}
    for r in ext:
        if r["scheme"] not in scheme_col:
            continue                       # строки E3 (гибриды) в A4 не входят
        k = 7 + int(r["attack_id"])        # атаки 1..10 расширенного набора = 8..17 каталога
        sch, key = scheme_col[r["scheme"]], r["key_assumption"]
        if sch == "sha":
            col = "sha_recomp" if (key.startswith("с ключом") or k == 16) else "sha_asis"
        elif k in (15, 16):
            col = f"{sch}_A1"
        else:
            col = f"{sch}_A2" if key.startswith("с ключом") else f"{sch}_A1"
        observed[(k, col)] = (classify(r["detected"] == "True", r["where"]), r["where"])

    # --- Матрица: ожидаемое против наблюдаемого ---
    out = []
    for k, name, expected in CATALOGUE:
        for col in COLUMNS:
            exp = expected.get(col, "")
            obs, raw = observed.get((k, col), ("", ""))
            out.append({"attack_id": k, "attack": name, "column": col,
                        "scheme": col.split("_")[0], "adversary": col.split("_")[1],
                        "expected": exp, "observed": obs,
                        "expected_group": outcome_group(exp), "observed_group": outcome_group(obs),
                        "outcome_match": outcome_group(exp) == outcome_group(obs),
                        "code_match": exp == obs, "prototype_verdict": raw})
    with open(matrix_path, "w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=list(out[0].keys()))
        w.writeheader()
        w.writerows(out)

    tested = [r for r in out if r["expected"] or r["observed"]]
    n_out = sum(r["outcome_match"] for r in tested)
    n_code = sum(r["code_match"] for r in tested)
    say("\nATTACK MATRIX (expected -> observed; R record, B block, C checkpoint, D detected, "
        "M missed, U unconfirmed tail)")
    say(f"{'#':>3} {'attack':42}" + "".join(f"{c:>12}" for c in COLUMNS))
    for k, name, _ in CATALOGUE:
        cells = []
        for col in COLUMNS:
            r = next(x for x in out if x["attack_id"] == k and x["column"] == col)
            if not r["expected"] and not r["observed"]:
                cells.append(f"{'-':>12}")
            else:
                mark = "" if r["code_match"] else ("*" if r["outcome_match"] else " !!")
                cells.append(f"{r['expected'] + '->' + r['observed'] + mark:>12}")
        say(f"{k:>3} {name[:42]:42}" + "".join(cells))
    say(f"\nCells tested: {len(tested)}; outcome as expected (detected/missed/tail): {n_out}/{len(tested)}; "
        f"exact code as expected: {n_code}/{len(tested)}  (* = code differs, !! = outcome differs)")
    return out


# =====================================================================
# Шаг 4. Бенчмарк
# =====================================================================
def t_quantile_975(df):
    from scipy.stats import t
    return float(t.ppf(0.975, df))


def holm(pvalues):
    """Поправка Холма: p_(i) * (m - i + 1), по порядку, с монотонностью, не больше 1."""
    m = len(pvalues)
    order = sorted(range(m), key=lambda i: pvalues[i])
    adj, running = [0.0] * m, 0.0
    for rank, i in enumerate(order):
        running = max(running, min(1.0, (m - rank) * pvalues[i]))
        adj[i] = running
    return adj


def run_benchmark(runs_path, summary_path, tests_path, storage_path, workdir):
    from scipy.stats import rankdata, skew, wilcoxon
    import cert_chain as ch
    import cert_chain_hmac as chm
    import cert_block_baseline as bb
    import cert_performance_revised as perf

    rows = ch.load_rows(ch.DEVICE_FILE, N)
    # Те же функции записи, те же параметры и те же файлы, что в cert_performance_revised.py (строки 165-170):
    # B = 1000, контрольная точка каждые chm.CHECKPOINT_EVERY = 1000, тот же ключ, запись на диск в TEMP.
    # Запись контрольных точек и меток блоков идёт внутри той же функции, значит входит в замер.
    write = {
        "ordinary": (lambda: ch.write_plain(rows, perf.P_PLAIN), [perf.P_PLAIN]),
        "sha256_chain": (lambda: ch.write_chained(rows, perf.P_SHA), [perf.P_SHA]),
        "hmac_chain": (lambda: chm.write_hmac_chain(rows, perf.P_HLOG, perf.P_HANCH, perf.KEY),
                       [perf.P_HLOG, perf.P_HANCH]),
        "block_hmac": (lambda: bb.write_block_hmac(rows, perf.P_BLOG, perf.P_BTAGS, perf.KEY, perf.BLOCK),
                       [perf.P_BLOG, perf.P_BTAGS]),
    }
    say(f"Parameters: N={N}, B={perf.BLOCK}, checkpoint every {chm.CHECKPOINT_EVERY}, "
        f"warm-up rounds={WARMUP}, timed rounds={REPEATS}, timer=time.perf_counter, no fsync")
    say("Order of schemes per round: Latin square rows " +
        "; ".join(",".join(SCHEMES[i] for i in row) for row in LATIN_SQUARE))

    times = {s: [] for s in SCHEMES}
    run_rows = []
    for rnd in range(WARMUP + REPEATS):
        order = LATIN_SQUARE[rnd % 4]
        timed_round = rnd >= WARMUP
        for pos, i in enumerate(order):
            s = SCHEMES[i]
            fn, paths = write[s]
            ms = 1000 * perf.timed(fn, paths, False)       # та же функция замера, что в оригинале
            if timed_round:
                times[s].append(ms)
                run_rows.append({"round": rnd - WARMUP + 1, "square_row": rnd % 4 + 1,
                                 "position": pos + 1, "scheme": s, "time_ms": round(ms, 4)})
        if timed_round:
            say(f"  round {rnd - WARMUP + 1:2d}: " +
                "  ".join(f"{SCHEMES[i]}={times[SCHEMES[i]][-1]:6.2f}" for i in order) + " ms")
        else:
            say(f"  warm-up round {rnd + 1} done (not counted)")
    with open(runs_path, "w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=list(run_rows[0].keys()))
        w.writeheader()
        w.writerows(run_rows)

    # --- Оригинальный скрипт прототипа без изменений: перекрёстная проверка и объём хранилища ---
    say("\n--- cert_performance_revised.main(), unchanged (sequential order: 20 runs of one scheme, then the next) ---")
    perf.main()
    with open(os.path.join(workdir, "results_revision", "performance_revised.csv"), encoding="utf-8") as f:
        orig = {r["scheme"]: r for r in csv.DictReader(f)
                if r["metric"] == "scheme_comparison" and r["write_mode"] == "обычная"}
    orig_name = {"ordinary": "обычный журнал", "sha256_chain": "SHA-256 цепочка",
                 "hmac_chain": "HMAC поэлементная", "block_hmac": "блочная HMAC B=1000"}
    with open(os.path.join(workdir, "results_revision", "storage_breakdown.csv"), encoding="utf-8") as f:
        storage = list(csv.DictReader(f))
    plain_bytes = int(storage[0]["total_bytes_actual"])
    st_name = {"обычный журнал": "ordinary", "SHA-256 цепочка": "sha256_chain",
               "HMAC поэлементная": "hmac_chain", "блочная HMAC B=1000": "block_hmac"}
    st_rows = []
    for r in storage:
        total = int(r["total_bytes_actual"])
        st_rows.append({"scheme": st_name[r["scheme"]],
                        "tag_encoding": {"-": "none", "hex": "hex", "бинарно": "binary"}[r["tag_encoding"]],
                        "records_bytes": r["records_bytes"], "tags_bytes": r["tags_bytes"],
                        "block_metadata_bytes": r["block_metadata_bytes"],
                        "checkpoints_bytes": r["checkpoints_bytes"], "total_bytes": total,
                        "overhead_pct": round(100 * (total - plain_bytes) / plain_bytes, 3),
                        "sum_check": r["matches"]})
    with open(storage_path, "w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=list(st_rows[0].keys()))
        w.writeheader()
        w.writerows(st_rows)

    # --- Сводка ---
    t975 = t_quantile_975(REPEATS - 1)
    base = mean(times["ordinary"])
    summary = []
    for s in SCHEMES:
        x = times[s]
        m, sd = mean(x), stdev(x)
        half = t975 * sd / len(x) ** 0.5
        o = orig[orig_name[s]]
        o_mean = float(o["mean_ms"])
        summary.append({"scheme": s, "n": len(x), "mean_ms": round(m, 2), "sd_ms": round(sd, 2),
                        "ci95_lo_ms": round(m - half, 2), "ci95_hi_ms": round(m + half, 2),
                        "median_ms": round(median(x), 2),
                        "ratio_to_ordinary_mean": round(m / base, 3),
                        "overhead_vs_ordinary_pct": round(100 * (m - base) / base, 1),
                        "original_script_mean_ms": o_mean,
                        "original_script_ci95": f"{o['ci95_lo_ms']}-{o['ci95_hi_ms']}",
                        "original_ratio_to_ordinary": round(o_mean / float(orig[orig_name['ordinary']]['mean_ms']), 3),
                        "diff_original_vs_a4_pct": round(100 * (o_mean - m) / m, 1),
                        "original_inside_a4_ci": m - half <= o_mean <= m + half})
    with open(summary_path, "w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=list(summary[0].keys()))
        w.writeheader()
        w.writerows(summary)

    # --- Wilcoxon signed-rank на 20 парах (пара = одна и та же строка круга), поправка Холма ---
    tests = []
    for a, b in COMPARISONS:
        xa, xb = times[a], times[b]
        d = [p - q for p, q in zip(xa, xb)]
        res = wilcoxon(xa, xb, alternative="two-sided", method="exact")
        ranks = rankdata([abs(v) for v in d])
        w_plus = sum(r for r, v in zip(ranks, d) if v > 0)
        w_minus = sum(r for r, v in zip(ranks, d) if v < 0)
        total = len(d) * (len(d) + 1) / 2
        ratios = [p / q for p, q in zip(xa, xb)]
        tests.append({"comparison": f"{a} vs {b}", "n_pairs": len(d),
                      "pairs_a_slower": sum(v > 0 for v in d),
                      "median_ratio_a_over_b": round(median(ratios), 3),
                      "min_ratio": round(min(ratios), 3), "max_ratio": round(max(ratios), 3),
                      "median_diff_ms": round(median(d), 2),
                      "W_plus": w_plus, "W_minus": w_minus, "statistic": float(res.statistic),
                      "p_exact": float(res.pvalue),
                      "rank_biserial_r": round((w_plus - w_minus) / total, 3),
                      "skewness_of_differences": round(float(skew(d)), 3)})
    for t_, p_adj in zip(tests, holm([t_["p_exact"] for t_ in tests])):
        t_["p_holm"] = p_adj
    with open(tests_path, "w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=list(tests[0].keys()))
        w.writeheader()
        w.writerows(tests)

    say("\nBENCHMARK SUMMARY (10,000 records, 20 timed rounds, Latin-square order)")
    say(f"{'scheme':14} {'mean ms':>8} {'95% CI':>17} {'x ordinary':>11} {'orig. script':>13} {'diff':>7}")
    for r in summary:
        say(f"{r['scheme']:14} {r['mean_ms']:8.2f} {r['ci95_lo_ms']:8.2f}-{r['ci95_hi_ms']:<8.2f} "
            f"{r['ratio_to_ordinary_mean']:>10.2f}x {r['original_script_mean_ms']:>12.2f} "
            f"{r['diff_original_vs_a4_pct']:>6.1f}%")
    say("\nPAIRED TESTS (Wilcoxon signed-rank, exact, two-sided; Holm over 3 comparisons)")
    for t_ in tests:
        say(f"  {t_['comparison']:26} median ratio {t_['median_ratio_a_over_b']:.3f} "
            f"(range {t_['min_ratio']:.2f}-{t_['max_ratio']:.2f}), a slower in {t_['pairs_a_slower']}/20 pairs, "
            f"p = {t_['p_exact']:.2e}, Holm p = {t_['p_holm']:.2e}, r = {t_['rank_biserial_r']}")
    say("\nSTORAGE (bytes, from cert_performance_revised.py)")
    for r in st_rows:
        say(f"  {r['scheme']:14} {r['tag_encoding']:7} {r['total_bytes']:>9}  +{r['overhead_pct']}%")
    return summary, tests


# =====================================================================
def main():
    ap = argparse.ArgumentParser(description="Assignment 4 empirical study: attacks + benchmark")
    ap.add_argument("--proto", default=os.path.join(os.path.expanduser("~"), "audit-paper"),
                    help="path to the prototype repository (default ~/audit-paper)")
    ap.add_argument("--attacks-only", action="store_true", help="skip the benchmark (about 1 minute faster)")
    args = ap.parse_args()

    try:
        sys.stdout.reconfigure(encoding="utf-8")       # прототип печатает по-русски
    except Exception:
        pass
    proto = os.path.abspath(args.proto)
    sys.path.insert(0, os.path.join(proto, "code"))
    import paths
    device = paths.DEVICE_R42

    run = dt.datetime.now().strftime("%Y%m%d_%H%M%S")
    os.makedirs(EVIDENCE, exist_ok=True)
    workdir = os.path.join(EVIDENCE, f"work_{run}")      # сюда прототип пишет свои results_revision/*.csv
    os.makedirs(os.path.join(workdir, "results_revision"), exist_ok=True)
    ev = lambda name: os.path.join(EVIDENCE, f"{name}_{run}")
    screen = sys.stdout

    # 1. окружение
    if not write_environment(ev("environment") + ".txt", proto, device):
        sys.exit("STOP: mechanism files differ from d753388, see environment file. Nothing was run.")

    # 2. тесты прототипа
    say("\nStep 2. Prototype tests (pytest)")
    r = subprocess.run([sys.executable, "-m", "pytest", "tests", "-q", "-p", "no:cacheprovider"], cwd=proto,
                       capture_output=True, text=True, encoding="utf-8", errors="replace")
    with open(ev("pytest") + ".log", "w", encoding="utf-8") as f:
        f.write(f"{dt.datetime.now().isoformat(timespec='seconds')}  python -m pytest tests -q  (cwd {proto})\n")
        f.write(r.stdout + r.stderr)
    say("  " + (r.stdout.strip().splitlines() or ["<no output>"])[-1])
    if r.returncode != 0:
        sys.exit("STOP: prototype tests failed, see pytest log. No numbers were produced.")

    os.chdir(workdir)
    # 3. атаки
    tee = TimestampTee(ev("attack_run") + ".log", screen)
    sys.stdout = tee
    say(f"Step 3. Attack suite  (run {run}, prototype {proto})")
    t0 = time.perf_counter()
    run_attacks(proto, workdir, ev("attack_run") + ".log", ev("attack_matrix") + ".csv")
    say(f"Attack suite finished in {time.perf_counter() - t0:.1f} s")
    sys.stdout = screen
    tee.close_log()

    # 4. бенчмарк
    if not args.attacks_only:
        tee = TimestampTee(ev("bench_run") + ".log", screen)
        sys.stdout = tee
        say(f"Step 4. Write-time benchmark  (run {run})")
        t0 = time.perf_counter()
        run_benchmark(ev("bench_runs") + ".csv", ev("bench_summary") + ".csv", ev("bench_tests") + ".csv",
                      ev("storage") + ".csv", workdir)
        say(f"Benchmark finished in {time.perf_counter() - t0:.1f} s")
        sys.stdout = screen
        tee.close_log()

    # 5. рисунки
    say("\nStep 5. Figures")
    subprocess.run([sys.executable, os.path.join(A4, "make_figures.py"), run], check=True)

    # 6. имя пользователя и компьютера в файлах прогона -> <user>/<host> (числа не меняются)
    say("\nStep 6. Anonymize evidence files")
    subprocess.run([sys.executable, os.path.join(A4, "anonymize_evidence.py"), run], check=True)
    say(f"\nDone. Evidence: {EVIDENCE}  (run id {run})")


if __name__ == "__main__":
    main()
