"""
ДОБАВЛЯЕМ file.csv: поднимется ли сценарий 2?

Сценарий 2 (поиск работы + кража перед уходом) на logon и device почти не
виден: у него 1188 из 1364 вредоносных дней, а полнота 10.6% в лучшем случае.
Его основные следы должны лежать в журнале копирования файлов file.csv.

Новые признаки, по той же логике "отклонение от собственной нормы":
  novel_file_off_hours - копирование файлов вне рабочих часов, ранее не характерное
  file_spike           - копирований втрое больше собственного среднего
  novel_file_ext       - копируется тип файла (расширение), которого не было на обучении

Веса заданы по аналогии с device-признаками (вне часов 0.65, всплеск 0.30)
и НЕ подбирались под разметку, чтобы не подгонять результат.

Сравниваются четыре конфигурации при FPR не выше 1%:
  device / file / device + file / logon + device + file

Из file.csv читаем только дату, пользователя и имя файла. Колонка content
огромная и не нужна. Файл читается построчно.

Результат: cert_file_results.csv
Запуск (из папки с CSV):  python cert_file.py
"""

import csv
import sys
from datetime import datetime, timedelta
from collections import defaultdict

import cert_ablation as ab

FILE_FILE = "file.csv"
OUTPUT_FILE = "cert_file_results.csv"
DATE_FORMAT = "%m/%d/%Y %H:%M:%S"

# В колонке content встречаются очень длинные строки
csv.field_size_limit(sys.maxsize)

FILE_WEIGHTS = {
    "novel_file_off_hours": 0.65,
    "file_spike": 0.30,
    "novel_file_ext": 0.30,
}


def extension(filename):
    """Расширение файла в нижнем регистре: 'EYPC9Y08.doc' -> 'doc'."""
    return filename.rsplit(".", 1)[-1].lower() if "." in filename else ""


def load_file_events():
    """
    Сводка file.csv по парам (пользователь, день):
    число копирований, из них вне рабочих часов, множество расширений.
    """
    fd = defaultdict(lambda: {"n": 0, "off": 0, "exts": set()})
    with open(FILE_FILE, encoding="utf-8") as f:
        for r in csv.DictReader(f):
            dt = datetime.strptime(r["date"], DATE_FORMAT)
            d = fd[(r["user"], dt.date())]
            d["n"] += 1
            d["exts"].add(extension(r["filename"]))
            if dt.hour < ab.WORK_START or dt.hour >= ab.WORK_END:
                d["off"] += 1
    return fd


def build_file_profiles(fd, split):
    """Профиль копирования файлов по обучающему периоду (дни до split)."""
    p = defaultdict(lambda: {"days": 0, "n": 0, "off_days": 0, "exts": set()})
    for (user, day), v in fd.items():
        if day >= split:
            continue
        pr = p[user]
        pr["days"] += 1
        pr["n"] += v["n"]
        pr["exts"] |= v["exts"]
        if v["off"] > 0:
            pr["off_days"] += 1
    return p


def file_features(v, pr, train_days):
    """
    Признаки копирования файлов. v - сводка за день, pr - профиль пользователя.
    train_days - длина обучающего периода в днях (общая для всех пользователей).
    Доли считаем от полного обучающего периода, а не только от дней с копированием,
    иначе редкое копирование выглядело бы частым.
    """
    f = {"novel_file_off_hours": False, "file_spike": False, "novel_file_ext": False}
    if v is None:
        return f
    off_share = pr["off_days"] / train_days if pr else 0.0
    avg = pr["n"] / train_days if pr else 0.0
    known_exts = pr["exts"] if pr else set()
    f["novel_file_off_hours"] = v["off"] > 0 and off_share < 0.05
    f["file_spike"] = avg > 0 and v["n"] > 3 * avg
    f["novel_file_ext"] = bool(v["exts"] - known_exts) and bool(known_exts)
    return f


def score(key, ud, prof, fd, fprof, config, train_days):
    """Оценка риска дня для выбранной конфигурации (сумма весов, максимум 1)."""
    user = key[0]
    pr = prof.get(user)
    v = ud.get(key)
    f = {}
    if "logon" in config and pr and pr["days"] and v:
        f.update(ab.logon_features(v, pr))
    if "device" in config and pr and pr["days"] and v:
        f.update(ab.device_features(v, pr))
    if "file" in config:
        f.update(file_features(fd.get(key), fprof.get(user), train_days))
    weights = {**ab.WEIGHTS, **FILE_WEIGHTS}
    return min(sum(weights[k] for k, on in f.items() if on), 1.0)


def main():
    print("Загрузка CERT r4.2 + file.csv...")
    windows = ab.load_labels()
    ud = ab.load_events()
    fd = load_file_events()
    days = sorted({d for _, d in ud} | {d for _, d in fd})
    split = days[0] + timedelta(days=ab.BASELINE_DAYS)
    prof = ab.build_profiles(ud, split)
    fprof = build_file_profiles(fd, split)

    # Тестовые пары: любая пара пользователь-день после split, где были события
    test_keys = sorted({k for k in list(ud) + list(fd) if k[1] >= split})
    labels = {k: ab.scenario_of(windows, k[0], k[1]) for k in test_keys}
    mal = sum(1 for k in test_keys if labels[k])
    print(f"  пар пользователь-день в file.csv: {len(fd)}")
    print(f"  тестовых дней: {len(test_keys)}, вредоносных {mal} "
          f"({100 * mal / len(test_keys):.2f}%)\n")
    print(f"Сравнение при FPR не выше {ab.TARGET_FPR:.0%}\n")

    out = []
    configs = [("device", "device"),
               ("file", "file"),
               ("device+file", "device file"),
               ("logon+device+file", "logon device file")]
    for name, cfg in configs:
        rows = [(score(k, ud, prof, fd, fprof, cfg, ab.BASELINE_DAYS), labels[k])
                for k in test_keys]
        cutoff, m = ab.pick_cutoff(rows, ab.TARGET_FPR)
        _, caught, total = ab.metrics(rows, cutoff)
        print(f"{name}   (порог {cutoff})")
        print(f"  TP {m['TP']:>4}   FN {m['FN']:>5}   FP {m['FP']:>5}   "
              f"precision {m['precision']:.3f}   recall {m['recall']:.3f}   "
              f"FPR {m['fpr']:.4f}")
        row = {"config": name, "cutoff": cutoff, **m}
        for sc in sorted(total):
            pct = 100 * caught[sc] / total[sc]
            print(f"    сценарий {sc} ({ab.SCENARIO_NAMES[sc]}): "
                  f"{caught[sc]:>4}/{total[sc]:<5} {pct:5.1f}%")
            row[f"recall_s{sc}"] = round(caught[sc] / total[sc], 4)
        print()
        out.append(row)

    with open(OUTPUT_FILE, "w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=list(out[-1].keys()))
        w.writeheader()
        w.writerows(out)
    print(f"Таблица сохранена: {OUTPUT_FILE}")


if __name__ == "__main__":
    main()
