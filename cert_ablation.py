"""
ЭКСПЕРИМЕНТ НА CERT r4.2: сравнение конфигураций телеметрии

Главный вопрос работы: что сильнее влияет на обнаружение инсайдера -
алгоритм или набор собираемых журналов?

Чтобы ответить, мы сравниваем три конфигурации на ОДНОМ И ТОМ ЖЕ
множестве пользователь-день и при ОДИНАКОВОМ уровне ложных тревог:

  A. только logon.csv   - входы на рабочие станции
  B. только device.csv  - подключение съёмных носителей
  C. logon + device     - объединённая телеметрия

Сравнение при фиксированном FPR - обязательное условие честности.
Без него конфигурацию можно "выиграть" простым понижением порога.

Данные:
  logon.csv, device.csv, insiders.csv (официальная разметка CMU SEI)

Запуск (из папки с тремя CSV):  python3 cert_ablation.py
"""

import csv
from datetime import datetime, timedelta
from collections import defaultdict

LOGON_FILE = "logon.csv"
DEVICE_FILE = "device.csv"
INSIDERS_FILE = "insiders.csv"
OUTPUT_FILE = "cert_ablation_results.csv"

BASELINE_DAYS = 120
WORK_START, WORK_END = 8, 18
TARGET_FPR = 0.01          # 1% ложных тревог - рабочий уровень для SOC
SCENARIO_NAMES = {
    "1": "ночной доступ + съёмный носитель",
    "2": "поиск работы + кража перед уходом",
    "3": "администратор под чужой учёткой",
}


# ---------------------------------------------------------------
# Загрузка
# ---------------------------------------------------------------
def load_labels():
    w = defaultdict(list)
    with open(INSIDERS_FILE, encoding="utf-8") as f:
        for r in csv.DictReader(f):
            if r["dataset"] != "4.2":
                continue
            w[r["user"]].append((
                r["scenario"],
                datetime.strptime(r["start"], "%m/%d/%Y %H:%M:%S").date(),
                datetime.strptime(r["end"], "%m/%d/%Y %H:%M:%S").date()))
    return w


def scenario_of(windows, user, day):
    for sc, s, e in windows.get(user, []):
        if s <= day <= e:
            return sc
    return None


def load_events():
    ud = defaultdict(lambda: {"logon_off": 0, "logon_wknd": 0, "pcs": set(),
                              "dev": 0, "dev_off": 0})

    with open(LOGON_FILE, encoding="utf-8") as f:
        for r in csv.DictReader(f):
            if r["activity"] != "Logon":
                continue
            dt = datetime.strptime(r["date"], "%m/%d/%Y %H:%M:%S")
            d = ud[(r["user"], dt.date())]
            d["pcs"].add(r["pc"])
            if dt.hour < WORK_START or dt.hour >= WORK_END:
                d["logon_off"] += 1
            if dt.weekday() >= 5:
                d["logon_wknd"] += 1

    with open(DEVICE_FILE, encoding="utf-8") as f:
        for r in csv.DictReader(f):
            if r["activity"] != "Connect":
                continue
            dt = datetime.strptime(r["date"], "%m/%d/%Y %H:%M:%S")
            d = ud[(r["user"], dt.date())]
            d["dev"] += 1
            if dt.hour < WORK_START or dt.hour >= WORK_END:
                d["dev_off"] += 1

    return ud


def build_profiles(ud, split):
    p = defaultdict(lambda: {"days": 0, "off": 0, "wknd": 0,
                             "dev_off": 0, "dev_total": 0, "pcs": set()})
    for (user, day), v in ud.items():
        if day >= split:
            continue
        pr = p[user]
        pr["days"] += 1
        pr["pcs"] |= v["pcs"]
        pr["dev_total"] += v["dev"]
        if v["logon_off"] > 0:
            pr["off"] += 1
        if v["logon_wknd"] > 0:
            pr["wknd"] += 1
        if v["dev_off"] > 0:
            pr["dev_off"] += 1
    return p


# ---------------------------------------------------------------
# Признаки. Каждый - отклонение от собственной нормы пользователя.
# ---------------------------------------------------------------
def logon_features(v, pr):
    days = pr["days"]
    f = {}
    f["novel_off_hours"] = v["logon_off"] > 0 and pr["off"] / days < 0.10
    f["novel_weekend"] = v["logon_wknd"] > 0 and pr["wknd"] / days < 0.05
    f["novel_pc"] = bool(v["pcs"] - pr["pcs"])
    return f


def device_features(v, pr):
    days = pr["days"]
    dev_avg = pr["dev_total"] / days
    f = {}
    f["novel_dev_off_hours"] = v["dev_off"] > 0 and pr["dev_off"] / days < 0.05
    f["dev_spike"] = dev_avg > 0 and v["dev"] > 3 * dev_avg
    return f


WEIGHTS = {
    "novel_off_hours": 0.45,
    "novel_weekend": 0.30,
    "novel_pc": 0.50,
    "novel_dev_off_hours": 0.65,
    "dev_spike": 0.30,
}


def score(v, pr, config):
    if not pr or pr["days"] == 0:
        return 0.0
    f = {}
    if config in ("logon", "combined"):
        f.update(logon_features(v, pr))
    if config in ("device", "combined"):
        f.update(device_features(v, pr))
    s = sum(WEIGHTS[k] for k, on in f.items() if on)
    return min(s, 1.0)


# ---------------------------------------------------------------
# Оценка
# ---------------------------------------------------------------
def metrics(rows, cutoff):
    tp = fn = fp = tn = 0
    caught, total = defaultdict(int), defaultdict(int)
    for s, sc in rows:
        alert = s >= cutoff
        bad = sc is not None
        if bad:
            total[sc] += 1
            if alert:
                caught[sc] += 1
        if alert and bad:
            tp += 1
        elif not alert and bad:
            fn += 1
        elif alert:
            fp += 1
        else:
            tn += 1
    prec = tp / (tp + fp) if (tp + fp) else 0.0
    rec = tp / (tp + fn) if (tp + fn) else 0.0
    f1 = 2 * prec * rec / (prec + rec) if (prec + rec) else 0.0
    fpr = fp / (fp + tn) if (fp + tn) else 0.0
    return {"TP": tp, "FN": fn, "FP": fp, "TN": tn,
            "precision": round(prec, 4), "recall": round(rec, 4),
            "f1": round(f1, 4), "fpr": round(fpr, 5)}, caught, total


def pick_cutoff(rows, target_fpr):
    """Наибольший recall при FPR не выше целевого."""
    cand = sorted({round(s, 2) for s, _ in rows})
    best = None
    for c in cand:
        m, _, _ = metrics(rows, c)
        if m["fpr"] <= target_fpr:
            if best is None or m["recall"] > best[1]["recall"]:
                best = (c, m)
    return best if best else (1.01, metrics(rows, 1.01)[0])


def main():
    print("Загрузка CERT r4.2...")
    windows = load_labels()
    ud = load_events()
    days = sorted({d for _, d in ud})
    split = days[0] + timedelta(days=BASELINE_DAYS)
    prof = build_profiles(ud, split)

    print(f"  пользователей:         {len({u for u, _ in ud})}")
    print(f"  пар пользователь-день: {len(ud)}")
    print(f"  период:                {days[0]} — {days[-1]}")
    print(f"  обучающий период:      первые {BASELINE_DAYS} дней (до {split})")
    print(f"  инсайдеров в разметке: {len(windows)}")

    test_keys = [(u, d) for (u, d) in ud if d >= split]
    labels = {k: scenario_of(windows, k[0], k[1]) for k in test_keys}
    mal = sum(1 for k in test_keys if labels[k])
    print(f"  тестовых дней:         {len(test_keys)}, "
          f"вредоносных {mal} ({100 * mal / len(test_keys):.2f}%)\n")

    print(f"Сравнение при фиксированном уровне ложных тревог "
          f"(FPR не выше {TARGET_FPR:.0%})\n")

    out = []
    for config, title in [("logon", "A. только logon"),
                          ("device", "B. только device"),
                          ("combined", "C. logon + device")]:
        rows = [(score(ud[k], prof.get(k[0]), config), labels[k])
                for k in test_keys]
        cutoff, m = pick_cutoff(rows, TARGET_FPR)
        _, caught, total = metrics(rows, cutoff)

        print(f"{title}   (порог {cutoff})")
        print(f"  TP {m['TP']:>4}   FN {m['FN']:>5}   FP {m['FP']:>5}   "
              f"precision {m['precision']:.3f}   recall {m['recall']:.3f}   "
              f"FPR {m['fpr']:.4f}")
        row = {"config": config, "cutoff": cutoff, **m}
        for sc in sorted(total):
            pct = 100 * caught[sc] / total[sc]
            print(f"    сценарий {sc} ({SCENARIO_NAMES[sc]}): "
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
