"""
НЕЗАВИСИМАЯ ПРОВЕРКА ГЛАВНЫХ ЦИФР (аудит)

Этот скрипт НЕ импортирует ни один из наших модулей. Он заново читает сырые CSV и
пересчитывает главные цифры проекта по описанию методики (CLAUDE.md, раздел 4),
другим кодом и другим способом. Если цифры совпадают с основными скриптами, значит
в коде нет случайных ошибок. Методологические решения (признаки, пороги, веса)
это, конечно, НЕ проверяет: они одинаковы по построению.

Отличия от основного кода: даты разбираются срезом строки, а не strptime; окно накопления
считается прямым перебором, а не двумя указателями; счётчики ведутся отдельно.

Проверяем:
  1. Дневные метрики device (порог 0.30) по всему периоду после обучения
     (эталон из cert_ablation.py: TP 211, FN 1153, FP 2362).
  2. user-level recall и FPR на тесте для четырёх рабочих точек.
  3. Точные значения теста знаков и интервала Уилсона другим способом.
  4. Служебные проверки: сколько инсайдеров имеют несколько окон атаки, границы периодов.

Запуск (из папки с CSV):  python audit_independent.py
"""

import csv
from collections import defaultdict
from datetime import date, timedelta
from fractions import Fraction
from math import comb, sqrt


def parse(stamp):
    """'01/02/2010 07:23:14' -> (дата, час). Разбор срезом строки, без strptime."""
    return date(int(stamp[6:10]), int(stamp[0:2]), int(stamp[3:5])), int(stamp[11:13])


# ---------------- чтение данных ----------------
day = defaultdict(lambda: {"off": 0, "wknd": 0, "pcs": set(), "dev": 0, "dev_off": 0})

with open("logon.csv", encoding="utf-8") as f:
    for r in csv.DictReader(f):
        if r["activity"] != "Logon":
            continue
        d, h = parse(r["date"])
        v = day[(r["user"], d)]
        v["pcs"].add(r["pc"])
        if h < 8 or h >= 18:
            v["off"] += 1
        if d.weekday() >= 5:
            v["wknd"] += 1

with open("device.csv", encoding="utf-8") as f:
    for r in csv.DictReader(f):
        if r["activity"] != "Connect":
            continue
        d, h = parse(r["date"])
        v = day[(r["user"], d)]
        v["dev"] += 1
        if h < 8 or h >= 18:
            v["dev_off"] += 1

windows = defaultdict(list)          # инсайдер -> список (сценарий, начало, конец)
with open("insiders.csv", encoding="utf-8") as f:
    for r in csv.DictReader(f):
        if r["dataset"] != "4.2":
            continue
        windows[r["user"]].append((r["scenario"], parse(r["start"])[0], parse(r["end"])[0]))

first_day = min(d for _, d in day)
TRAIN_END = first_day + timedelta(days=120)
TEST_START = date(2010, 10, 1)
print(f"первый день данных {first_day}, конец обучения {TRAIN_END}, начало теста {TEST_START}")

# ---------------- профили по обучающему периоду ----------------
prof = defaultdict(lambda: {"days": 0, "off": 0, "wknd": 0, "dev_off": 0, "dev_total": 0, "pcs": set()})
for (u, d), v in day.items():
    if d < TRAIN_END:
        p = prof[u]
        p["days"] += 1
        p["dev_total"] += v["dev"]
        p["pcs"] |= v["pcs"]
        p["off"] += v["off"] > 0
        p["wknd"] += v["wknd"] > 0
        p["dev_off"] += v["dev_off"] > 0

W_OFF, W_WKND, W_PC, W_DEVOFF, W_SPIKE = 0.45, 0.30, 0.50, 0.65, 0.30


def score(u, d, kinds):
    """Оценка риска дня. kinds: множество из 'logon', 'device'."""
    p, v = prof.get(u), day[(u, d)]
    if not p or p["days"] == 0:
        return 0.0
    s = 0.0
    if "logon" in kinds:
        s += W_OFF * (v["off"] > 0 and p["off"] / p["days"] < 0.10)
        s += W_WKND * (v["wknd"] > 0 and p["wknd"] / p["days"] < 0.05)
        s += W_PC * (len(v["pcs"] - p["pcs"]) > 0)
    if "device" in kinds:
        s += W_DEVOFF * (v["dev_off"] > 0 and p["dev_off"] / p["days"] < 0.05)
        avg = p["dev_total"] / p["days"]
        s += W_SPIKE * (avg > 0 and v["dev"] > 3 * avg)
    return round(min(s, 1.0), 2)


def is_bad(u, d):
    return any(s <= d <= e for _, s, e in windows.get(u, []))


# ---------------- 1. дневные метрики device 0.30 ----------------
tp = fn = fp = tn = 0
for (u, d) in day:
    if d < TRAIN_END:
        continue
    alert = score(u, d, {"device"}) >= 0.30
    bad = is_bad(u, d)
    tp += alert and bad
    fn += (not alert) and bad
    fp += alert and not bad
    tn += (not alert) and not bad
print(f"\n1. Дневные метрики device, порог 0.30, весь период после обучения")
print(f"   независимый расчёт: TP {tp} FN {fn} FP {fp} TN {tn}, FPR {100 * fp / (fp + tn):.2f}%")
print("   эталон cert_ablation.py: TP 211 FN 1153 FP 2362 (FPR 0.97%)")

# ---------------- 2. user-level ----------------
first_window = {u: min(w, key=lambda x: x[1]) for u, w in windows.items()}
ins_test = {u: w for u, w in first_window.items() if w[1] >= TEST_START}
users_test = {u for (u, d) in day if d >= TEST_START}
normal_test = users_test - set(windows)
print(f"\n2. Тест с {TEST_START}: инсайдеров {len(ins_test)}, обычных пользователей {len(normal_test)}")


def user_level(kinds, cutoff, n, w):
    alerts = defaultdict(list)
    for (u, d) in day:
        if d >= TEST_START and score(u, d, kinds) >= cutoff:
            alerts[u].append(d)
    for u in alerts:
        alerts[u].sort()

    def fires_on(u, t):
        """В день t правило срабатывает: тревожных дней в (t-W, t] не менее N."""
        return sum(1 for x in alerts[u] if 0 <= (t - x).days < w) >= n

    def fired_any(u, lo=None, hi=None):
        return any(fires_on(u, t) for t in alerts.get(u, []) if lo is None or lo <= t <= hi)

    caught = sum(1 for u, (sc, s, e) in ins_test.items() if fired_any(u, s, e))
    false = sum(1 for u in normal_test if fired_any(u))
    return caught, false


cases = [("device 0.65 N=2 W=7", {"device"}, 0.65, 2, 7, "18/35 и 21/888"),
         ("device 0.30 N=1 W=7", {"device"}, 0.30, 1, 7, "33/35 и 108/888"),
         ("logon 0.50 N=4 W=7", {"logon"}, 0.50, 4, 7, "5/35 и 27/888"),
         ("logon+device 0.60 N=3 W=30", {"logon", "device"}, 0.60, 3, 30, "17/35 и 29/888")]
for name, kinds, cut, n, w, ref in cases:
    c, fl = user_level(kinds, cut, n, w)
    print(f"   {name:28} независимо: инсайдеров {c}/35, ложно помечено {fl}/{len(normal_test)}   (основной код: {ref})")

# ---------------- 3. статистика другим способом ----------------
def sign_exact(b, c):
    """Двусторонний точный тест знаков через дроби (без float)."""
    m, k = b + c, min(b, c)
    return float(min(Fraction(1), 2 * Fraction(sum(comb(m, i) for i in range(k + 1)), 2 ** m)))


def wilson_alt(k, n, z=1.96):
    """Интервал Уилсона через решение квадратного уравнения (другая форма записи формулы)."""
    p = k / n
    a = 1 + z * z / n
    b = -(2 * p + z * z / n)
    c = p * p
    disc = sqrt(b * b - 4 * a * c)
    return (-b - disc) / (2 * a), (-b + disc) / (2 * a)


print("\n3. Статистика")
print(f"   тест знаков 4 против 17: p = {sign_exact(4, 17):.4f} (основной код 0.0072)")
print(f"   тест знаков 4 против 16: p = {sign_exact(4, 16):.4f} (основной код 0.0118)")
print(f"   тест знаков 1 против 0:  p = {sign_exact(1, 0):.4f} (основной код 1.0000)")
for k in (18, 17, 5, 33):
    lo, hi = wilson_alt(k, 35)
    print(f"   Уилсон {k}/35: [{100 * lo:.1f}; {100 * hi:.1f}]")
print("   (основной код: 18/35 [35.6; 67.0], 17/35 [33.0; 64.4], 5/35 [6.3; 29.4])")

# ---------------- 4. служебные проверки ----------------
print("\n4. Служебные проверки")
multi = [u for u, w in windows.items() if len(w) > 1]
print(f"   инсайдеров в разметке r4.2: {len(windows)}; с несколькими окнами атаки: {len(multi)}")
straddle = [u for u, (sc, s, e) in first_window.items() if s < TEST_START <= e]
print(f"   инсайдеров, чьё окно пересекает границу валидация/тест: {len(straddle)}")
print(f"   инсайдеров с началом до теста: {sum(1 for w in first_window.values() if w[1] < TEST_START)}, "
      f"с началом в тесте: {len(ins_test)}")
bad_before = sum(1 for (u, d) in day if d < TRAIN_END and is_bad(u, d))
print(f"   вредоносных пар пользователь-день в обучающем периоде: {bad_before}")

# ---------------- 5. risk-aware: доли событий в цепочке ----------------
print("\n5. Risk-aware на тесте: доля событий device в защищённой цепочке")
rows_test = []
with open("device.csv", encoding="utf-8") as f:
    for r in csv.DictReader(f):                     # все записи журнала device (Connect и Disconnect)
        d, _ = parse(r["date"])
        if d >= TEST_START:
            rows_test.append((r["user"], d))
total = len(rows_test)
bad_total = sum(1 for u, d in rows_test if is_bad(u, d))
print(f"   событий device в тесте: {total} (основной код 168392), вредоносных по разметке: {bad_total} (3985)")
for cutoff, ref in [(0.30, "4.29% и 31.8%"), (0.65, "1.47% и 6.6%"), (0.95, "0.14% и 1.6%")]:
    in_chain = sum(1 for u, d in rows_test if score(u, d, {"device"}) >= cutoff)
    bad_prot = sum(1 for u, d in rows_test if is_bad(u, d) and score(u, d, {"device"}) >= cutoff)
    print(f"   порог {cutoff}: в цепочке {100 * in_chain / total:.2f}% событий, защищено "
          f"{100 * bad_prot / bad_total:.1f}% вредоносных (основной код: {ref})")
