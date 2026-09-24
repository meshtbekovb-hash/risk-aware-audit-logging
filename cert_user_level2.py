"""
ОЦЕНКА ПО ПОЛЬЗОВАТЕЛЯМ ПРИ РАВНОМ user-FPR, доверительные интервалы,
разбор ложных тревог и потерянных инсайдеров, гибридное правило

Дневной расчёт и разбиение (обучение до 2010-05-02, валидация до 2010-10-01,
тест с 2010-10-01) НЕ меняются. Используем функции из cert_honest_split.py
и cert_user_level.py.

ЖЁСТКОЕ ПРАВИЛО ПРО ТЕСТ: все параметры (порог риска, N, W, H) выбираются
только по валидации. В коде на тест вызывается уже выбранная комбинация,
перебор на тесте не выполняется.

Что считаем:
  1. Главная таблица при равном user-FPR: целевой user-FPR = 3%. Для каждой
     конфигурации на ВАЛИДАЦИИ выбираем порог риска и (N, W) с наибольшим
     user-recall при user-FPR не выше 3% (при равном recall берём точку с FPR
     ближе к 3%). Затем один раз считаем результат на тесте.
  2. Интервалы Уилсона 95% для user-recall (n=35) и сравнение пар конфигураций:
     по перекрытию интервалов и точным парным тестом знаков (одни и те же
     инсайдеры, поэтому сравнение парное).
  3. Кто ложно помечен: распределение по признакам, концентрация тревог.
  4. Какие инсайдеры теряются при лучшей конфигурации.
  5. Гибридное правило: (N тревожных дней в окне W) ИЛИ (один день с оценкой
     не ниже высокого порога H). Все параметры - по валидации.

Результат: user_level2_results.csv
Запуск (из папки с CSV):  python cert_user_level2.py
"""

import csv
from math import comb, sqrt
from itertools import combinations
from datetime import timedelta
from statistics import median
from collections import defaultdict

import cert_ablation as ab
import cert_honest_split as hs
import cert_user_level as ul

OUTPUT_FILE = "user_level2_results.csv"
TARGET_FPR = 0.03
N_VALUES = ul.N_VALUES
W_VALUES = ul.W_VALUES
CONFIGS = [("logon", "logon"), ("device", "device"), ("logon+device", "combined")]


# ---------------------------------------------------------------
# Статистика
# ---------------------------------------------------------------
def wilson(k, n, z=1.96):
    """Доверительный интервал Уилсона 95% для доли k/n."""
    p = k / n
    d = 1 + z * z / n
    center = (p + z * z / (2 * n)) / d
    half = z * sqrt(p * (1 - p) / n + z * z / (4 * n * n)) / d
    return center - half, center + half


def sign_test(b, c):
    """
    Точный парный тест знаков. b - инсайдеров поймала только конфигурация A,
    c - только B. Нулевая гипотеза: обе ловят одинаково (вероятность 1/2).
    Возвращает двусторонний p-value.
    """
    m = b + c
    if m == 0:
        return 1.0
    k = min(b, c)
    return min(1.0, 2 * sum(comb(m, i) for i in range(k + 1)) / 2 ** m)


# ---------------------------------------------------------------
# Оценка правила по пользователям
# ---------------------------------------------------------------
def fired(alerts_u, n, w, high_u=None):
    """
    Дни срабатывания правила для одного пользователя.
    Накопление: не менее N тревожных дней в окне W дней.
    Гибрид: плюс любой день с оценкой не ниже высокого порога H (high_u).
    """
    days = ul.firing_days(alerts_u, n, w)
    if high_u:
        return sorted(set(days) | set(high_u))
    return days


def evaluate(alerts, high, insiders, normal, n, w):
    """user-recall, user-FPR и множества пойманных инсайдеров и ложных пользователей."""
    caught, by_sc, total_sc = set(), defaultdict(int), defaultdict(int)
    for u, (sc, start, end) in insiders.items():
        total_sc[sc] += 1
        hi = high.get(u) if high else None
        if any(start <= t <= end for t in fired(alerts.get(u, []), n, w, hi)):
            caught.add(u)
            by_sc[sc] += 1
    false_users = {u for u in normal
                   if fired(alerts.get(u, []), n, w, high.get(u) if high else None)}
    return {"caught": caught, "false": false_users,
            "recall": len(caught) / len(insiders), "fpr": len(false_users) / len(normal),
            "by_sc": dict(by_sc), "total_sc": dict(total_sc)}


def score_levels(used):
    """
    Все возможные значения оценки риска для набора признаков: суммы весов по всем
    подмножествам, максимум 1. Считаются только из весов, от данных не зависят.
    """
    names = [f for f in hs.FEATURES if f in used]
    levels = set()
    for r in range(1, len(names) + 1):
        for sub in combinations(names, r):
            levels.add(round(min(sum(ab.WEIGHTS[x] for x in sub), 1.0), 2))
    return sorted(levels)


class Setup:
    """Данные: шаблоны дней, части (валидация/тест), тревожные дни по порогам."""

    def __init__(self):
        self.windows = ab.load_labels()
        self.ud = ab.load_events()
        days = sorted({d for _, d in self.ud})
        self.train_end = days[0] + timedelta(days=ab.BASELINE_DAYS)
        self.prof = ab.build_profiles(self.ud, self.train_end)
        info = {u: min(w, key=lambda x: x[1]) for u, w in self.windows.items()}
        self.parts = {
            "валидация": ([k for k in self.ud if self.train_end <= k[1] < hs.TEST_START],
                          {u: v for u, v in info.items() if v[1] < hs.TEST_START}),
            "тест": ([k for k in self.ud if k[1] >= hs.TEST_START],
                     {u: v for u, v in info.items() if v[1] >= hs.TEST_START}),
        }
        self.normal = {name: {k[0] for k in keys} - set(self.windows)
                       for name, (keys, _) in self.parts.items()}
        # Шаблон каждого дня считаем один раз
        self.pattern = {k: hs.day_pattern(self.ud[k], self.prof.get(k[0]))
                        for keys, _ in self.parts.values() for k in keys}
        self._cache = {}

    def alerts(self, part, used, cutoff):
        """Тревожные дни по пользователям для части, набора признаков и порога (с кэшем)."""
        key = (part, tuple(used), cutoff)
        if key not in self._cache:
            days = defaultdict(list)
            for k in self.parts[part][0]:
                s = round(hs.pattern_score(self.pattern[k], ab.WEIGHTS, used), 2)
                if s >= cutoff:
                    days[k[0]].append(k[1])
            for u in days:
                days[u].sort()
            self._cache[key] = days
        return self._cache[key]

    def run(self, part, used, cutoff, n, w, high_level=None):
        """Оценка правила на части. high_level - порог H для гибрида (или None)."""
        a = self.alerts(part, used, cutoff)
        h = self.alerts(part, used, high_level) if high_level else None
        return evaluate(a, h, self.parts[part][1], self.normal[part], n, w)


def select_on_validation(st, used, hybrid):
    """
    Перебор на ВАЛИДАЦИИ: порог риска, (N, W) и для гибрида порог H.
    Правило выбора: наибольший user-recall при user-FPR не выше TARGET_FPR,
    при равном recall - FPR ближе к целевому.
    Возвращает (параметры, результат на валидации) или None.
    """
    levels = score_levels(used)
    best = None
    for cutoff in levels:
        highs = [None] + ([h for h in levels if h > cutoff] if hybrid else [])
        for n in N_VALUES:
            for w in W_VALUES:
                for h in highs:
                    r = st.run("валидация", used, cutoff, n, w, h)
                    if r["fpr"] > TARGET_FPR:
                        continue
                    key = (r["recall"], r["fpr"])
                    if best is None or key > best[0]:
                        best = (key, {"cutoff": cutoff, "N": n, "W": w, "H": h}, r)
    return (best[1], best[2]) if best else None


def fmt_ci(k, n):
    lo, hi = wilson(k, n)
    return f"{100 * k / n:4.1f}% [{100 * lo:4.1f}; {100 * hi:4.1f}]"


def main():
    print("Загрузка...")
    st = Setup()
    print(f"валидация: инсайдеров {len(st.parts['валидация'][1])}, "
          f"неинсайдеров {len(st.normal['валидация'])}")
    print(f"тест:      инсайдеров {len(st.parts['тест'][1])}, "
          f"неинсайдеров {len(st.normal['тест'])}")
    print(f"Целевой user-FPR: не выше {TARGET_FPR:.0%} на валидации. "
          f"Ограничение на тесте НЕ навязывается, фактический FPR печатается как есть.\n")

    # ------------------------------------------------------------
    # Задача 1 + 2: главная таблица и интервалы
    # ------------------------------------------------------------
    print("=" * 100)
    print("ЗАДАЧА 1. Главная таблица: user-FPR не выше 3% (выбор по валидации)")
    print("=" * 100)
    chosen, test_res, rows = {}, {}, []
    for name, cfg in CONFIGS:
        used = hs.CONFIG_FEATURES[cfg]
        sel = select_on_validation(st, used, hybrid=False)
        if sel is None:
            print(f"{name}: на валидации нет правила с user-FPR не выше 3%")
            continue
        p, v = sel
        t = st.run("тест", used, p["cutoff"], p["N"], p["W"])          # тест: один раз
        chosen[name], test_res[name] = p, t
        n_ins = len(st.parts["тест"][1])
        print(f"{name:13} порог {p['cutoff']:<4} N={p['N']} W={p['W']:>2} | валидация: "
              f"{len(v['caught'])}/35 FPR {100 * v['fpr']:.1f}% | ТЕСТ: "
              f"recall {len(t['caught'])}/{n_ins} {fmt_ci(len(t['caught']), n_ins)}, "
              f"FPR {100 * t['fpr']:.1f}% ({len(t['false'])} из {len(st.normal['тест'])})")
        rows.append({"table": "main", "config": name, **p,
                     "val_recall": round(v["recall"], 4), "val_fpr": round(v["fpr"], 4),
                     "test_caught": len(t["caught"]), "test_total": n_ins,
                     "test_recall": round(t["recall"], 4), "test_fpr": round(t["fpr"], 4),
                     "test_false_users": len(t["false"])})

    print("\nЗАДАЧА 2. Сравнение конфигураций (интервалы Уилсона и парный тест знаков)")
    names = list(test_res)
    for i in range(len(names)):
        for j in range(i + 1, len(names)):
            a, b = test_res[names[i]], test_res[names[j]]
            only_a, only_b = len(a["caught"] - b["caught"]), len(b["caught"] - a["caught"])
            lo_a, hi_a = wilson(len(a["caught"]), 35)
            lo_b, hi_b = wilson(len(b["caught"]), 35)
            overlap = max(lo_a, lo_b) <= min(hi_a, hi_b)
            p = sign_test(only_a, only_b)
            verdict = "различие значимо" if p < 0.05 else "различие НЕ значимо"
            print(f"  {names[i]} против {names[j]}: интервалы "
                  f"{'перекрываются' if overlap else 'не перекрываются'}; только первая "
                  f"поймала {only_a}, только вторая {only_b}; p = {p:.4f} -> {verdict}")

    if not chosen:
        return
    # Лучшая конфигурация ПО ВАЛИДАЦИИ (не по тесту)
    best_name = max(chosen, key=lambda n: (
        st.run("валидация", hs.CONFIG_FEATURES[dict(CONFIGS)[n]], chosen[n]["cutoff"],
               chosen[n]["N"], chosen[n]["W"])["recall"], n == "device"))
    bp, used = chosen[best_name], hs.CONFIG_FEATURES[dict(CONFIGS)[best_name]]
    print(f"\nЛучшая по валидации: {best_name} (порог {bp['cutoff']}, N={bp['N']}, W={bp['W']})")

    # ------------------------------------------------------------
    # Задача 3: кто ложно помечен
    # ------------------------------------------------------------
    print("\n" + "=" * 100)
    print("ЗАДАЧА 3. Ложно помеченные пользователи (тест, только описание, ничего не подбирается)")
    print("=" * 100)
    feat_names = [f for f in hs.FEATURES if f in used]
    for label, n, w in [(f"N=1 (любая тревога), порог {bp['cutoff']}", 1, 7),
                        (f"выбранное правило N={bp['N']}, W={bp['W']}", bp["N"], bp["W"])]:
        r = st.run("тест", used, bp["cutoff"], n, w)
        alerts = st.alerts("тест", used, bp["cutoff"])
        per_user = sorted((len(alerts.get(u, [])) for u in r["false"]), reverse=True)
        total_days = sum(per_user)
        top = max(1, len(per_user) // 10)
        print(f"\n{label}: ложно помечено {len(r['false'])} из {len(st.normal['тест'])}")
        if not per_user:
            continue
        print(f"  тревожных дней на такого пользователя: медиана {median(per_user)}, "
              f"максимум {per_user[0]}, всего {total_days}; "
              f"на долю верхних 10% пользователей ({top} чел.) приходится "
              f"{100 * sum(per_user[:top]) / total_days:.0f}% тревожных дней")
        # По каким признакам срабатывали тревоги у этих людей
        feat_days = defaultdict(int)
        dominant = defaultdict(int)
        for u in r["false"]:
            counts = defaultdict(int)
            for d in alerts.get(u, []):
                f = {**ab.logon_features(st.ud[(u, d)], st.prof.get(u)),
                     **ab.device_features(st.ud[(u, d)], st.prof.get(u))} \
                    if st.prof.get(u) and st.prof[u]["days"] else {}
                for name in feat_names:
                    if f.get(name):
                        feat_days[name] += 1
                        counts[name] += 1
            if counts:
                dominant[max(counts, key=counts.get)] += 1
        print("  тревожных дней по признакам (день может содержать несколько признаков): "
              + ", ".join(f"{k} {feat_days[k]}" for k in feat_names))
        print("  пользователей по главному признаку: "
              + ", ".join(f"{k} {dominant[k]}" for k in feat_names))
        # Сравнение с остальными по обычному использованию флешки на обучении
        def usage(u):
            p = st.prof.get(u)
            return p["dev_total"] / p["days"] if p and p["days"] else 0.0
        rest = [u for u in st.normal["тест"] if u not in r["false"]]
        print(f"  среднее число подключений носителя в день на обучении: ложно помеченные "
              f"{median(usage(u) for u in r['false']):.2f} (медиана), остальные "
              f"{median(usage(u) for u in rest):.2f}")
    print("\nLDAP в папке нет, сопоставить роль или отдел нельзя. Описано только распределение по признакам.")

    # ------------------------------------------------------------
    # Задача 4: какие инсайдеры теряются
    # ------------------------------------------------------------
    print("\n" + "=" * 100)
    print(f"ЗАДАЧА 4. Потерянные инсайдеры, {best_name} (тест)")
    print("=" * 100)
    t = test_res[best_name]
    alerts = st.alerts("тест", used, bp["cutoff"])
    missed = [(u, v) for u, v in st.parts["тест"][1].items() if u not in t["caught"]]
    by_sc = defaultdict(list)
    for u, (sc, start, end) in sorted(missed, key=lambda x: (x[1][0], x[0])):
        in_win = [d for d in alerts.get(u, []) if start <= d <= end]
        why = ("ни одного тревожного дня в окне атаки" if not in_win else
               f"{len(in_win)} тревожных дн. в окне, но правилу N={bp['N']}, W={bp['W']} мало")
        by_sc[sc].append(u)
        print(f"  сценарий {sc}, {u}: окно {start}..{end} ({(end - start).days + 1} дн.): {why}")
    print("  итого потеряно по сценариям: " +
          ", ".join(f"сц.{s}: {len(by_sc[s])} из {t['total_sc'][s]}" for s in sorted(t["total_sc"])))

    # ------------------------------------------------------------
    # Задача 5: гибридное правило
    # ------------------------------------------------------------
    print("\n" + "=" * 100)
    print("ЗАДАЧА 5. Гибрид: N тревожных дней в окне W ИЛИ один день с оценкой не ниже H")
    print("=" * 100)
    for name, cfg in CONFIGS:
        used_c = hs.CONFIG_FEATURES[cfg]
        sel = select_on_validation(st, used_c, hybrid=True)
        if sel is None:
            print(f"{name}: гибрид не найден при user-FPR не выше 3% на валидации")
            continue
        p, v = sel
        t = st.run("тест", used_c, p["cutoff"], p["N"], p["W"], p["H"])
        plain = test_res.get(name)
        sc = ", ".join(f"сц.{s}: {t['by_sc'].get(s, 0)}/{t['total_sc'][s]}" for s in sorted(t["total_sc"]))
        print(f"{name:13} порог {p['cutoff']}, N={p['N']}, W={p['W']}, H={p['H'] if p['H'] else 'нет (гибрид не улучшает)'} | валидация "
              f"{len(v['caught'])}/35 FPR {100 * v['fpr']:.1f}% | ТЕСТ recall {len(t['caught'])}/35 "
              f"{fmt_ci(len(t['caught']), 35)}, FPR {100 * t['fpr']:.1f}% | {sc}")
        if plain:
            ps = ", ".join(f"сц.{s}: {plain['by_sc'].get(s, 0)}/{plain['total_sc'][s]}" for s in sorted(plain["total_sc"]))
            print(f"{'':13} без гибрида: recall {len(plain['caught'])}/35, FPR {100 * plain['fpr']:.1f}% | {ps}")
        rows.append({"table": "hybrid", "config": name, **p,
                     "val_recall": round(v["recall"], 4), "val_fpr": round(v["fpr"], 4),
                     "test_caught": len(t["caught"]), "test_total": 35,
                     "test_recall": round(t["recall"], 4), "test_fpr": round(t["fpr"], 4),
                     "test_false_users": len(t["false"])})

    fields = ["table", "config", "cutoff", "N", "W", "H", "val_recall", "val_fpr", "test_caught",
              "test_total", "test_recall", "test_fpr", "test_false_users"]
    with open(OUTPUT_FILE, "w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=fields)
        w.writeheader()
        for r in rows:
            r.setdefault("H", "")
            w.writerow(r)
    print(f"\nТаблица сохранена: {OUTPUT_FILE}")


if __name__ == "__main__":
    main()
