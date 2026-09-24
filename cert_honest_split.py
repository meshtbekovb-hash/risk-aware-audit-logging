"""
ЧЕСТНОЕ РАЗБИЕНИЕ НА ТРИ ЧАСТИ: обучение / валидация / тест

Зачем. Прежние веса и пороги признаков подбирались с оглядкой на метрики
по всему периоду, включая тест. Значит, результаты в cert_ablation.py
оптимистично смещены. Здесь веса и порог подбираются ТОЛЬКО на валидационной
части, а отчёт делается на тестовой части, которую подбор не видел.

Три части по времени (строго хронологически):
  обучение   до 2010-05-02          - профили пользователей (как раньше)
  валидация  2010-05-02 .. 2010-10-01 - здесь подбираем веса и порог
  тест       с 2010-10-01          - используется один раз для отчёта

Инсайдер относится к валидации или тесту по дате НАЧАЛА окна атаки
(по 35 человек в каждой части).

Что подбираем: веса пяти признаков (значения 0.1 ... 1.0 с шагом 0.1) и порог.
Цель подбора: максимальная ПОЛНОТА в среднем по трём сценариям при FPR не выше 1%.
Среднее по сценариям взято потому, что дневная полнота иначе определяется
сценарием 2 (87% вредоносных дней).

Что НЕ подбираем и честно оговариваем: сами признаки и их пороги новизны
(10%, 5%, втрое, ...). Они выбирались раньше, с оглядкой на данные всего
периода, так что часть смещения остаётся. Сравнение "ручные веса" против
"веса с валидации" показывает, сколько давал именно подбор весов.

Ускорение. Оценка риска зависит только от того, какие из пяти признаков
сработали, то есть от одного из 32 шаблонов. Поэтому считаем, сколько
обычных и вредоносных дней приходится на каждый шаблон, и перебор весов
идёт по этим счётчикам, а не по 245 тысячам дней.

Результат: honest_split_results.csv
Запуск (из папки с CSV):  python cert_honest_split.py
"""

import csv
from datetime import date, timedelta
from itertools import product
from collections import defaultdict

import cert_ablation as ab

OUTPUT_FILE = "honest_split_results.csv"
VAL_START = None                      # задаётся в main: конец обучающего периода
TEST_START = date(2010, 10, 1)        # начало тестовой части

FEATURES = ["novel_off_hours", "novel_weekend", "novel_pc",
            "novel_dev_off_hours", "dev_spike"]
CONFIG_FEATURES = {
    "logon": ["novel_off_hours", "novel_weekend", "novel_pc"],
    "device": ["novel_dev_off_hours", "dev_spike"],
    "combined": FEATURES,
}
GRID = [round(0.1 * i, 1) for i in range(1, 11)]      # 0.1 ... 1.0
SCENARIOS = ["1", "2", "3"]


def day_pattern(v, pr):
    """Шаблон дня: кортеж из 5 значений True/False по порядку FEATURES."""
    if not pr or pr["days"] == 0:
        return (False,) * len(FEATURES)
    f = {**ab.logon_features(v, pr), **ab.device_features(v, pr)}
    return tuple(bool(f[name]) for name in FEATURES)


def count_patterns(keys, ud, prof, windows):
    """
    Для каждого шаблона считаем: сколько обычных дней и сколько вредоносных
    по сценариям. Возвращает (счётчики, всего обычных, всего вредоносных по сценариям).
    """
    cnt = defaultdict(lambda: {"normal": 0, "1": 0, "2": 0, "3": 0})
    for k in keys:
        pat = day_pattern(ud[k], prof.get(k[0]))
        sc = ab.scenario_of(windows, k[0], k[1])
        cnt[pat][sc if sc else "normal"] += 1
    total = {"normal": sum(c["normal"] for c in cnt.values())}
    for s in SCENARIOS:
        total[s] = sum(c[s] for c in cnt.values())
    return cnt, total


def pattern_score(pat, weights, used):
    """Оценка риска шаблона: сумма весов сработавших признаков из used, максимум 1."""
    s = sum(weights[name] for name, on in zip(FEATURES, pat) if on and name in used)
    return min(s, 1.0)


def best_cutoff(cnt, total, weights, used, target_fpr):
    """
    Для заданных весов ищем порог с наибольшей средней по сценариям полнотой
    при FPR не выше target_fpr. Возвращает (цель, порог) или (-1, None).
    """
    scored = defaultdict(lambda: {"normal": 0, "1": 0, "2": 0, "3": 0})
    for pat, c in cnt.items():
        s = round(pattern_score(pat, weights, used), 2)
        for key in c:
            scored[s][key] += c[key]
    best = (-1.0, None)
    for cutoff in sorted(scored):
        if cutoff <= 0:
            continue                       # порог 0 означает "тревога на каждый день"
        alerted = {"normal": 0, "1": 0, "2": 0, "3": 0}
        for s, c in scored.items():
            if s >= cutoff:
                for key in alerted:
                    alerted[key] += c[key]
        if alerted["normal"] / total["normal"] > target_fpr:
            continue
        recalls = [alerted[s] / total[s] for s in SCENARIOS if total[s] > 0]
        goal = sum(recalls) / len(recalls)
        if goal > best[0]:
            best = (goal, cutoff)
    return best


def tune_weights(cnt, total, used):
    """Перебор всех комбинаций весов из сетки. Возвращает (цель, порог, веса)."""
    best = (-1.0, None, None)
    for combo in product(GRID, repeat=len(used)):
        weights = dict(zip(used, combo))
        goal, cutoff = best_cutoff(cnt, total, weights, used, ab.TARGET_FPR)
        if goal > best[0]:
            best = (goal, cutoff, weights)
    return best


def evaluate(keys, ud, prof, windows, weights, used, cutoff, info):
    """
    Отчёт на тестовой части: по дням и по инсайдерам.
    info - {пользователь: (сценарий, дата начала)} только для инсайдеров этой части.
    """
    tp = fp = fn = tn = 0
    caught_days = {s: 0 for s in SCENARIOS}
    total_days = {s: 0 for s in SCENARIOS}
    first_alert, false_users = set(), set()
    for k in keys:
        pat = day_pattern(ud[k], prof.get(k[0]))
        alert = round(pattern_score(pat, weights, used), 2) >= cutoff
        sc = ab.scenario_of(windows, k[0], k[1])
        if sc:
            total_days[sc] += 1
            if alert:
                caught_days[sc] += 1
                tp += 1
                if k[0] in info:
                    first_alert.add(k[0])
            else:
                fn += 1
        elif alert:
            fp += 1
            if k[0] not in windows:
                false_users.add(k[0])
        else:
            tn += 1
    caught_ins = {s: sum(1 for u in first_alert if info[u][0] == s) for s in SCENARIOS}
    total_ins = {s: sum(1 for v in info.values() if v[0] == s) for s in SCENARIOS}
    return {
        "TP": tp, "FN": fn, "FP": fp, "TN": tn,
        "precision": round(tp / (tp + fp), 4) if tp + fp else 0.0,
        "recall": round(tp / (tp + fn), 4) if tp + fn else 0.0,
        "fpr": round(fp / (fp + tn), 5),
        "macro_recall": round(sum(caught_days[s] / total_days[s]
                                  for s in SCENARIOS if total_days[s]) /
                              sum(1 for s in SCENARIOS if total_days[s]), 4),
        "insiders_caught": sum(caught_ins.values()),
        "insiders_total": sum(total_ins.values()),
        "caught_by_scenario": caught_ins, "total_by_scenario": total_ins,
        "false_users": len(false_users),
    }


def main():
    windows = ab.load_labels()
    ud = ab.load_events()
    days = sorted({d for _, d in ud})
    train_end = days[0] + timedelta(days=ab.BASELINE_DAYS)
    prof = ab.build_profiles(ud, train_end)

    val_keys = [k for k in ud if train_end <= k[1] < TEST_START]
    test_keys = [k for k in ud if k[1] >= TEST_START]
    starts = {u: (min(w, key=lambda x: x[1])[0], min(x[1] for x in w))
              for u, w in windows.items()}
    ins_test = {u: v for u, v in starts.items() if v[1] >= TEST_START}
    ins_val = {u: v for u, v in starts.items() if v[1] < TEST_START}

    print(f"обучение: до {train_end}; валидация: до {TEST_START}; тест: с {TEST_START}")
    print(f"валидация: {len(val_keys)} дней, инсайдеров {len(ins_val)}")
    print(f"тест:      {len(test_keys)} дней, инсайдеров {len(ins_test)}\n")

    cnt_val, tot_val = count_patterns(val_keys, ud, prof, windows)
    print(f"вредоносных дней на валидации: { {s: tot_val[s] for s in SCENARIOS} }, "
          f"обычных {tot_val['normal']}\n")

    hand = dict(ab.WEIGHTS)
    out = []
    for config in ["logon", "device", "combined"]:
        used = CONFIG_FEATURES[config]
        print(f"=== {config} ===")
        # 1. Ручные (прежние) веса: порог всё равно выбираем только на валидации
        _, cut_hand = best_cutoff(cnt_val, tot_val, hand, used, ab.TARGET_FPR)
        # 2. Веса, подобранные на валидации
        goal, cut_tuned, w_tuned = tune_weights(cnt_val, tot_val, used)
        print(f"  веса с валидации: {w_tuned}, порог {cut_tuned}, "
              f"средняя полнота по сценариям на валидации {goal:.3f}")

        for name, weights, cutoff in [("ручные веса", hand, cut_hand),
                                      ("веса с валидации", w_tuned, cut_tuned)]:
            if cutoff is None:
                print(f"  {name}: порог при FPR<=1% не найден")
                continue
            m = evaluate(test_keys, ud, prof, windows, weights, used, cutoff, ins_test)
            cs, ts = m["caught_by_scenario"], m["total_by_scenario"]
            print(f"  {name:17} порог {cutoff}: TEST recall {m['recall']:.3f} "
                  f"(по сценариям в среднем {m['macro_recall']:.3f}), "
                  f"precision {m['precision']:.3f}, FPR {m['fpr']:.4f}; "
                  f"инсайдеров {m['insiders_caught']}/{m['insiders_total']} "
                  f"(сц.1 {cs['1']}/{ts['1']}, сц.2 {cs['2']}/{ts['2']}, "
                  f"сц.3 {cs['3']}/{ts['3']}); ложно затронуто {m['false_users']}")
            out.append({"config": config, "weights": name, "cutoff": cutoff,
                        **{k: v for k, v in m.items() if not k.endswith("_by_scenario")},
                        "tuned_weights": str(weights)})
        print()

    with open(OUTPUT_FILE, "w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=list(out[0].keys()))
        w.writeheader()
        w.writerows(out)
    print(f"Таблица сохранена: {OUTPUT_FILE}")


if __name__ == "__main__":
    main()
