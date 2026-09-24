"""
ЗАДАЧА 4 REVISION_PLAN.md: ЧУВСТВИТЕЛЬНОСТЬ К ВЕСАМ И ВКЛАД ПРИЗНАКОВ

Ревью спрашивает: откуда веса 0.45/0.30/0.50/0.65/0.30 и как сильно от них зависит
результат? Здесь тот же протокол, что в cert_user_level2.py (обучение до 2010-05-02 -
профили; валидация до 2010-10-01 - подбор tau/N/W при user FPR <= 3%; тест с
2010-10-01 - один прогон), но вместо наших весов подставляются альтернативы.

ЧТО ЗАМОРОЖЕНО (не меняется): 5 признаков и их пороги новизны (10%/5%/5%/x3, код
cert_ablation.py), разбиение обучение/валидация/тест, правило "recall при user FPR
<= 3%" для выбора (tau, N, W). МЕНЯЕТСЯ только сама комбинация признаков (веса) -
это и есть предмет задачи.

Варианты:
  1. НАШИ ВЕСА (как сейчас) - ab.WEIGHTS, для сверки должно совпасть с
     user_level2_results.csv.
  2. РАВНЫЕ ВЕСА - каждому признаку конфигурации 1/n (n - число признаков), чтобы
     максимум (все признаки сработали) остался 1, как в исходной формуле.
  3. КАЖДЫЙ ПРИЗНАК ОТДЕЛЬНО - однопризнаковый детектор, вес 1.0, остальные признаки
     не используются вовсе.
  4. ABLATION - убрать один признак, у оставшихся веса НЕ меняются (наши исходные).
  5. ЛОГИСТИЧЕСКАЯ РЕГРЕССИЯ - те же бинарные признаки, простая статистическая модель
     вместо взвешенной суммы. Обучающий период (первые 120 дней) не подходит: там 0
     вредоносных дней (см. cert_leakcheck.py), логистическую регрессию обучать не на
     чем (вырожденный случай, только один класс). ПОЭТОМУ обучаем на ВАЛИДАЦИИ и
     честно отмечаем: для этого варианта валидация используется дважды - и чтобы
     подобрать коэффициенты, и чтобы выбрать порог/N/W. Это не то же самое, что у
     остальных вариантов (там веса заданы заранее, на валидации выбирается только
     порог) - асимметрия оговорена в отчёте.

Для каждого варианта: user recall с интервалом Уилсона, user FPR (обе версии по
аналогии с cert_user_level2.py - здесь только "по всем", т.к. задача не просит
наблюдаемую популяцию), точный парный тест знаков ПРОТИВ варианта "наши веса" (та
же конфигурация, те же 35 тестовых инсайдеров).

Результат: results_revision/weight_sensitivity.csv
Запуск (из папки с CSV):  python cert_weight_sensitivity.py
"""

import csv
from collections import defaultdict
from itertools import combinations, product
from math import exp

import cert_ablation as ab
import cert_honest_split as hs
import cert_user_level2 as u2

OUTPUT_FILE = "results_revision/weight_sensitivity.csv"
CONFIGS = [("device", "device"), ("logon+device", "combined")]
TARGET_FPR = u2.TARGET_FPR   # 0.03, не меняется
L2 = 1e-6                    # крошечная регуляризация логрегрессии от полного разделения классов


# ---------------------------------------------------------------
# Обобщённый подбор порога/N/W под ПРОИЗВОЛЬНЫЕ веса (та же логика,
# что select_on_validation в cert_user_level2.py, но веса не зашиты)
# ---------------------------------------------------------------
def score_levels_custom(used, weights):
    names = [f for f in hs.FEATURES if f in used]
    levels = set()
    for r in range(1, len(names) + 1):
        for sub in combinations(names, r):
            levels.add(round(min(sum(weights[x] for x in sub), 1.0), 2))
    return sorted(levels)


def alerts_custom(st, part, used, weights, cutoff):
    from collections import defaultdict
    days = defaultdict(list)
    for k in st.parts[part][0]:
        s = round(hs.pattern_score(st.pattern[k], weights, used), 2)
        if s >= cutoff:
            days[k[0]].append(k[1])
    for u in days:
        days[u].sort()
    return days


def run_custom(st, part, used, weights, cutoff, n, w):
    a = alerts_custom(st, part, used, weights, cutoff)
    return u2.evaluate(a, None, st.parts[part][1], st.normal[part], n, w)


def select_on_validation_custom(st, used, weights, target_fpr=TARGET_FPR):
    levels = score_levels_custom(used, weights)
    best = None
    cache = {}
    for cutoff in levels:
        for n in u2.N_VALUES:
            for w in u2.W_VALUES:
                key = (cutoff, n, w)
                if key not in cache:
                    cache[key] = run_custom(st, "валидация", used, weights, cutoff, n, w)
                r = cache[key]
                if r["fpr"] > target_fpr:
                    continue
                score = (r["recall"], r["fpr"])
                if best is None or score > best[0]:
                    best = (score, {"cutoff": cutoff, "N": n, "W": w}, r)
    return (best[1], best[2]) if best else None


# ---------------------------------------------------------------
# Логистическая регрессия (та же бинарные признаки), метод Ньютона (IRLS)
# на агрегированных по шаблону дня счётчиках - точный расчёт, не приближение,
# просто быстрее, чем идти по 100+ тыс. дней по отдельности.
# ---------------------------------------------------------------
def sigmoid(z):
    if z >= 0:
        return 1.0 / (1.0 + exp(-z))
    e = exp(z)
    return e / (1.0 + e)


def aggregate_patterns(st, part, used):
    """Для каждого встретившегося под-шаблона (по признакам used) - (всего дней, вредоносных дней)."""
    from collections import defaultdict
    names = [f for f in hs.FEATURES if f in used]
    idx = [hs.FEATURES.index(f) for f in names]
    cnt = defaultdict(lambda: [0, 0])
    for k in st.parts[part][0]:
        pat = st.pattern[k]
        sub = tuple(pat[i] for i in idx)
        bad = ab.scenario_of(st.windows, k[0], k[1]) is not None
        c = cnt[sub]
        c[0] += 1
        c[1] += 1 if bad else 0
    return names, cnt


def solve_linear(A, b):
    """Решение A x = b методом Гаусса с выбором ведущего элемента. A - список списков, b - список."""
    n = len(A)
    M = [row[:] + [b[i]] for i, row in enumerate(A)]
    for col in range(n):
        piv = max(range(col, n), key=lambda r: abs(M[r][col]))
        if abs(M[piv][col]) < 1e-12:
            M[piv][col] = 1e-12   # вырожденный случай - крошечная защита от деления на ноль
        M[col], M[piv] = M[piv], M[col]
        pv = M[col][col]
        M[col] = [x / pv for x in M[col]]
        for r in range(n):
            if r != col:
                f = M[r][col]
                M[r] = [M[r][j] - f * M[col][j] for j in range(n + 1)]
    return [M[i][n] for i in range(n)]


def fit_logistic(names, cnt, iters=50, l2=L2):
    """
    Взвешенная логистическая регрессия методом Ньютона (IRLS) на агрегированных
    по шаблону данных: theta = [b0, b1..bk] (b0 - свободный член).
    y_j (число вредоносных) из n_j (всего) для шаблона x_j (0/1 по каждому признаку).
    """
    patterns = list(cnt.keys())
    X = [[1.0] + [1.0 if v else 0.0 for v in pat] for pat in patterns]
    n_tot = [cnt[pat][0] for pat in patterns]
    n_bad = [cnt[pat][1] for pat in patterns]
    k = len(names) + 1
    theta = [0.0] * k

    for _ in range(iters):
        p = [sigmoid(sum(theta[j] * X[i][j] for j in range(k))) for i in range(len(X))]
        grad = [0.0] * k
        H = [[0.0] * k for _ in range(k)]
        for i in range(len(X)):
            diff = n_bad[i] - n_tot[i] * p[i]           # d(loglik)/d(linear predictor)
            wgt = n_tot[i] * p[i] * (1 - p[i])
            for a in range(k):
                grad[a] += diff * X[i][a]
                for c in range(k):
                    H[a][c] -= wgt * X[i][a] * X[i][c]
        for a in range(1, k):                            # L2 только на коэффициенты признаков, не на b0
            grad[a] -= l2 * theta[a]
            H[a][a] -= l2
        step = solve_linear(H, grad)                     # H * step = grad  =>  theta -= (-step)
        theta = [theta[j] - step[j] for j in range(k)]
    return theta   # [b0, b_novel_off_hours, ...] в порядке names


def logreg_score_levels(names, theta):
    """Все достижимые значения sigmoid(b0 + b*x) по всем 2^len(names) шаблонам."""
    levels = set()
    for combo in product([0, 1], repeat=len(names)):
        z = theta[0] + sum(theta[i + 1] * combo[i] for i in range(len(names)))
        levels.add(round(sigmoid(z), 4))
    return sorted(levels)


def select_on_validation_logreg(st, used, names, theta, target_fpr=TARGET_FPR):
    levels = logreg_score_levels(names, theta)
    idx = [hs.FEATURES.index(f) for f in names]

    def alerts_for_cutoff(part, cutoff):
        from collections import defaultdict
        days = defaultdict(list)
        for k in st.parts[part][0]:
            pat = st.pattern[k]
            z = theta[0] + sum(theta[i + 1] * (1.0 if pat[idx[i]] else 0.0) for i in range(len(names)))
            if round(sigmoid(z), 4) >= cutoff:
                days[k[0]].append(k[1])
        for u in days:
            days[u].sort()
        return days

    best = None
    for cutoff in levels:
        a_val = alerts_for_cutoff("валидация", cutoff)
        for n in u2.N_VALUES:
            for w in u2.W_VALUES:
                r = u2.evaluate(a_val, None, st.parts["валидация"][1], st.normal["валидация"], n, w)
                if r["fpr"] > target_fpr:
                    continue
                score = (r["recall"], r["fpr"])
                if best is None or score > best[0]:
                    best = (score, {"cutoff": cutoff, "N": n, "W": w}, r)
    if best is None:
        return None
    p, _ = best[1], best[2]
    a_test = alerts_for_cutoff("тест", p["cutoff"])
    t = u2.evaluate(a_test, None, st.parts["тест"][1], st.normal["тест"], p["N"], p["W"])
    return p, best[2], t


# ---------------------------------------------------------------
# Главный проход
# ---------------------------------------------------------------
def main():
    print("Загрузка...")
    st = u2.Setup()
    print(f"валидация: инсайдеров {len(st.parts['валидация'][1])}, "
          f"неинсайдеров {len(st.normal['валидация'])}")
    print(f"тест:      инсайдеров {len(st.parts['тест'][1])}, "
          f"неинсайдеров {len(st.normal['тест'])}\n")

    rows_out = []
    baselines = {}   # config -> (caught_set, params) варианта "наши веса", для теста знаков

    for cfg_name, cfg in CONFIGS:
        used = hs.CONFIG_FEATURES[cfg]
        names = [f for f in hs.FEATURES if f in used]
        print("=" * 100)
        print(f"КОНФИГУРАЦИЯ: {cfg_name} (признаки: {', '.join(names)})")
        print("=" * 100)

        variants = []   # (variant, detail, used_subset, weights)

        # 1. наши веса
        variants.append(("наши веса", "ab.WEIGHTS " + str({n: ab.WEIGHTS[n] for n in names}),
                          used, dict(ab.WEIGHTS)))

        # 2. равные веса (1/n, максимум при всех признаках = 1, как в исходной формуле)
        eq = {n: round(1.0 / len(names), 4) for n in names}
        variants.append(("равные веса", str(eq), used, {**ab.WEIGHTS, **eq}))

        # 3. каждый признак отдельно (однопризнаковый детектор, вес 1.0)
        for n in names:
            variants.append((f"только {n}", f"{n}=1.0, остальные не используются", [n], {n: 1.0}))

        # 4. ablation: убрать один признак, у оставшихся - наши исходные веса
        for n in names:
            rest = [x for x in names if x != n]
            variants.append((f"без {n}", f"убран {n}, у остальных веса как сейчас", rest, dict(ab.WEIGHTS)))

        for variant, detail, used_v, weights_v in variants:
            sel = select_on_validation_custom(st, used_v, weights_v)
            if sel is None:
                print(f"{variant:28} -> на валидации нет порога с user FPR <= 3%")
                rows_out.append({"config": cfg_name, "variant": variant, "detail": detail,
                                  "cutoff": "", "N": "", "W": "",
                                  "val_recall": "", "val_fpr": "",
                                  "test_caught": "", "test_total": "", "test_recall": "",
                                  "recall_ci_lo": "", "recall_ci_hi": "",
                                  "test_false": "", "test_normal_total": "", "test_fpr": "",
                                  "sign_test_only_variant": "", "sign_test_only_baseline": "",
                                  "sign_test_p": "", "sign_test_verdict": "не выбрано на валидации",
                                  "note": ""})
                continue
            p, v = sel
            t = run_custom(st, "тест", used_v, weights_v, p["cutoff"], p["N"], p["W"])
            n_ins = len(st.parts["тест"][1])
            lo, hi = u2.wilson(len(t["caught"]), n_ins)
            print(f"{variant:28} tau={p['cutoff']:<5} N={p['N']} W={p['W']:<3} | "
                  f"валидация {len(v['caught'])}/35 FPR {100*v['fpr']:.1f}% | "
                  f"ТЕСТ {len(t['caught'])}/{n_ins} = {100*len(t['caught'])/n_ins:.1f}% "
                  f"[{100*lo:.1f};{100*hi:.1f}], FPR {100*t['fpr']:.1f}%")

            if variant == "наши веса":
                baselines[cfg_name] = t["caught"]
                sign_p, only_v, only_b, verdict = "", "", "", "база для сравнения"
            else:
                base = baselines[cfg_name]
                only_v = len(t["caught"] - base)
                only_b = len(base - t["caught"])
                sign_p = u2.sign_test(only_v, only_b)
                verdict = ("значимо отличается от наших весов" if sign_p < 0.05
                           else "различие не обнаружено (или тест без мощности)")
                print(f"   {'':28} тест знаков против 'наши веса': только вариант {only_v}, "
                      f"только базa {only_b}, p={sign_p:.4f} -> {verdict}")

            rows_out.append({
                "config": cfg_name, "variant": variant, "detail": detail,
                "cutoff": p["cutoff"], "N": p["N"], "W": p["W"],
                "val_recall": round(v["recall"], 4), "val_fpr": round(v["fpr"], 4),
                "test_caught": len(t["caught"]), "test_total": n_ins,
                "test_recall": round(len(t["caught"]) / n_ins, 4),
                "recall_ci_lo": round(lo, 4), "recall_ci_hi": round(hi, 4),
                "test_false": len(t["false"]), "test_normal_total": len(st.normal["тест"]),
                "test_fpr": round(t["fpr"], 4),
                "sign_test_only_variant": only_v, "sign_test_only_baseline": only_b,
                "sign_test_p": sign_p if sign_p == "" else round(sign_p, 4),
                "sign_test_verdict": verdict, "note": "",
            })
        print()

        # 5. логистическая регрессия (обучена на ВАЛИДАЦИИ - честно отмечено)
        print(f"5. Логистическая регрессия ({cfg_name}), признаки те же, обучена на валидации "
              f"(в обучающем периоде 0 вредоносных дней - обучать не на чем)")
        names_lr, cnt = aggregate_patterns(st, "валидация", used)
        theta = fit_logistic(names_lr, cnt)
        coef_str = ", ".join(f"{n}={theta[i+1]:+.3f}" for i, n in enumerate(names_lr))
        print(f"   b0={theta[0]:+.3f}, {coef_str}")
        res = select_on_validation_logreg(st, used, names_lr, theta)
        if res is None:
            print("   -> на валидации нет порога с user FPR <= 3%")
            rows_out.append({"config": cfg_name, "variant": "логистическая регрессия",
                              "detail": f"b0={theta[0]:.3f}; " + coef_str,
                              "cutoff": "", "N": "", "W": "", "val_recall": "", "val_fpr": "",
                              "test_caught": "", "test_total": "", "test_recall": "",
                              "recall_ci_lo": "", "recall_ci_hi": "",
                              "test_false": "", "test_normal_total": "", "test_fpr": "",
                              "sign_test_only_variant": "", "sign_test_only_baseline": "",
                              "sign_test_p": "", "sign_test_verdict": "не выбрано на валидации",
                              "note": "обучена на валидации, не на обучающем периоде"})
        else:
            p, v, t = res
            n_ins = len(st.parts["тест"][1])
            lo, hi = u2.wilson(len(t["caught"]), n_ins)
            base = baselines[cfg_name]
            only_v = len(t["caught"] - base)
            only_b = len(base - t["caught"])
            sign_p = u2.sign_test(only_v, only_b)
            verdict = ("значимо отличается от наших весов" if sign_p < 0.05
                       else "различие не обнаружено (или тест без мощности)")
            print(f"   tau(prob)={p['cutoff']:<7} N={p['N']} W={p['W']:<3} | "
                  f"валидация {len(v['caught'])}/35 FPR {100*v['fpr']:.1f}% | "
                  f"ТЕСТ {len(t['caught'])}/{n_ins} = {100*len(t['caught'])/n_ins:.1f}% "
                  f"[{100*lo:.1f};{100*hi:.1f}], FPR {100*t['fpr']:.1f}%")
            print(f"   тест знаков против 'наши веса': только вариант {only_v}, только база {only_b}, "
                  f"p={sign_p:.4f} -> {verdict}")
            rows_out.append({
                "config": cfg_name, "variant": "логистическая регрессия",
                "detail": f"b0={theta[0]:.3f}; " + coef_str,
                "cutoff": p["cutoff"], "N": p["N"], "W": p["W"],
                "val_recall": round(v["recall"], 4), "val_fpr": round(v["fpr"], 4),
                "test_caught": len(t["caught"]), "test_total": n_ins,
                "test_recall": round(len(t["caught"]) / n_ins, 4),
                "recall_ci_lo": round(lo, 4), "recall_ci_hi": round(hi, 4),
                "test_false": len(t["false"]), "test_normal_total": len(st.normal["тест"]),
                "test_fpr": round(t["fpr"], 4),
                "sign_test_only_variant": only_v, "sign_test_only_baseline": only_b,
                "sign_test_p": round(sign_p, 4), "sign_test_verdict": verdict,
                "note": "коэффициенты и порог подобраны на валидации (train-период без "
                        "вредоносных дней), а не только порог, как у остальных вариантов",
            })
        print()

    fields = list(rows_out[0].keys())
    with open(OUTPUT_FILE, "w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=fields)
        w.writeheader()
        w.writerows(rows_out)
    print(f"Таблица сохранена: {OUTPUT_FILE}")


if __name__ == "__main__":
    main()
