"""
ЗАДАЧА 3 REVISION_PLAN.md: МОДЕЛЬ РИСКА ПРОТИВ ПРОСТЫХ ПРАВИЛ ОТБОРА

Ревью просит показать: если бы вместо оценки риска (novelty-признаки и веса) отбирать
записи для поэлементной защиты простым правилом, было бы хуже, так же или лучше?

Журнал и период - ТЕ ЖЕ, что в cert_riskaware_test.py: device.csv, тестовая часть
честного разбиения (с 2010-10-01), 168 392 записи (Connect и Disconnect), из них 3 985
вредоносных по разметке (определение "вредоносного события" - из задачи 1: запись
device.csv инсайдера, чей день попадает в окно его атаки).

Наша модель риска НЕ перебирается заново: доли записей в цепочке (4.29% / 1.47% / 0.14%,
7228 / 2476 / 244 записей) и покрытие вредоносных (31.8% / 6.6% / 1.6%) взяты как есть
из уже посчитанного riskaware_test_results.csv (cert_riskaware_test.py). Здесь для тех
же ТОЧНЫХ количеств записей (не округлённых процентов) считаются альтернативы:

  1. модель риска tau=0.30/0.65/0.95           - перенесено из riskaware_test_results.csv
  2. случайный отбор того же ЧИСЛА записей     - 1000 повторов, seed фиксирован (42)
  3. device вне рабочих часов (8:00-18:00)     - правило по записи, без порогов новизны
  4. вне рабочих часов, logon ИЛИ device       - запись device отбирается, если она сама
                                                  вне часов ИЛИ у пользователя в этот же
                                                  день был вход (Logon) вне часов
  5. все события Connect                       - без учёта времени вообще

Для правил 3-5 доля отобранных записей не задаётся заранее (в отличие от 1-2), поэтому
для честного сравнения считаем ОБЕ величины: сколько записей это правило берёт (доля
затрат) и сколько вредоносных покрывает (доля выгоды), и делим одно на другое -
"покрытие на единицу затрат" (efficiency). У модели риска и случайного отбора доля
затрат совпадает по построению (те же 3 количества записей), поэтому efficiency для них
считается тем же способом - для честного сравнения всех пяти вариантов в одной колонке.

Часы новизны/пороги/веса самой модели риска НЕ меняются - код cert_riskaware.py и
cert_ablation.py не трогается, только читается их готовый результат.

Результат: results_revision/selection_baselines.csv
Запуск (из папки с CSV):  python cert_selection_baselines.py
"""

import csv
import random
from datetime import datetime
from statistics import mean

import cert_ablation as ab
import cert_honest_split as hs
import cert_riskaware as ra

OUTPUT_FILE = "results_revision/selection_baselines.csv"
RISKAWARE_CSV = "riskaware_test_results.csv"
WORK_START, WORK_END = ab.WORK_START, ab.WORK_END     # те же 8 и 18, не подбираются
DATE_FORMAT = "%m/%d/%Y %H:%M:%S"
RANDOM_SEED = 42
REPEATS = 1000


def is_off_hours(dt):
    return dt.hour < WORK_START or dt.hour >= WORK_END


def load_riskaware_reference():
    """Читает уже посчитанный риск-осведомлённый результат, ничего не пересчитывая."""
    rows = []
    with open(RISKAWARE_CSV, encoding="utf-8") as f:
        for r in csv.DictReader(f):
            rows.append({
                "cutoff": float(r["cutoff"]),
                "events_in_chain": int(r["events_in_chain"]),
                "share_in_chain_pct": float(r["share_in_chain_pct"]),
                "bad_events_protected_pct": float(r["bad_events_protected_pct"]),
            })
    return rows


def random_baseline(total, total_bad, is_bad, k, repeats, seed):
    """
    Случайный отбор k записей из total, repeats раз, без возвращения.
    Возвращает список долей покрытых вредоносных событий (по одному числу на повтор).
    is_bad - список True/False по индексам записей (0..total-1) в исходном порядке events.
    """
    bad_idx = {i for i, b in enumerate(is_bad) if b}
    rng = random.Random(seed)
    coverages = []
    for _ in range(repeats):
        picked = rng.sample(range(total), k)
        caught = sum(1 for i in picked if i in bad_idx)
        coverages.append(caught / total_bad)
    return coverages


def ci95_from_samples(samples):
    """95% интервал по эмпирическим 2.5 / 97.5 перцентилям (без предположения о форме)."""
    s = sorted(samples)
    n = len(s)
    lo = s[max(0, round(0.025 * (n - 1)))]
    hi = s[min(n - 1, round(0.975 * (n - 1)))]
    return lo, hi


def main():
    print("Отбор для поэлементной защиты: модель риска против простых правил")
    print("Журнал: device.csv, тестовый период (с 2010-10-01), тот же, что в cert_riskaware_test.py\n")

    events = ra.load_test_events(hs.TEST_START)
    total = len(events)
    windows = ab.load_labels()
    is_bad = [ab.scenario_of(windows, u, d) is not None for _, u, d in events]
    total_bad = sum(is_bad)
    print(f"всего записей: {total}, вредоносных: {total_bad}\n")

    # Для правила 4 нужен признак "в этот день у пользователя был Logon вне часов" -
    # берём из уже загруженного ud (та же функция, что и в основном эксперименте).
    ud = ab.load_events()

    rows_out = []

    def add(rule, param, selected, note):
        n_sel = len(selected)
        n_bad = sum(1 for i in selected if is_bad[i])
        share = 100 * n_sel / total
        cov = 100 * n_bad / total_bad
        eff = round(cov / share, 3) if share else 0.0
        print(f"{rule:38} {param:10} записей {n_sel:>7} ({share:5.2f}%)  "
              f"вредоносных покрыто {n_bad:>5} ({cov:5.1f}%)  eff {eff}")
        rows_out.append({
            "rule": rule, "param": param, "records_selected": n_sel, "total_records": total,
            "share_selected_pct": round(share, 2), "malicious_selected": n_bad,
            "total_malicious": total_bad, "malicious_covered_pct": round(cov, 1),
            "efficiency_coverage_per_share": eff,
            "coverage_ci_lo_pct": "", "coverage_ci_hi_pct": "", "note": note,
        })

    # ---- 1. Модель риска (перенесено как есть, не пересчитывается) ----
    print("1. Модель риска (из riskaware_test_results.csv, без пересчёта)")
    ra_ref = load_riskaware_reference()
    for r in ra_ref:
        share = r["share_in_chain_pct"]
        cov = r["bad_events_protected_pct"]
        eff = round(cov / share, 3) if share else 0.0
        print(f"   tau={r['cutoff']:<5} записей {r['events_in_chain']:>7} ({share:5.2f}%)  "
              f"вредоносных покрыто {cov:5.1f}%  eff {eff}")
        rows_out.append({
            "rule": "risk model", "param": f"tau={r['cutoff']}",
            "records_selected": r["events_in_chain"], "total_records": total,
            "share_selected_pct": share, "malicious_selected": "",
            "total_malicious": total_bad, "malicious_covered_pct": cov,
            "efficiency_coverage_per_share": eff,
            "coverage_ci_lo_pct": "", "coverage_ci_hi_pct": "",
            "note": "перенесено из riskaware_test_results.csv, не пересчитывалось",
        })
    print()

    # ---- 2. Случайный отбор того же числа записей, 1000 повторов ----
    print(f"2. Случайный отбор (тот же объём, что у модели риска), {REPEATS} повторов, seed={RANDOM_SEED}")
    for r in ra_ref:
        k = r["events_in_chain"]
        coverages = random_baseline(total, total_bad, is_bad, k, REPEATS, RANDOM_SEED)
        m = 100 * mean(coverages)
        lo, hi = ci95_from_samples([100 * c for c in coverages])
        print(f"   k={k:>7} (доля {100*k/total:5.2f}%, как при tau={r['cutoff']})  "
              f"среднее покрытие {m:5.2f}%  95% ДИ [{lo:.2f}; {hi:.2f}]")
        eff = round(m / (100 * k / total), 3)
        rows_out.append({
            "rule": "random selection", "param": f"k={k} (as tau={r['cutoff']})",
            "records_selected": k, "total_records": total,
            "share_selected_pct": round(100 * k / total, 2), "malicious_selected": "",
            "total_malicious": total_bad, "malicious_covered_pct": round(m, 2),
            "efficiency_coverage_per_share": eff,
            "coverage_ci_lo_pct": round(lo, 2), "coverage_ci_hi_pct": round(hi, 2),
            "note": f"{REPEATS} повторов без возвращения, seed={RANDOM_SEED}, "
                    f"интервал по эмпирическим перцентилям 2.5/97.5",
        })
    print()

    # ---- 3. Device вне рабочих часов ----
    print("3. Device вне рабочих часов (8:00-18:00), правило по самой записи")
    sel3 = [i for i, (r, u, d) in enumerate(events)
            if is_off_hours(datetime.strptime(r["date"], DATE_FORMAT))]
    add("device off-hours (record's own time)", "8-18", sel3,
        "запись отбирается, если её собственное время вне 8:00-18:00")

    # ---- 4. Вне рабочих часов: logon ИЛИ device ----
    print("\n4. Вне рабочих часов: logon ИЛИ device (по паре пользователь-день)")
    sel4 = []
    for i, (r, u, d) in enumerate(events):
        dt = datetime.strptime(r["date"], DATE_FORMAT)
        dev_off = is_off_hours(dt)
        logon_off = ud.get((u, d), {}).get("logon_off", 0) > 0
        if dev_off or logon_off:
            sel4.append(i)
    add("off-hours: logon OR device", "8-18", sel4,
        "запись отбирается, если она сама вне часов, или в этот же день у пользователя "
        "был вход (Logon) вне часов")

    # ---- 5. Все события Connect ----
    print("\n5. Все события Connect (без учёта времени)")
    sel5 = [i for i, (r, u, d) in enumerate(events) if r["activity"] == "Connect"]
    add("all Connect events", "-", sel5, "запись отбирается, если activity == 'Connect'")

    with open(OUTPUT_FILE, "w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=list(rows_out[0].keys()))
        w.writeheader()
        w.writerows(rows_out)
    print(f"\nТаблица сохранена: {OUTPUT_FILE}")


if __name__ == "__main__":
    main()
