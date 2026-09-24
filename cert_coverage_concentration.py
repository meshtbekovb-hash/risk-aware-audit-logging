"""
ДИАГНОСТИКА УСТОЙЧИВОСТИ ПОКРЫТИЯ 31.8% (раздел 24 FULL_REPORT_for_review.md)

Вопрос: 31.8% вредоносных записей под поэлементной защитой при tau=0.30 - это много дней
понемногу или несколько дней с огромным числом записей? Если второе, цифра держится на
единицах дней и неустойчива.

Для четырёх множеств дней (тест r4.2, журнал device, тот же, что в разделах 6.8 и 24):
  - слой 0.30: дни с оценкой РОВНО 0.30 (сработал только dev_spike);
  - device tau=0.30, 0.65, 0.95: дни с оценкой не ниже tau;
считаем, сколько вредоносных записей приходится на каждый пользователь-день, и смотрим:
сколько дней дают покрытие, распределение записей на день, доля покрытия у 5 и 10
крупнейших дней, сколько дней нужно для 50% и 80% покрытия, и то же по инсайдерам
(дни одного человека не независимы).

Ничего не подбирается - только диагностика уже посчитанных множеств.

Результат: results_revision/coverage_concentration.csv (сводка),
           results_revision/coverage_concentration_days.csv (все дни с покрытием)
Запуск (из папки с CSV):  python cert_coverage_concentration.py
"""

import csv
from collections import Counter
from datetime import timedelta
from statistics import median, mean

import cert_ablation as ab
import cert_honest_split as hs
import cert_riskaware as ra

OUT_SUMMARY = "results_revision/coverage_concentration.csv"
OUT_DAYS = "results_revision/coverage_concentration_days.csv"


def quantile(sorted_vals, q):
    """Простая квантиль по ближайшему рангу (без интерполяции)."""
    i = min(len(sorted_vals) - 1, max(0, round(q * (len(sorted_vals) - 1))))
    return sorted_vals[i]


def days_to_reach(counts_desc, total, share):
    """Сколько крупнейших единиц нужно, чтобы набрать долю share от total."""
    acc = 0
    for i, c in enumerate(counts_desc, 1):
        acc += c
        if acc >= share * total:
            return i
    return len(counts_desc)


def main():
    windows = ab.load_labels()
    ud = ab.load_events()
    days = sorted({d for _, d in ud})
    train_end = days[0] + timedelta(days=ab.BASELINE_DAYS)
    prof = ab.build_profiles(ud, train_end)
    test_keys = [k for k in ud if k[1] >= hs.TEST_START]

    events = ra.load_test_events(hs.TEST_START)
    total_bad = 0
    bad_per_day = Counter()                    # вредоносных записей на пользователь-день
    for _, u, d in events:
        if ab.scenario_of(windows, u, d) is not None:
            bad_per_day[(u, d)] += 1
            total_bad += 1
    print(f"журнал device теста: {len(events)} записей, вредоносных {total_bad}\n")

    score = {k: round(ab.score(ud[k], prof.get(k[0]), "device"), 2) for k in test_keys}
    layers = {
        "слой 0.30 (только dev_spike)": {k for k, s in score.items() if s == 0.30},
        "device tau=0.30": {k for k, s in score.items() if s >= 0.30},
        "device tau=0.65": {k for k, s in score.items() if s >= 0.65},
        "device tau=0.95": {k for k, s in score.items() if s >= 0.95},
    }

    summary, day_rows = [], []
    for name, keys in layers.items():
        per_day = sorted((bad_per_day[k] for k in keys if bad_per_day[k] > 0), reverse=True)
        covered = sum(per_day)
        per_user = Counter()
        for k in keys:
            per_user[k[0]] += bad_per_day[k]
        users_desc = sorted((c for c in per_user.values() if c > 0), reverse=True)
        top5, top10 = sum(per_day[:5]), sum(per_day[:10])
        asc = sorted(per_day)
        row = {
            "set": name,
            "flagged_days": len(keys),
            "days_with_malicious": len(per_day),
            "malicious_covered": covered,
            "coverage_pct_of_all_malicious": round(100 * covered / total_bad, 1),
            "per_day_min": asc[0], "per_day_median": median(asc), "per_day_mean": round(mean(asc), 1),
            "per_day_p75": quantile(asc, 0.75), "per_day_p90": quantile(asc, 0.90), "per_day_max": asc[-1],
            "top5_days_share_pct": round(100 * top5 / covered, 1),
            "top10_days_share_pct": round(100 * top10 / covered, 1),
            "top5_days_pp_of_all": round(100 * top5 / total_bad, 1),
            "top10_days_pp_of_all": round(100 * top10 / total_bad, 1),
            "days_for_50pct": days_to_reach(per_day, covered, 0.5),
            "days_for_80pct": days_to_reach(per_day, covered, 0.8),
            "insiders_with_coverage": len(users_desc),
            "top1_insider_share_pct": round(100 * users_desc[0] / covered, 1),
            "top3_insiders_share_pct": round(100 * sum(users_desc[:3]) / covered, 1),
            "insiders_for_50pct": days_to_reach(users_desc, covered, 0.5),
            "insiders_for_80pct": days_to_reach(users_desc, covered, 0.8),
        }
        summary.append(row)

        print(f"=== {name} ===")
        print(f"  помеченных дней {row['flagged_days']}, из них с вредоносными записями {row['days_with_malicious']}; "
              f"покрыто {covered} из {total_bad} = {row['coverage_pct_of_all_malicious']}%")
        print(f"  вредоносных записей на день: мин {row['per_day_min']}, медиана {row['per_day_median']}, "
              f"среднее {row['per_day_mean']}, p75 {row['per_day_p75']}, p90 {row['per_day_p90']}, макс {row['per_day_max']}")
        print(f"  топ-5 дней: {row['top5_days_share_pct']}% покрытия ({row['top5_days_pp_of_all']} п.п. из "
              f"{row['coverage_pct_of_all_malicious']}); топ-10: {row['top10_days_share_pct']}% "
              f"({row['top10_days_pp_of_all']} п.п.)")
        print(f"  дней для 50% покрытия: {row['days_for_50pct']}, для 80%: {row['days_for_80pct']}")
        print(f"  инсайдеров с покрытием: {row['insiders_with_coverage']}; топ-1: {row['top1_insider_share_pct']}%, "
              f"топ-3: {row['top3_insiders_share_pct']}%; инсайдеров для 50%: {row['insiders_for_50pct']}, "
              f"для 80%: {row['insiders_for_80pct']}")
        top = sorted(((bad_per_day[k], k) for k in keys if bad_per_day[k] > 0), reverse=True)[:10]
        print("  10 крупнейших дней: " + "; ".join(f"{u} {d} сц.{ab.scenario_of(windows, u, d)}: {c}"
                                                  for c, (u, d) in top))
        print()
        for c, (u, d) in sorted(((bad_per_day[k], k) for k in keys if bad_per_day[k] > 0), reverse=True):
            day_rows.append({"set": name, "user": u, "day": d, "scenario": ab.scenario_of(windows, u, d),
                             "score": score[(u, d)], "malicious_records": c})

    with open(OUT_SUMMARY, "w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=list(summary[0].keys()))
        w.writeheader()
        w.writerows(summary)
    with open(OUT_DAYS, "w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=list(day_rows[0].keys()))
        w.writeheader()
        w.writerows(day_rows)
    print(f"сохранено: {OUT_SUMMARY}, {OUT_DAYS}")


if __name__ == "__main__":
    main()
