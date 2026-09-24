"""
ЗАДАЧА 8 REVISION_PLAN.md: ЦЕНА ЛОКАЛИЗАЦИИ И РЕАЛЬНОЕ ВРЕМЯ

Журнал везде тот же, что в разделах 6.8/6.8a/16: device.csv, тестовый период честного
разбиения (с 2010-10-01), 168 392 записи, 3 985 вредоносных (определение - раздел 14.1).
Ничего в методе не подбирается: пороги риска, веса и признаки - те же замороженные
значения, что везде в проекте.

ЧАСТЬ А. Польза точной локализации.
Смоделировано изменение ОДНОЙ случайной записи: сколько записей аналитику придётся
просмотреть после сбоя проверки, чтобы найти её. У блочной схемы сбой указывает на блок
целиком (B записей). У гибрида: если запись входит в поэлементную цепочку (день
"рискованный", r >= tau) - ровно 1 запись; если нет - блок целиком (как у блочной
схемы, B=1000). Вместо семплирования (шумной оценки) posчитано ТОЧНОЕ математическое
ожидание перебором по всем записям журнала (и отдельно по всем вредоносным) - это и
есть результат "смоделировать одну случайную запись", только без случайного шума.

ЧАСТЬ Б. Реальное время.
Сейчас risk(u, d) считается ПОСТФАКТУМ, по итогам всех событий дня. Здесь - потоковая
симуляция: события дня проигрываются в хронологическом порядке, оценка риска
пересчитывается после каждого события (той же формулой ab.score/ab.device_features -
код признаков не меняется), и для каждого дня, получившего в итоге risk >= tau,
находится ПЕРВОЕ событие, после которого накопленная оценка достигла tau. Всё, что
записано ДО этого момента, в потоковой системе уже лежало бы в "обычном" журнале (день
ещё не выглядел рискованным) - его пришлось бы дописывать в поэлементную цепочку задним
числом.

Результаты: results_revision/localization_cost.csv, results_revision/realtime_analysis.csv
Запуск (из папки с CSV):  python cert_localization_realtime.py
"""

import csv
from collections import defaultdict
from datetime import datetime, timedelta
from statistics import mean, median

import cert_ablation as ab
import cert_honest_split as hs
import cert_riskaware as ra

LOC_CSV = "results_revision/localization_cost.csv"
RT_CSV = "results_revision/realtime_analysis.csv"
TAUS = [0.30, 0.65, 0.95]
BLOCKS_PURE = [100, 1000, 10000]
HYBRID_BLOCK = 1000       # тот же B, что принят как основной вариант гибрида (раздел 23 CLAUDE.md)
DATE_FORMAT = "%m/%d/%Y %H:%M:%S"


# ---------------------------------------------------------------
# ЧАСТЬ А. Цена локализации
# ---------------------------------------------------------------
def block_sizes(n_total, block):
    """Список размеров блоков для журнала из n_total записей при размере блока block
    (последний блок может быть короче)."""
    full = n_total // block
    rem = n_total % block
    sizes = [block] * full
    if rem:
        sizes.append(rem)
    return sizes


def expected_review_cost_uniform_record(n_total, block):
    """
    Ожидаемое число записей к просмотру, если испорченная запись выбрана РАВНОВЕРОЯТНО
    среди всех n_total записей журнала (не среди блоков!): запись из блока размера s
    выбирается с вероятностью s/n_total, и тогда просматривать нужно s записей -
    поэтому E[cost] = sum(s_i^2) / n_total (взвешивание по размеру блока, не простое
    среднее размеров блоков).
    """
    sizes = block_sizes(n_total, block)
    return sum(s * s for s in sizes) / n_total


def expected_review_cost_for_subset(positions, n_total, block):
    """То же самое, но для ЗАДАННОГО подмножества позиций записей (например, только
    вредоносных) - для каждой позиции берём размер её блока и усредняем."""
    sizes = block_sizes(n_total, block)
    # позиция p (0-индекс) принадлежит блоку p // block
    total = 0
    for p in positions:
        b = p // block
        total += sizes[b]
    return total / len(positions) if positions else 0.0


def part_a(events, is_bad, windows, ud, prof, test_keys):
    print("=" * 100)
    print("ЧАСТЬ А. Цена локализации: сколько записей просматривать после сбоя проверки")
    print("=" * 100)
    n_total = len(events)
    bad_positions = [i for i, b in enumerate(is_bad) if b]
    n_bad = len(bad_positions)
    print(f"всего записей: {n_total}, из них вредоносных: {n_bad}\n")

    rows_out = []

    # --- чистая блочная схема, B = 100 / 1000 / 10000 ---
    print("Чистая блочная схема (не зависит от того, вредоносна запись или нет):")
    for B in BLOCKS_PURE:
        cost_all = expected_review_cost_uniform_record(n_total, B)
        cost_bad = expected_review_cost_for_subset(bad_positions, n_total, B)
        print(f"  B={B:<6} среднее по журналу {cost_all:8.1f} записей   "
              f"среднее по вредоносным {cost_bad:8.1f} записей")
        rows_out.append({"scheme": "блочная (чистая)", "param": f"B={B}", "population": "весь журнал",
                          "records_reviewed_if_in_chain": "", "records_reviewed_if_not_in_chain": round(cost_all, 1),
                          "share_in_chain_pct": 0.0, "avg_records_to_review": round(cost_all, 1), "note": ""})
        rows_out.append({"scheme": "блочная (чистая)", "param": f"B={B}", "population": "только вредоносные",
                          "records_reviewed_if_in_chain": "", "records_reviewed_if_not_in_chain": round(cost_bad, 1),
                          "share_in_chain_pct": 0.0, "avg_records_to_review": round(cost_bad, 1),
                          "note": "почти совпадает со 'весь журнал' - блочная схема не различает вредоносность"})
    print()

    # --- гибрид: блок 1000 для всех + поэлементная для рискованных дней (tau) ---
    print(f"Гибрид (блок B={HYBRID_BLOCK} для всех + поэлементная для дней risk >= tau):")
    for tau in TAUS:
        flagged = ra.flagged_days(ud, prof, test_keys, tau)
        in_chain_all = [(u, d) in flagged for _, u, d in events]
        in_chain_bad = [in_chain_all[i] for i in bad_positions]

        cost_not_in_chain = expected_review_cost_uniform_record(n_total, HYBRID_BLOCK)  # тот же блок для всех
        n_in_all = sum(in_chain_all)
        share_all = n_in_all / n_total
        avg_all = share_all * 1 + (1 - share_all) * cost_not_in_chain

        n_in_bad = sum(in_chain_bad)
        share_bad = n_in_bad / n_bad if n_bad else 0.0
        avg_bad = share_bad * 1 + (1 - share_bad) * cost_not_in_chain

        print(f"  tau={tau:<5} в цепочке: весь журнал {100*share_all:5.2f}% "
              f"({n_in_all}/{n_total}), вредоносные {100*share_bad:5.2f}% ({n_in_bad}/{n_bad})")
        print(f"          среднее к просмотру: весь журнал {avg_all:7.2f} записей, "
              f"вредоносные {avg_bad:7.2f} записей "
              f"(если в цепочке: 1 запись; если нет: {cost_not_in_chain:.1f} записей, блок B={HYBRID_BLOCK})")

        rows_out.append({"scheme": "гибрид", "param": f"tau={tau}", "population": "весь журнал",
                          "records_reviewed_if_in_chain": 1,
                          "records_reviewed_if_not_in_chain": round(cost_not_in_chain, 1),
                          "share_in_chain_pct": round(100 * share_all, 2),
                          "avg_records_to_review": round(avg_all, 2), "note": ""})
        rows_out.append({"scheme": "гибрид", "param": f"tau={tau}", "population": "только вредоносные",
                          "records_reviewed_if_in_chain": 1,
                          "records_reviewed_if_not_in_chain": round(cost_not_in_chain, 1),
                          "share_in_chain_pct": round(100 * share_bad, 2),
                          "avg_records_to_review": round(avg_bad, 2),
                          "note": "доля в цепочке выше, чем по всему журналу - вредоносные события "
                                  "непропорционально чаще попадают в рискованные дни"})
    print()

    with open(LOC_CSV, "w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=list(rows_out[0].keys()))
        w.writeheader()
        w.writerows(rows_out)
    print(f"Таблица сохранена: {LOC_CSV}\n")


# ---------------------------------------------------------------
# ЧАСТЬ Б. Реальное время (потоковая симуляция)
# ---------------------------------------------------------------
def load_device_events_by_day(split):
    """Все записи device.csv (без фильтра по activity) в тестовом периоде, сгруппированные
    по (user, day), внутри дня - отсортированы по времени. Нужно для потоковой симуляции:
    там важен порядок событий ВНУТРИ дня, а не только их число."""
    by_day = defaultdict(list)
    with open(ab.DEVICE_FILE, encoding="utf-8") as f:
        for r in csv.DictReader(f):
            dt = datetime.strptime(r["date"], DATE_FORMAT)
            if dt.date() < split:
                continue
            by_day[(r["user"], dt.date())].append((dt, r))
    for k in by_day:
        by_day[k].sort(key=lambda x: x[0])
    return by_day


def streaming_crossing_point(events_sorted, profile, tau):
    """
    Проигрывает события дня в хронологическом порядке, пересчитывая device_features/score
    ПОСЛЕ каждого Connect (та же формула ab.device_features + ab.WEIGHTS, не меняется).
    Возвращает позицию (1-индекс, считая ВСЕ события дня, включая Disconnect) первого
    события, после которого накопленная оценка достигла tau, или None, если за весь день
    порог так и не достигнут (не должно случаться для дней, отобранных как "рискованные"
    по итоговой дневной оценке - проверяется отдельно).
    """
    v = {"dev": 0, "dev_off": 0}
    for i, (dt, r) in enumerate(events_sorted, start=1):
        if r["activity"] == "Connect":
            v["dev"] += 1
            if dt.hour < ab.WORK_START or dt.hour >= ab.WORK_END:
                v["dev_off"] += 1
        if profile and profile["days"]:
            s = ab.score(v, profile, "device")
            if s >= tau:
                return i
    return None


def part_b(windows, ud, prof, test_keys):
    print("=" * 100)
    print("ЧАСТЬ Б. Реальное время: сколько записей дня пришлось бы добавлять задним числом")
    print("=" * 100)
    by_day = load_device_events_by_day(hs.TEST_START)
    rows_out = []

    for tau in TAUS:
        flagged = ra.flagged_days(ud, prof, test_keys, tau)   # те же дни, что и везде (не подбирается)
        fractions, backfill_counts, total_counts = [], [], []
        no_crossing = 0
        for (u, d) in flagged:
            key = (u, d)
            if key not in by_day:
                continue           # день рискованный по logon-части признаков, событий device в этот день нет
            ev = by_day[key]
            cross = streaming_crossing_point(ev, prof.get(u), tau)
            n = len(ev)
            if cross is None:
                no_crossing += 1
                continue
            backfill = cross - 1   # события ДО момента пересечения (само пересекающее событие уже защищено)
            fractions.append(backfill / n if n else 0.0)
            backfill_counts.append(backfill)
            total_counts.append(n)

        n_days = len(fractions)
        total_events = sum(total_counts)
        total_backfill = sum(backfill_counts)
        mean_frac = mean(fractions) if fractions else 0.0
        median_frac = median(fractions) if fractions else 0.0
        print(f"tau={tau}: рискованных дней с device-событиями {n_days} "
              f"(из них без пересечения порога при потоковом пересчёте: {no_crossing})")
        print(f"  событий в этих днях всего: {total_events}, "
              f"из них потребовали бы дозаписи задним числом: {total_backfill} "
              f"({100 * total_backfill / total_events:.1f}%)")
        print(f"  доля дозаписи по дню: среднее {100 * mean_frac:.1f}%, медиана {100 * median_frac:.1f}%\n")

        rows_out.append({
            "tau": tau, "flagged_days_with_device_events": n_days,
            "days_never_crossed_streaming": no_crossing,
            "total_events_in_flagged_days": total_events,
            "events_needing_backfill": total_backfill,
            "share_events_needing_backfill_pct": round(100 * total_backfill / total_events, 2) if total_events else 0,
            "mean_backfill_fraction_per_day_pct": round(100 * mean_frac, 2),
            "median_backfill_fraction_per_day_pct": round(100 * median_frac, 2),
        })

    with open(RT_CSV, "w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=list(rows_out[0].keys()))
        w.writeheader()
        w.writerows(rows_out)
    print(f"Таблица сохранена: {RT_CSV}")


def main():
    print("Загрузка...")
    windows = ab.load_labels()
    ud = ab.load_events()
    days = sorted({d for _, d in ud})
    train_end = days[0] + timedelta(days=ab.BASELINE_DAYS)
    prof = ab.build_profiles(ud, train_end)
    test_keys = [k for k in ud if k[1] >= hs.TEST_START]

    events = ra.load_test_events(hs.TEST_START)
    is_bad = [ab.scenario_of(windows, u, d) is not None for _, u, d in events]
    print(f"тестовый период с {hs.TEST_START}; событий device: {len(events)}, "
          f"вредоносных: {sum(is_bad)}\n")

    part_a(events, is_bad, windows, ud, prof, test_keys)
    part_b(windows, ud, prof, test_keys)


if __name__ == "__main__":
    main()
