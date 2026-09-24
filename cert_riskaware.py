"""
RISK-AWARE ЛОГИРОВАНИЕ: сколько стоит защита только рискованных событий

Ядро вклада статьи. Криптозащита (хеш-цепочка) стоит ресурсов, поэтому
применять её ко всему журналу дорого. Схема risk-aware:

  - пользователь-день с оценкой риска НИЖЕ порога -> обычная короткая запись;
  - пользователь-день с оценкой риска НЕ НИЖЕ порога -> запись в защищённую
    хеш-цепочку.

Скрипт на тестовом периоде CERT (журнал device.csv) считает:
  1. какая доля событий попадает в защищённую цепочку;
  2. сколько вредоносных событий при этом оказалось под защитой;
  3. во сколько это дешевле, чем защищать весь журнал (время и объём).

Стоимость измеряется реальной записью файлов, а не оценивается по формуле.

Результат: riskaware_results.csv
Запуск (из папки с CSV):  python cert_riskaware.py
"""

import csv
import os
from datetime import datetime, timedelta

import cert_ablation as ab      # признаки, оценка риска, разметка
import cert_chain as ch         # запись журнала обычным способом и с цепочкой

OUTPUT_FILE = "riskaware_results.csv"
REPEATS = 3                     # файлы большие, поэтому повторов меньше
DATE_FORMAT = "%m/%d/%Y %H:%M:%S"
CONFIG = "device"               # по выводу статьи именно device несёт сигнал


def load_test_events(split):
    """
    Читает device.csv построчно и оставляет события тестового периода.
    Возвращает список (запись, пользователь, день).
    """
    events = []
    with open(ab.DEVICE_FILE, encoding="utf-8") as f:
        for r in csv.DictReader(f):
            day = datetime.strptime(r["date"], DATE_FORMAT).date()
            if day >= split:
                events.append((r, r["user"], day))
    return events


def flagged_days(ud, prof, test_keys, cutoff):
    """Множество пар (пользователь, день) с оценкой риска не ниже порога."""
    return {k for k in test_keys
            if ab.score(ud[k], prof.get(k[0]), CONFIG) >= cutoff}


def cost_of(rows_plain, rows_chain, plain_path, chain_path):
    """
    Стоимость схемы: время записи (мс) и суммарный объём файлов (КБ).
    rows_plain пишем обычным способом, rows_chain - с хеш-цепочкой.
    """
    def write_both():
        if rows_plain:
            ch.write_plain(rows_plain, plain_path)
        if rows_chain:
            ch.write_chained(rows_chain, chain_path)

    time_ms = ch.avg_time_ms(write_both, REPEATS)
    size_kb = 0.0
    for rows, path in [(rows_plain, plain_path), (rows_chain, chain_path)]:
        if rows:
            size_kb += os.path.getsize(path) / 1024
    return time_ms, size_kb


def main():
    print("Risk-aware логирование на CERT r4.2 (журнал device.csv)\n")
    windows = ab.load_labels()
    ud = ab.load_events()
    days = sorted({d for _, d in ud})
    split = days[0] + timedelta(days=ab.BASELINE_DAYS)
    prof = ab.build_profiles(ud, split)
    test_keys = [k for k in ud if k[1] >= split]

    events = load_test_events(split)
    total = len(events)
    # Вредоносное событие = событие внутри окна атаки инсайдера (разметка CMU SEI)
    is_bad = [ab.scenario_of(windows, u, d) is not None for _, u, d in events]
    total_bad = sum(is_bad)
    print(f"  событий device в тестовом периоде: {total}")
    print(f"  из них вредоносных (по разметке):  {total_bad}\n")

    plain_path = os.path.join(ch.TMP_DIR, "ra_plain.csv")
    chain_path = os.path.join(ch.TMP_DIR, "ra_chain.csv")
    all_rows = [r for r, _, _ in events]

    # Базовые случаи: всё обычным журналом и всё в цепочку
    plain_ms, plain_kb = cost_of(all_rows, [], plain_path, chain_path)
    full_ms, full_kb = cost_of([], all_rows, plain_path, chain_path)
    print(f"  весь журнал обычный:     {plain_ms:9.1f} мс  {plain_kb:9.1f} КБ")
    print(f"  весь журнал в цепочке:   {full_ms:9.1f} мс  {full_kb:9.1f} КБ\n")

    # Пороги: все различные положительные значения оценки риска, начиная с 0.30
    scores = sorted({round(ab.score(ud[k], prof.get(k[0]), CONFIG), 2)
                     for k in test_keys})
    cutoffs = [c for c in scores if c >= 0.30]

    results = []
    for cutoff in cutoffs:
        flagged = flagged_days(ud, prof, test_keys, cutoff)
        in_chain = [r for (r, u, d) in events if (u, d) in flagged]
        in_plain = [r for (r, u, d) in events if (u, d) not in flagged]
        bad_protected = sum(1 for (e, b) in zip(events, is_bad)
                            if b and (e[1], e[2]) in flagged)

        # FPR по парам пользователь-день, как в основном эксперименте
        rows = [(ab.score(ud[k], prof.get(k[0]), CONFIG),
                 ab.scenario_of(windows, k[0], k[1])) for k in test_keys]
        m, _, _ = ab.metrics(rows, cutoff)

        ms, kb = cost_of(in_plain, in_chain, plain_path, chain_path)
        res = {
            "cutoff": cutoff,
            "fpr": m["fpr"],
            "events_in_chain": len(in_chain),
            "share_in_chain_pct": round(100 * len(in_chain) / total, 2),
            "bad_events_protected_pct": round(100 * bad_protected / total_bad, 1),
            "riskaware_time_ms": round(ms, 1),
            "riskaware_size_kb": round(kb, 1),
            "full_chain_time_ms": round(full_ms, 1),
            "full_chain_size_kb": round(full_kb, 1),
            "time_saving_pct": round(100 * (full_ms - ms) / full_ms, 1),
            "size_saving_pct": round(100 * (full_kb - kb) / full_kb, 1),
            "extra_time_vs_plain_pct": round(100 * (ms - plain_ms) / plain_ms, 1),
            "extra_size_vs_plain_pct": round(100 * (kb - plain_kb) / plain_kb, 1),
        }
        results.append(res)
        print(f"порог {cutoff:.2f} (FPR {m['fpr']:.4f}): "
              f"в цепочке {res['share_in_chain_pct']}% событий, "
              f"защищено {res['bad_events_protected_pct']}% вредоносных, "
              f"время {ms:.1f} мс (экономия {res['time_saving_pct']}% "
              f"против полной цепочки), объём {kb:.1f} КБ "
              f"(экономия {res['size_saving_pct']}%)")

    with open(OUTPUT_FILE, "w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=list(results[0].keys()))
        w.writeheader()
        w.writerows(results)
    print(f"\nТаблица сохранена: {OUTPUT_FILE}")

    for p in [plain_path, chain_path]:
        if os.path.exists(p):
            os.remove(p)


if __name__ == "__main__":
    main()
