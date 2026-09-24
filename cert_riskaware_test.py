"""
RISK-AWARE ЛОГИРОВАНИЕ НА ЧЕСТНОМ РАЗБИЕНИИ

Прежний cert_riskaware.py считал стоимость защиты по всему периоду после обучения
(с 2010-05-02) и до разделения на валидацию и тест. Здесь то же самое считаем
ТОЛЬКО по тестовой части (с 2010-10-01), профили по обучающему периоду (до 2010-05-02).

Пороги не выбираем по тесту: показываем ВСЕ возможные значения оценки риска для
device (0.30, 0.65, 0.95), чтобы читатель сам видел компромисс. Для каждого порога:
  - какая доля событий device попадает в защищённую цепочку;
  - какая доля вредоносных событий (по разметке) оказалась под защитой;
  - время записи и объём файла: весь журнал в цепочке против risk-aware;
  - дневной FPR порога на тесте (для справки).

Стоимость измеряется реальной записью файлов. ОСНОВНЫЕ колонки посчитаны для HMAC-цепочки
с контрольными точками (cert_chain_hmac.py): это схема, которая описана в статье.
Колонки с префиксом sha_ - для простой SHA-256 цепочки (cert_chain.py), для сравнения.

Результат: riskaware_test_results.csv
Запуск (из папки с CSV):  python cert_riskaware_test.py
"""

import csv
import os
from datetime import timedelta

import cert_ablation as ab
import cert_chain as ch
import cert_chain_hmac as chm
import cert_honest_split as hs
import cert_riskaware as ra
import cert_user_level2 as u2

OUTPUT_FILE = "riskaware_test_results.csv"


def cost_of_hmac(rows_plain, rows_chain, plain_path, log_path, anchor_path):
    """Стоимость risk-aware схемы с HMAC-цепочкой: время (мс) и суммарный объём (КБ)."""
    def write_both():
        if rows_plain:
            ch.write_plain(rows_plain, plain_path)
        if rows_chain:
            chm.write_hmac_chain(rows_chain, log_path, anchor_path, chm.KEY)

    time_ms = ch.avg_time_ms(write_both, ra.REPEATS)
    size_kb = sum(os.path.getsize(p) / 1024
                  for rows, paths in [(rows_plain, [plain_path]), (rows_chain, [log_path, anchor_path])]
                  if rows for p in paths)
    return time_ms, size_kb


def main():
    windows = ab.load_labels()
    ud = ab.load_events()
    days = sorted({d for _, d in ud})
    train_end = days[0] + timedelta(days=ab.BASELINE_DAYS)        # конец обучающего периода
    prof = ab.build_profiles(ud, train_end)
    test_keys = [k for k in ud if k[1] >= hs.TEST_START]

    events = ra.load_test_events(hs.TEST_START)          # события device только из теста
    total = len(events)
    is_bad = [ab.scenario_of(windows, u, d) is not None for _, u, d in events]
    total_bad = sum(is_bad)
    print(f"тестовый период: с {hs.TEST_START}; событий device: {total}, вредоносных по разметке: {total_bad}\n")

    plain_path = os.path.join(ch.TMP_DIR, "rat_plain.csv")
    chain_path = os.path.join(ch.TMP_DIR, "rat_chain.csv")
    log_path = os.path.join(ch.TMP_DIR, "rat_hmac.csv")
    anchor_path = os.path.join(ch.TMP_DIR, "rat_anchor.csv")
    all_rows = [r for r, _, _ in events]
    plain_ms, plain_kb = ra.cost_of(all_rows, [], plain_path, chain_path)
    sha_full_ms, sha_full_kb = ra.cost_of([], all_rows, plain_path, chain_path)
    full_ms, full_kb = cost_of_hmac([], all_rows, plain_path, log_path, anchor_path)
    print(f"весь журнал обычный:          {plain_ms:8.1f} мс  {plain_kb / 1024:6.1f} МБ")
    print(f"весь журнал, HMAC-цепочка:    {full_ms:8.1f} мс  {full_kb / 1024:6.1f} МБ")
    print(f"весь журнал, SHA-цепочка:     {sha_full_ms:8.1f} мс  {sha_full_kb / 1024:6.1f} МБ\n")

    results = []
    for cutoff in u2.score_levels(hs.CONFIG_FEATURES["device"]):
        flagged = ra.flagged_days(ud, prof, test_keys, cutoff)
        in_chain = [r for (r, u, d) in events if (u, d) in flagged]
        in_plain = [r for (r, u, d) in events if (u, d) not in flagged]
        bad_protected = sum(1 for (e, b) in zip(events, is_bad) if b and (e[1], e[2]) in flagged)
        rows = [(ab.score(ud[k], prof.get(k[0]), "device"), ab.scenario_of(windows, k[0], k[1]))
                for k in test_keys]
        m, _, _ = ab.metrics(rows, cutoff)
        ms, kb = cost_of_hmac(in_plain, in_chain, plain_path, log_path, anchor_path)
        sha_ms, sha_kb = ra.cost_of(in_plain, in_chain, plain_path, chain_path)
        res = {
            "cutoff": cutoff, "day_fpr": m["fpr"],
            "events_in_chain": len(in_chain),
            "share_in_chain_pct": round(100 * len(in_chain) / total, 2),
            "bad_events_protected_pct": round(100 * bad_protected / total_bad, 1),
            "riskaware_time_ms": round(ms, 1), "riskaware_size_kb": round(kb, 1),
            "full_chain_time_ms": round(full_ms, 1), "full_chain_size_kb": round(full_kb, 1),
            "plain_time_ms": round(plain_ms, 1), "plain_size_kb": round(plain_kb, 1),
            "time_saving_pct": round(100 * (full_ms - ms) / full_ms, 1),
            "size_saving_pct": round(100 * (full_kb - kb) / full_kb, 1),
            "extra_time_vs_plain_pct": round(100 * (ms - plain_ms) / plain_ms, 1),
            "extra_size_vs_plain_pct": round(100 * (kb - plain_kb) / plain_kb, 1),
            "sha_riskaware_time_ms": round(sha_ms, 1), "sha_riskaware_size_kb": round(sha_kb, 1),
            "sha_full_chain_time_ms": round(sha_full_ms, 1), "sha_full_chain_size_kb": round(sha_full_kb, 1),
            "sha_time_saving_pct": round(100 * (sha_full_ms - sha_ms) / sha_full_ms, 1),
            "sha_size_saving_pct": round(100 * (sha_full_kb - sha_kb) / sha_full_kb, 1),
        }
        results.append(res)
        print(f"порог {cutoff:.2f} (дневной FPR {100 * m['fpr']:.2f}%): в цепочке {res['share_in_chain_pct']}% событий, "
              f"защищено {res['bad_events_protected_pct']}% вредоносных; время {ms:.0f} мс "
              f"(экономия {res['time_saving_pct']}% против полной цепочки, на {res['extra_time_vs_plain_pct']}% дороже "
              f"обычного), объём {kb / 1024:.1f} МБ (экономия {res['size_saving_pct']}%, "
              f"+{res['extra_size_vs_plain_pct']}% к обычному)")

    with open(OUTPUT_FILE, "w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=list(results[0].keys()))
        w.writeheader()
        w.writerows(results)
    print(f"\nТаблица сохранена: {OUTPUT_FILE}")
    for p in (plain_path, chain_path, log_path, anchor_path):
        if os.path.exists(p):
            os.remove(p)


if __name__ == "__main__":
    main()
