"""
Сверка ключевых чисел FULL_REPORT_for_review.md с логами (logs/) и таблицами результатов.

Порядок: сначала запусти скрипты с записью логов в logs/ (список в разделе 11 отчёта), затем из папки проекта:
    python check_report_numbers.py
Скрипт (1) досчитывает дневные TP/FN/FP/TN для device на тестовой части (с 2010-10-01);
(2) проверяет, что каждое из ключевых чисел отчёта действительно есть в логе или таблице результатов.
"""

import io
import os
import sys
from datetime import timedelta

sys.path.insert(0, os.getcwd())          # запуск из папки проекта
import cert_ablation as ab
import cert_honest_split as hs

# 1. Дневные TP/FN/FP/TN для device на тесте
windows = ab.load_labels()
ud = ab.load_events()
days = sorted({d for _, d in ud})
train_end = days[0] + timedelta(days=ab.BASELINE_DAYS)
prof = ab.build_profiles(ud, train_end)
used = hs.CONFIG_FEATURES["device"]
for cut in (0.30, 0.65):
    tp = fn = fp = tn = 0
    for k in ud:
        if k[1] < hs.TEST_START:
            continue
        alert = round(hs.pattern_score(hs.day_pattern(ud[k], prof.get(k[0])), ab.WEIGHTS, used), 2) >= cut
        bad = ab.scenario_of(windows, k[0], k[1]) is not None
        tp += alert and bad
        fn += (not alert) and bad
        fp += alert and not bad
        tn += (not alert) and not bad
    print(f"device {cut}: TP {tp} FN {fn} FP {fp} TN {tn}  recall {tp / (tp + fn):.4f}  "
          f"FPR {fp / (fp + tn):.5f}  precision {tp / (tp + fp):.4f}")


# 2. Сверка чисел отчёта с логами и таблицами
def read(path):
    return io.open(path, encoding="utf-8").read()


checks = [
    ("logs/cert_user_level2.txt", "recall 5/35 14.3% [ 6.3; 29.4], FPR 3.0% (27 из 888)"),
    ("logs/cert_user_level2.txt", "recall 18/35 51.4% [35.6; 67.0], FPR 2.4% (21 из 888)"),
    ("logs/cert_user_level2.txt", "recall 17/35 48.6% [33.0; 64.4], FPR 3.3% (29 из 888)"),
    ("logs/cert_user_level2.txt", "p = 0.0072"),
    ("logs/cert_user_level2.txt", "p = 0.0118"),
    ("logs/cert_user_level2.txt", "p = 1.0000"),
    ("logs/cert_user_level2.txt", "сц.3: 2/4"),
    ("logs/cert_observed.txt", "21/182 = 11.5%"),
    ("logs/cert_observed.txt", "с device-событиями в тесте: 182"),
    ("logs/cert_observed.txt", "из них без флешки на обучении: 0"),
    ("logs/cert_observed.txt", "сценарий 2: пропущено 13; без единого device-события в окне 0; с device-событиями 13"),
    ("logs/cert_curves.txt", "сц.2 15/15 при FPR 12.2%"),
    ("logs/cert_file_user_level.txt", "ТЕСТ recall 8/35 = 22.9% [12.1; 39.0], user-FPR 3.7% (33/888)"),
    ("logs/cert_file_user_level.txt", "ТЕСТ recall 19/35 = 54.3% [38.2; 69.5], user-FPR 1.9% (17/888)"),
    ("logs/cert_file_user_level.txt", "p = 0.0129"),
    ("logs/audit_independent.txt", "TP 211 FN 1153 FP 2362 TN 241502"),
    ("logs/audit_independent.txt", "инсайдеров 18/35, ложно помечено 21/888"),
    ("logs/audit_independent.txt", "инсайдеров 33/35, ложно помечено 108/888"),
    ("logs/audit_independent.txt", "инсайдеров 5/35, ложно помечено 27/888"),
    ("logs/audit_independent.txt", "инсайдеров 17/35, ложно помечено 29/888"),
    ("logs/audit_independent.txt", "событий device в тесте: 168392"),
    ("logs/audit_independent.txt", "вредоносных по разметке: 3985"),
    ("logs/audit_independent.txt", "с несколькими окнами атаки: 0"),
    ("logs/audit_independent.txt", "окно пересекает границу валидация/тест: 5"),
    ("logs/audit_independent.txt", "вредоносных пар пользователь-день в обучающем периоде: 0"),
    ("logs/cert_leakcheck.txt", "вредоносных пар пользователь-день: 0 из 85044"),
    ("logs/cert_leakcheck.txt", "дней в профилях: 85044"),
    ("logs/cert_honest_split.txt", "валидация: 104095 дней, инсайдеров 35"),
    ("logs/cert_honest_split.txt", "тест:      141133 дней, инсайдеров 35"),
    ("logs/cert_chain_hmac.txt", "9900 записей, зафиксировано 10000"),
    ("logs/cert_riskaware_test.txt", "событий device: 168392"),
    ("logs/cert_riskaware_test.txt", "в цепочке 4.29% событий, защищено 31.8% вредоносных"),
    ("chain_hmac_overhead_results.csv", "100000,117.97,405.78,502.95,537.07,244.0,326.3"),
    ("riskaware_test_results.csv", "0.3,0.00942,7228,4.29,31.8,299.7"),
    ("cert_ablation_results.csv", "device,0.3,211,1153,2362,241502"),
    ("logs/cert_block_baseline.txt", "4.90x"),
    ("logs/cert_block_baseline.txt", "1.92x"),
    ("logs/cert_block_baseline.txt", "1.25x"),
    ("logs/cert_block_baseline.txt", "2.24x"),
    ("logs/cert_block_baseline.txt", "блок 5 (записи 4001..5000)"),
    ("logs/cert_block_baseline.txt", "7. ключ украден, подмена в открытом блоке: ПРОПУЩЕНА"),
    ("block_baseline_results.csv", "hybrid: block B=1000 for all + per-record chain tau=0.3"),
]
missing = 0
for path, text in checks:
    ok = text in read(path)
    missing += not ok
    print(("OK   " if ok else "НЕТ  ") + path + " :: " + text[:70])
print(f"\nпроверено {len(checks)}, не найдено {missing}")
