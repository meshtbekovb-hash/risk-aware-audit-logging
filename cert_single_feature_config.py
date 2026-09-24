"""
ЗАДАЧА 12 REVISION_PLAN.md (доп.): ОДНОПРИЗНАКОВАЯ КОНФИГУРАЦИЯ КАК ПОЛНОЦЕННЫЙ ВАРИАНТ

Из задачи 4 видно: один признак novel_dev_off_hours (вес 1.0, остальные не используются)
ловит тех же 18 инсайдеров на тесте r4.2, что и вся пятипризнаковая модель device. Здесь
эта конфигурация прогоняется полным набором метрик задачи 5 (precision, F1, PR-AUC,
event recall, задержка, ложные тревоги/мес, recall по сценариям) на r4.2 И на r5.2,
сравнивается с device и logon+device в одной таблице.

ВАЖНАЯ МЕТОДИЧЕСКАЯ ОГОВОРКА (нельзя обойти молчанием). Сама идея "взять только этот
признак" родилась ПОСЛЕ того, как в задаче 4 увидели совпадение множеств пойманных на
ТЕСТЕ r4.2. Это post-hoc решение: если бы совпадения не было, конфигурацию не стали бы
выделять отдельно. Поэтому:
  - результат этой конфигурации на r4.2 - НЕ независимая проверка, он выведен из
    наблюдения на том же самом тесте, который здесь же и оценивается (смещение по
    построению, не устранимо задним числом);
  - результат на r5.2 - НЕЗАВИСИМАЯ проверка, потому что r5.2 не участвовал и не мог
    участвовать в выборе этой конфигурации (выбор сделан целиком по r4.2, r5.2 в тот
    момент ещё не рассматривался в этом контексте).

Порог tau, N и W для однопризнаковой конфигурации ПОДБИРАЮТСЯ на валидации r4.2 тем же
протоколом, что и все остальные конфигурации (наибольший user recall при user FPR <= 3%
на валидации) - это единственное, что здесь "подбирается", и подбирается честно, не по
тесту. Признак фиксирован заранее (novel_dev_off_hours). Вес НЕ меняется на 1.0 - берётся
тот же ab.WEIGHTS["novel_dev_off_hours"] = 0.65, что и во всех остальных конфигурациях
(cert_detection_metrics.analyze_config считает оценку риска через ab.WEIGHTS без
исключений, и вес всё равно не влияет на то, какие дни сработают: при единственном
признаке в наборе есть только ОДИН достижимый уровень оценки, WEIGHTS[feature] - будь он
0.65 или 1.0, набор дней с "признак сработал" один и тот же, меняется только число, с
которым сравнивается порог. Использование родного веса 0.65 без изменений - самый простой
способ не разойтись с analyze_config и избежать путаницы с двумя разными "версиями" веса
для одного и того же признака в одном отчёте).

Результат: results_revision/single_feature_config.csv
Запуск (из папки с CSV):  python cert_single_feature_config.py
"""

import csv
from datetime import timedelta

import cert_ablation as ab
import cert_honest_split as hs
import cert_user_level2 as u2
import cert_r52_external_test as r52
from cert_detection_metrics import analyze_config, FROZEN as FROZEN5, CFG_JOURNALS, DATE_FORMAT

OUTPUT_FILE = "results_revision/single_feature_config.csv"
SINGLE_USED = ["novel_dev_off_hours"]


def select_single_feature_params(st):
    """Тот же протокол выбора (tau, N, W), что у всех конфигураций - только на валидации,
    только по правилу 'наибольший user recall при user FPR <= 3%'. Использует ту же функцию
    u2.select_on_validation, что и штатные конфигурации (device, logon+device) - никакого
    отдельного пути для этого варианта, чтобы гарантированно не разойтись с analyze_config,
    который использует ab.WEIGHTS без изменений."""
    sel = u2.select_on_validation(st, SINGLE_USED, hybrid=False)
    if sel is None:
        raise SystemExit("На валидации r4.2 нет порога с user FPR <= 3% для однопризнаковой конфигурации")
    p, v = sel
    return p, v


def main():
    print("Выбор (tau, N, W) для однопризнаковой конфигурации (novel_dev_off_hours, вес 1.0) на ВАЛИДАЦИИ r4.2...")
    st = u2.Setup()
    p, v = select_single_feature_params(st)
    print(f"выбрано: tau={p['cutoff']}, N={p['N']}, W={p['W']} "
          f"(валидация: {len(v['caught'])}/35, FPR {100*v['fpr']:.1f}%)\n")
    print("НАПОМИНАНИЕ: сама идея тестировать именно этот признак отдельно появилась после того, как в задаче 4 "
          "увидели совпадение множеств пойманных на тесте r4.2 - результат ниже на r4.2 это НЕ независимая проверка. "
          "Независима только часть на r5.2.\n")

    FROZEN = dict(FROZEN5)
    FROZEN["device_single (novel_dev_off_hours only)"] = {"cfg": None, "cutoff": p["cutoff"], "N": p["N"], "W": p["W"]}

    rows = []

    # ---- r4.2 ----
    print("=" * 100)
    print("r4.2 (тест r4.2 - для однопризнаковой конфигурации это POST-HOC, не независимо)")
    print("=" * 100)
    test_start, test_end = hs.TEST_START, max(d for _, d in st.ud)
    event_paths_42 = {"logon": ab.LOGON_FILE, "device": ab.DEVICE_FILE}
    for name, pp in FROZEN.items():
        used = SINGLE_USED if pp["cfg"] is None else hs.CONFIG_FEATURES[pp["cfg"]]
        journals = ["device"] if pp["cfg"] is None else CFG_JOURNALS[name]
        paths = {j: event_paths_42[j] for j in journals}
        m = analyze_config(name, pp, used, st.ud, st.prof, st.windows,
                            st.parts["тест"][0], st.parts["тест"][1], st.normal["тест"],
                            test_start, test_end, paths, DATE_FORMAT, st.pattern)
        m["dataset"] = "r4.2"
        m["is_independent"] = "нет (post-hoc)" if pp["cfg"] is None else "да (штатная конфигурация)"
        rows.append(m)
        print(f"{name:40} recall {m['insiders_caught']}/{m['insiders_total']}={100*m['user_recall']:.1f}% "
              f"precision {m['user_precision']:.3f} F1 {m['user_f1']:.3f} PR-AUC {m['pr_auc']:.3f}")

    # ---- r5.2 ----
    print("\n" + "=" * 100)
    print("r5.2 (для однопризнаковой конфигурации это НЕЗАВИСИМАЯ проверка - r5.2 не участвовал в выборе)")
    print("=" * 100)
    windows52 = r52.load_labels_r52()
    ud52 = r52.load_events_r52()
    days52 = sorted({d for _, d in ud52})
    train_end52 = days52[0] + timedelta(days=ab.BASELINE_DAYS)
    prof52 = ab.build_profiles(ud52, train_end52)
    test_keys52 = [k for k in ud52 if k[1] >= train_end52]
    info_all52 = {u: min(w, key=lambda x: x[1]) for u, w in windows52.items()}
    insiders_test52 = {u: v for u, v in info_all52.items() if v[1] >= train_end52}
    normal_test52 = {k[0] for k in test_keys52} - set(windows52)
    test_end52 = max(d for _, d in ud52)
    event_paths_52 = {"logon": r52.LOGON_FILE_R52, "device": r52.DEVICE_FILE_R52}
    pattern52 = {k: hs.day_pattern(ud52[k], prof52.get(k[0])) for k in test_keys52}

    for name, pp in FROZEN.items():
        used = SINGLE_USED if pp["cfg"] is None else hs.CONFIG_FEATURES[pp["cfg"]]
        journals = ["device"] if pp["cfg"] is None else CFG_JOURNALS[name]
        paths = {j: event_paths_52[j] for j in journals}
        m = analyze_config(name, pp, used, ud52, prof52, windows52,
                            test_keys52, insiders_test52, normal_test52,
                            train_end52, test_end52, paths, r52.DATE_FORMAT, pattern52)
        m["dataset"] = "r5.2"
        m["is_independent"] = "да (r5.2 не участвовал в выборе конфигурации)" if pp["cfg"] is None else "да (штатная конфигурация)"
        rows.append(m)
        print(f"{name:40} recall {m['insiders_caught']}/{m['insiders_total']}={100*m['user_recall']:.1f}% "
              f"precision {m['user_precision']:.3f} F1 {m['user_f1']:.3f} PR-AUC {m['pr_auc']:.3f}")

    fields = ["dataset", "is_independent"] + [k for k in rows[0].keys() if k not in ("dataset", "is_independent")]
    with open(OUTPUT_FILE, "w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=fields)
        w.writeheader()
        w.writerows(rows)
    print(f"\nТаблица сохранена: {OUTPUT_FILE}")


if __name__ == "__main__":
    main()
