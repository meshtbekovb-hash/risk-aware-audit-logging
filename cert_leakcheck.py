"""
ПРОВЕРКА НА УТЕЧКУ ИЗ БУДУЩЕГО И НА ПОДГОНКУ ПОРОГА

Четыре проверки для cert_ablation.py:
  1. В профили попадают только дни строго до разделения обучение/тест.
  2. Тестовые дни не пересекаются с обучающими.
  3. Обучающий период не заражён: сколько вредоносных дней (по окнам атак
     CMU SEI) попало в профили пользователей. Если инсайдер уже "атаковал"
     до разделения, его профиль включает вредоносное поведение.
  4. Порог выбирается на одних данных, а оценивается на других: тестовый
     период делится по времени пополам, порог подбирается на первой половине
     (FPR не выше 1%), а качество меряется на второй.

Запуск (из папки с CSV):  python cert_leakcheck.py
"""

from datetime import timedelta

import cert_ablation as ab

CONFIGS = [("logon", "A. только logon"),
           ("device", "B. только device"),
           ("combined", "C. logon + device")]


def main():
    windows = ab.load_labels()
    ud = ab.load_events()
    days = sorted({d for _, d in ud})
    split = days[0] + timedelta(days=ab.BASELINE_DAYS)
    prof = ab.build_profiles(ud, split)

    # --- Проверка 1 и 2: границы обучения и теста ---
    train_keys = [k for k in ud if k[1] < split]
    test_keys = [k for k in ud if k[1] >= split]
    print("Проверка 1-2. Границы обучения и теста")
    print(f"  разделение по дате:             {split}")
    print(f"  последний обучающий день:       {max(d for _, d in train_keys)}")
    print(f"  первый тестовый день:           {min(d for _, d in test_keys)}")
    print(f"  пересечение обучения и теста:   {len(set(train_keys) & set(test_keys))} пар")
    profile_days = sum(p["days"] for p in prof.values())
    print(f"  дней в профилях: {profile_days}, обучающих пар: {len(train_keys)}"
          f" -> {'совпадает' if profile_days == len(train_keys) else 'НЕ СОВПАДАЕТ'}\n")

    # --- Проверка 3: заражённость обучающего периода ---
    bad_train = [k for k in train_keys if ab.scenario_of(windows, k[0], k[1])]
    users_bad = {u for u, _ in bad_train}
    print("Проверка 3. Вредоносные дни внутри обучающего периода")
    print(f"  вредоносных пар пользователь-день: {len(bad_train)} "
          f"из {len(train_keys)} ({100 * len(bad_train) / len(train_keys):.3f}%)")
    print(f"  затронуто инсайдеров: {len(users_bad)} из {len(windows)}\n")

    # --- Проверка 4: порог на одной половине теста, оценка на другой ---
    test_days = sorted({d for _, d in test_keys})
    mid = test_days[len(test_days) // 2]
    calib = [k for k in test_keys if k[1] < mid]
    evalu = [k for k in test_keys if k[1] >= mid]
    print("Проверка 4. Порог подбирается на первой половине теста, "
          "оценивается на второй")
    print(f"  калибровка: до {mid} ({len(calib)} дней), "
          f"оценка: с {mid} ({len(evalu)} дней)\n")

    for cfg, title in CONFIGS:
        def rows_of(keys):
            return [(ab.score(ud[k], prof.get(k[0]), cfg),
                     ab.scenario_of(windows, k[0], k[1])) for k in keys]
        calib_rows, eval_rows = rows_of(calib), rows_of(evalu)

        cutoff, m_cal = ab.pick_cutoff(calib_rows, ab.TARGET_FPR)
        m_eval, _, _ = ab.metrics(eval_rows, cutoff)
        # Для сравнения: порог, подобранный сразу на оценочной половине
        cut_own, m_own = ab.pick_cutoff(eval_rows, ab.TARGET_FPR)

        print(f"{title}")
        print(f"  порог с калибровки {cutoff}: на калибровке recall {m_cal['recall']:.3f} "
              f"FPR {m_cal['fpr']:.4f}  ->  на оценке recall {m_eval['recall']:.3f} "
              f"FPR {m_eval['fpr']:.4f}")
        print(f"  (порог, подобранный прямо на оценке: {cut_own}, "
              f"recall {m_own['recall']:.3f} FPR {m_own['fpr']:.4f})\n")


if __name__ == "__main__":
    main()
