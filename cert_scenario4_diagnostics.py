"""
ЗАДАЧА 13 REVISION_PLAN.md (доп.): ДИАГНОСТИКА СЦЕНАРИЯ 4 (r5.2) ПО ДАННЫМ

Официального описания сценария 4 нет (проверено: в data_r52/ только device.csv и
logon.csv, папки answers нет). Здесь - только диагностика по уже имеющимся данным,
метод НЕ трогается, ничего не подбирается.

Результат: results_revision/scenario4_diagnostics.csv
"""
import csv
from datetime import timedelta
from statistics import median, mean

import cert_ablation as ab
import cert_r52_external_test as r52

windows = r52.load_labels_r52()
ud = r52.load_events_r52()
days = sorted({d for _, d in ud})
train_end = days[0] + timedelta(days=ab.BASELINE_DAYS)
prof = ab.build_profiles(ud, train_end)

info_all = {u: min(w, key=lambda x: x[1]) for u, w in windows.items()}
sc4 = {u: v for u, v in info_all.items() if v[0] == "4"}
print(f"сценарий 4: {len(sc4)} инсайдеров (все, до исключения по границе теста)")

lens = sorted((e - s).days + 1 for u, (sc, s, e) in sc4.items())
print(f"длина окна атаки: мин {lens[0]}, медиана {median(lens)}, среднее {mean(lens):.1f}, макс {lens[-1]} дней")

ev = r52.event_days(ud)
rows = []
no_dev = no_logon = 0
dev_days_list, logon_days_list = [], []
for u, (sc, s, e) in sc4.items():
    dev_in_win = sorted(d for d in ev["device"].get(u, ()) if s <= d <= e)
    log_in_win = sorted(d for d in ev["logon"].get(u, ()) if s <= d <= e)
    dev_days_list.append(len(dev_in_win))
    logon_days_list.append(len(log_in_win))
    if not dev_in_win:
        no_dev += 1
    if not log_in_win:
        no_logon += 1
    # общая активность носителем ВООБЩЕ (train+test), не только в окне - "они вообще не пользуются флешкой" или нет
    dev_total_ever = len(ev["device"].get(u, ()))
    logon_total_ever = len(ev["logon"].get(u, ()))
    win_len = (e - s).days + 1
    rows.append({
        "user": u, "window_start": s, "window_end": e, "window_days": win_len,
        "logon_days_in_window": len(log_in_win), "device_days_in_window": len(dev_in_win),
        "logon_days_ever": logon_total_ever, "device_days_ever": dev_total_ever,
        "device_days_pct_of_window": round(100 * len(dev_in_win) / win_len, 1),
    })

print(f"\nбез единого device-дня в окне: {no_dev} из {len(sc4)}")
print(f"без единого logon-дня в окне: {no_logon} из {len(sc4)}")
print(f"device-дней в окне на человека: медиана {median(dev_days_list)}, среднее {mean(dev_days_list):.2f}")
print(f"logon-дней в окне на человека: медиана {median(logon_days_list)}, среднее {mean(logon_days_list):.1f}")

# Сколько из них вообще ХОТЬ КОГДА-ТО (train+test) пользовались носителем
ever_used_device = sum(1 for r in rows if r["device_days_ever"] > 0)
print(f"\nиз {len(sc4)} сценария 4: хоть раз пользовались носителем за всё время (train+test): {ever_used_device}")

# Сравнение с обычными (не-инсайдер) популяцией: доля дней с device относительно logon-дней в тесте
normal_users = set(prof.keys()) - set(windows.keys())
normal_dev_share = []
for u in list(normal_users)[:2000]:
    ld = len(ev["logon"].get(u, ()))
    dd = len(ev["device"].get(u, ()))
    if ld > 0:
        normal_dev_share.append(dd / ld)
print(f"обычные пользователи: доля device-дней от logon-дней, медиана по {len(normal_dev_share)} чел.: "
      f"{median(normal_dev_share):.3f}")
sc4_dev_share = [r["device_days_ever"] / r["logon_days_ever"] for r in rows if r["logon_days_ever"] > 0]
print(f"сценарий 4: та же доля, медиана по {len(sc4_dev_share)} чел.: {median(sc4_dev_share):.3f}")

with open("results_revision/scenario4_diagnostics.csv", "w", newline="", encoding="utf-8") as f:
    w = csv.DictWriter(f, fieldnames=list(rows[0].keys()))
    w.writeheader()
    w.writerows(rows)
print("\nсохранено: results_revision/scenario4_diagnostics.csv")
