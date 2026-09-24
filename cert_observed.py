"""
НАБЛЮДАЕМАЯ ПОПУЛЯЦИЯ и МОЩНОСТЬ ТЕСТА ЗНАКОВ

Проблема. user-FPR считался от ВСЕХ 888 обычных пользователей, но многие из них
вообще не имеют событий того типа, который использует конфигурация (например,
не пользуются съёмными носителями). Такие люди почти не могут получить тревогу
и разбавляют знаменатель. Поэтому для каждой конфигурации считаем ДВЕ версии:

  по всей популяции      - знаменатель: все обычные пользователи / все инсайдеры
  по наблюдаемой         - знаменатель: только те, у кого в тестовом периоде есть
                           события нужного типа (device: подключения носителей,
                           logon: входы, logon+device: любые из них).
                           Для инсайдеров событие должно попасть в ИХ окно атаки.

Обе версии показываем рядом. Recall по наблюдаемым инсайдерам - диагностика
("метод пропустил" против "метод физически не видит"), а не замена
главной цифры: невидимый инсайдер всё равно пропущен.

Также проверяем:
  - что у пропущенных инсайдеров сценария 2 есть записи в device.csv;
  - мощность парного теста знаков: сколько дискордантных пар и мог ли тест
    вообще дать значимый результат.

Параметры (порог, N, W) берутся из выбора на ВАЛИДАЦИИ (cert_user_level2.py).
Запуск (из папки с CSV):  python cert_observed.py
"""

from collections import defaultdict

import cert_ablation as ab
import cert_honest_split as hs
import cert_user_level2 as u2

CFG_KIND = {"logon": ("logon",), "device": ("device",), "logon+device": ("logon", "device")}


def event_days(ud):
    """Для каждого пользователя и типа событий - множество дней с такими событиями."""
    days = {"logon": defaultdict(set), "device": defaultdict(set)}
    for (user, day), v in ud.items():
        if v["pcs"]:
            days["logon"][user].add(day)      # были входы (Logon)
        if v["dev"] > 0:
            days["device"][user].add(day)     # были подключения носителя (Connect)
    return days


def main():
    st = u2.Setup()
    ev = event_days(st.ud)
    test_normal = st.normal["тест"]
    test_ins = st.parts["тест"][1]

    def user_has(kinds, user, lo=None, hi=None):
        """Есть ли у пользователя событие нужного типа в тестовом периоде (и в окне [lo, hi])."""
        for kind in kinds:
            for d in ev[kind].get(user, ()):
                if d >= hs.TEST_START and (lo is None or lo <= d <= hi):
                    return True
        return False

    # Проверка предпосылки: кто из обычных пользователей вообще имеет device-события в тесте
    dev_test = {x for x in test_normal if user_has(("device",), x)}
    base_zero = {x for x in dev_test if not (st.prof.get(x) and st.prof[x]["dev_total"] > 0)}
    print(f"обычных пользователей: {len(test_normal)}; с device-событиями в тесте: {len(dev_test)}; "
          f"из них без флешки на обучении: {len(base_zero)}\n")

    chosen, results = {}, {}
    for name, cfg in u2.CONFIGS:
        used = hs.CONFIG_FEATURES[cfg]
        p, _ = u2.select_on_validation(st, used, hybrid=False)   # выбор только по валидации
        r = st.run("тест", used, p["cutoff"], p["N"], p["W"])
        chosen[name], results[name] = p, r

    print("=" * 110)
    print("ЗАДАЧА 1. Четыре числа: recall и FPR по всей и по наблюдаемой популяции (тест)")
    print("=" * 110)
    print(f"{'конфигурация':13} {'параметры':22} | recall всей выборки | recall наблюдаемых  | "
          f"FPR всех          | FPR наблюдаемых")
    for name, _ in u2.CONFIGS:
        p, r = chosen[name], results[name]
        kinds = CFG_KIND[name]
        obs_ins = {u for u, (sc, s, e) in test_ins.items() if user_has(kinds, u, s, e)}
        obs_norm = {x for x in test_normal if user_has(kinds, x)}
        caught_obs = r["caught"] & obs_ins
        false_obs = r["false"] & obs_norm
        print(f"{name:13} {p['cutoff']:<4} N={p['N']} W={p['W']:<3}        | "
              f"{len(r['caught']):>2}/35 = {100 * r['recall']:4.1f}%    | "
              f"{len(caught_obs):>2}/{len(obs_ins):<2} = {100 * len(caught_obs) / len(obs_ins):4.1f}%    | "
              f"{len(r['false']):>3}/{len(test_normal)} = {100 * r['fpr']:4.1f}% | "
              f"{len(false_obs):>3}/{len(obs_norm)} = {100 * len(false_obs) / len(obs_norm):4.1f}%")
        if r["false"] - obs_norm:
            print(f"   (внимание: {len(r['false'] - obs_norm)} ложных вне наблюдаемой популяции)")

    # Пропущенные инсайдеры сценария 2 при выбранной точке device: есть ли у них device-записи
    print("\nПропущенные инсайдеры device (тест): физически невидимы или пропущены?")
    p, r = chosen["device"], results["device"]
    a_low = st.alerts("тест", hs.CONFIG_FEATURES["device"], 0.30)   # для сравнения: мягкий порог
    a_sel = st.alerts("тест", hs.CONFIG_FEATURES["device"], p["cutoff"])
    counts = defaultdict(lambda: [0, 0, 0, 0])   # сценарий -> [пропущено, без device-записей, есть записи, ловятся при 0.30]
    for u, (sc, s, e) in sorted(test_ins.items(), key=lambda x: (x[1][0], x[0])):
        if u in r["caught"]:
            continue
        n_dev = sum(1 for d in ev["device"].get(u, ()) if s <= d <= e and d >= hs.TEST_START)
        low = [d for d in a_low.get(u, []) if s <= d <= e]
        c = counts[sc]
        c[0] += 1
        c[1 if n_dev == 0 else 2] += 1
        c[3] += 1 if low else 0
        if sc == "2":
            print(f"  сц.2 {u}: подключений носителя в окне {n_dev:>3}; "
                  f"тревожных дней в окне при пороге {p['cutoff']}: {len([d for d in a_sel.get(u, []) if s <= d <= e])}, "
                  f"при пороге 0.30: {len(low)}")
    for sc in sorted(counts):
        c = counts[sc]
        print(f"  сценарий {sc}: пропущено {c[0]}; без единого device-события в окне {c[1]}; "
              f"с device-событиями {c[2]}; из пропущенных ловятся при пороге 0.30 (хотя бы 1 тревога): {c[3]}")

    # ------------------------------------------------------------
    # Задача 2: мощность теста знаков
    # ------------------------------------------------------------
    print("\n" + "=" * 110)
    print("ЗАДАЧА 2. Мощность парного теста знаков (тест, 35 инсайдеров)")
    print("=" * 110)
    names = [n for n, _ in u2.CONFIGS]
    for i in range(len(names)):
        for j in range(i + 1, len(names)):
            a, b = results[names[i]]["caught"], results[names[j]]["caught"]
            only_a, only_b = len(a - b), len(b - a)
            m = only_a + only_b
            min_p = 1.0 if m == 0 else min(1.0, 2 / 2 ** m)   # лучший возможный p при m дискордантных парах
            p = u2.sign_test(only_a, only_b)
            note = ("ТЕСТ НЕ ИМЕЕТ МОЩНОСТИ (меньше 5 дискордантных пар): писать 'различие не обнаружено', а не 'различия нет'"
                    if m < 5 else "дискордантных пар достаточно для вывода")
            print(f"  {names[i]} / {names[j]}: только первая {only_a}, только вторая {only_b}, всего дискордантных {m}; "
                  f"наименьший достижимый p при таком m: {min_p:.4f}; фактический p = {p:.4f}; {note}")
    print("  (для p < 0.05 нужно не менее 6 дискордантных пар, и все в одну сторону)")


if __name__ == "__main__":
    main()
