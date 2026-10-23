"""
ТЕСТЫ РАСЧЁТА МЕТРИК

Каждая функция, из которой получаются цифры обнаружения в статье, проверяется на
маленьком примере, где правильный ответ посчитан вручную (расчёт в комментариях).
Данные CERT не нужны.

Запуск из корня проекта:  python -m pytest tests -v
"""

from datetime import date

import pytest

import cert_ablation as ab
import cert_detection_metrics as dm
import cert_user_level as ul
import cert_user_level2 as ul2


def d(day):
    return date(2010, 10, day)


# ---------------------------------------------------------------
# Интервал Уилсона и тест знаков
# ---------------------------------------------------------------
def test_wilson_interval_for_5_of_10():
    # p = 0.5, z = 1.96, n = 10: знаменатель 1 + 3.8416/10 = 1.38416
    # центр = (0.5 + 0.19208) / 1.38416 = 0.5
    # полуширина = 1.96 * sqrt(0.025 + 0.009604) / 1.38416 = 0.2634
    lo, hi = ul2.wilson(5, 10)
    assert lo == pytest.approx(0.2366, abs=1e-4)
    assert hi == pytest.approx(0.7634, abs=1e-4)


def test_wilson_interval_for_18_of_35_matches_paper():
    # Статья, Table III: recall 51.4% (95% CI 35.6-67.0) для 18 из 35
    lo, hi = ul2.wilson(18, 35)
    assert round(100 * lo, 1) == 35.6
    assert round(100 * hi, 1) == 67.0


def test_both_wilson_implementations_agree():
    assert dm.wilson(30, 98) == pytest.approx(ul2.wilson(30, 98))


def test_sign_test_by_hand():
    # 8 расхождений, все в одну сторону: 2 * (1/2)^8 = 2/256
    assert ul2.sign_test(8, 0) == pytest.approx(2 / 256)
    # нет расхождений - нет оснований отвергать гипотезу
    assert ul2.sign_test(0, 0) == 1.0
    # порядок аргументов не важен (тест двусторонний)
    assert ul2.sign_test(3, 11) == ul2.sign_test(11, 3)
    # 2 расхождения из 2 в одну сторону: 2 * 1/4 = 0.5
    assert ul2.sign_test(2, 0) == pytest.approx(0.5)


# ---------------------------------------------------------------
# Правило накопления (N, W)
# ---------------------------------------------------------------
def test_firing_days_needs_n_alert_days_inside_window():
    alert_days = [d(1), d(2), d(9)]
    # N=2, W=7: 2-го в окне [26.09..2.10] два тревожных дня; 9-го в окне [3..9] один
    assert ul.firing_days(alert_days, 2, 7) == [d(2)]
    # N=1: срабатывает каждый тревожный день
    assert ul.firing_days(alert_days, 1, 7) == alert_days
    # N=2, W=1: в один день двух тревожных дней не бывает
    assert ul.firing_days(alert_days, 2, 1) == []
    # N=2, W=8: 9-го в окне [2..9] тревожные 2-е и 9-е
    assert ul.firing_days(alert_days, 2, 8) == [d(2), d(9)]


def test_user_level_recall_and_fpr_by_hand():
    # Два инсайдера с окном атаки 10-12 октября, правило N=2, W=7.
    # A: тревожные дни 10 и 11 -> срабатывание 11-го, внутри окна -> пойман, задержка 1 день.
    # B: тревожные дни 1 и 2  -> срабатывание 2-го, вне окна      -> не пойман.
    insiders = {"A": (1, d(10), d(12)), "B": (2, d(10), d(12))}
    # Три обычных пользователя: n1 срабатывает (ложная тревога), n2 один тревожный день, n3 без тревог.
    alerts = {"A": [d(10), d(11)], "B": [d(1), d(2)], "n1": [d(5), d(6)], "n2": [d(5)]}
    normal = {"n1", "n2", "n3"}

    r = ul.evaluate(alerts, insiders, normal, 2, 7)

    assert r["insiders_caught"] == 1 and r["insiders_total"] == 2
    assert r["recall"] == 0.5
    assert r["false_users"] == 1 and r["normal_users"] == 3
    assert r["fpr"] == pytest.approx(1 / 3)
    assert r["median_delay_days"] == 1
    assert r["caught_by_scenario"] == {1: 1, 2: 0}

    r2 = ul2.evaluate(alerts, None, insiders, normal, 2, 7)
    assert r2["caught"] == {"A"} and r2["false"] == {"n1"}
    assert r2["recall"] == 0.5 and r2["fpr"] == pytest.approx(1 / 3)


# ---------------------------------------------------------------
# Дневные метрики: precision, recall, F1, FPR
# ---------------------------------------------------------------
def test_day_level_metrics_by_hand():
    # (оценка риска, сценарий или None для обычного дня), порог 0.65
    rows = [(0.9, 1),       # вредоносный, тревога   -> TP
            (0.2, 1),       # вредоносный, без тревоги -> FN
            (0.7, None),    # обычный, тревога       -> FP
            (0.1, None),    # обычный, без тревоги   -> TN
            (0.0, None)]    # обычный, без тревоги   -> TN

    m, caught, total = ab.metrics(rows, 0.65)

    assert (m["TP"], m["FN"], m["FP"], m["TN"]) == (1, 1, 1, 2)
    assert m["precision"] == 0.5      # 1 / (1 + 1)
    assert m["recall"] == 0.5         # 1 / (1 + 1)
    assert m["f1"] == 0.5             # 2 * 0.5 * 0.5 / (0.5 + 0.5)
    assert m["fpr"] == 0.33333        # 1 / (1 + 2), округление до 5 знаков
    assert caught[1] == 1 and total[1] == 2


def test_metrics_with_no_alerts_do_not_divide_by_zero():
    m, _, _ = ab.metrics([(0.1, 1), (0.1, None)], 0.65)
    assert m["precision"] == 0.0 and m["recall"] == 0.0 and m["f1"] == 0.0 and m["fpr"] == 0.0


def test_average_precision_by_hand():
    # точки (recall, precision): 0.5 * 1.0 + (1.0 - 0.5) * 0.5 = 0.75
    assert dm.average_precision([(1.0, 0.5), (0.5, 1.0)]) == pytest.approx(0.75)


# ---------------------------------------------------------------
# Оценка риска: веса и уровни из статьи (0.30, 0.65, 0.95 для device)
# ---------------------------------------------------------------
PROFILE = {"days": 100, "off": 0, "wknd": 0, "pcs": {"PC-1"}, "dev_total": 100, "dev_off": 0}
QUIET_DAY = {"logon_off": 0, "logon_wknd": 0, "pcs": {"PC-1"}, "dev": 1, "dev_off": 0}


def day(**changes):
    return {**QUIET_DAY, **changes}


def test_device_score_takes_the_three_levels_stated_in_the_paper():
    assert ab.score(QUIET_DAY, PROFILE, "device") == 0.0
    # всплеск: 4 подключения при среднем 1 в день (больше 3 средних) -> 0.30
    assert ab.score(day(dev=4), PROFILE, "device") == pytest.approx(0.30)
    # носитель вне рабочих часов, раньше такого не было -> 0.65
    assert ab.score(day(dev_off=1), PROFILE, "device") == pytest.approx(0.65)
    # оба признака -> 0.95
    assert ab.score(day(dev=4, dev_off=1), PROFILE, "device") == pytest.approx(0.95)


def test_spike_needs_strictly_more_than_three_times_the_average():
    assert ab.score(day(dev=3), PROFILE, "device") == 0.0


def test_logon_score_weights():
    assert ab.score(day(logon_off=1), PROFILE, "logon") == pytest.approx(0.45)
    assert ab.score(day(logon_wknd=1), PROFILE, "logon") == pytest.approx(0.30)
    assert ab.score(day(pcs={"PC-1", "PC-2"}), PROFILE, "logon") == pytest.approx(0.50)


def test_habitual_behaviour_is_not_an_anomaly():
    # пользователь и раньше работал вне рабочих часов в 10% дней и больше
    habitual = {**PROFILE, "off": 10, "dev_off": 5}
    assert ab.score(day(logon_off=1), habitual, "logon") == 0.0
    assert ab.score(day(dev_off=1), habitual, "device") == 0.0


def test_score_is_capped_at_one_and_zero_without_profile():
    everything = day(logon_off=1, logon_wknd=1, pcs={"PC-9"}, dev=4, dev_off=1)
    assert ab.score(everything, PROFILE, "combined") == 1.0      # сумма весов 2.20
    assert ab.score(everything, None, "combined") == 0.0
    assert ab.score(everything, {**PROFILE, "days": 0}, "combined") == 0.0
