"""
Общая настройка тестов.

Тесты импортируют скрипты прототипа (cert_chain.py и другие) из папки code.
Чтобы прогнать те же тесты на другой версии кода (например, на ветке main из GitHub),
задайте переменную окружения AUDIT_CODE_DIR с путём к папке, где лежат скрипты:

    AUDIT_CODE_DIR=путь/к/другой/версии python -m pytest tests

Тестам не нужны данные CERT: журналы создаются искусственно, прямо в тесте.
"""

import os
import sys

PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
CODE_DIR = os.environ.get("AUDIT_CODE_DIR", os.path.join(PROJECT_ROOT, "code"))
sys.path.insert(0, CODE_DIR)


def pytest_report_header(config):
    return f"prototype code under test: {CODE_DIR}"
