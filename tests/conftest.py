"""
Общая настройка тестов.

Тесты импортируют скрипты прототипа (cert_chain.py и другие) из папки code, а если её нет
(плоская раскладка этого репозитория), то из корня проекта.
Чтобы прогнать те же тесты на другой версии кода (например, на ветке main из GitHub),
задайте переменную окружения AUDIT_CODE_DIR с путём к папке, где лежат скрипты:

    AUDIT_CODE_DIR=путь/к/другой/версии python -m pytest tests

Тестам не нужны данные CERT: журналы создаются искусственно, прямо в тесте.
"""

import os
import sys

PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DEFAULT_CODE_DIR = os.path.join(PROJECT_ROOT, "code")
if not os.path.isdir(DEFAULT_CODE_DIR):
    DEFAULT_CODE_DIR = PROJECT_ROOT
CODE_DIR = os.environ.get("AUDIT_CODE_DIR", DEFAULT_CODE_DIR)
sys.path.insert(0, CODE_DIR)


def pytest_report_header(config):
    return f"prototype code under test: {CODE_DIR}"
