"""
АНОНИМИЗАЦИЯ ДОКАЗАТЕЛЬСТВ ПЕРЕД ПУБЛИКАЦИЕЙ

Заменяет в текстовых файлах прогона имя пользователя Windows (папка профиля и логин) на <user>,
а имя компьютера на <host>. Числа замеров не трогаются: меняются только эти слова целиком
(например, «mesht» внутри «meshtbekovb-hash» в адресе GitHub остаётся как есть).

Запуск:  python a4/anonymize_evidence.py <run id> [ещё файлы ...]
         (run_a4.py вызывает его сам в конце прогона)
"""

import getpass
import glob
import os
import platform
import re
import sys

A4 = os.path.dirname(os.path.abspath(__file__))
EVIDENCE = os.path.join(A4, "evidence")
TEXT_EXT = (".txt", ".log", ".csv", ".md", ".json")


def replacements():
    """Пары (регулярное выражение, замена). Сначала пути, потом отдельные слова."""
    profile = os.path.basename(os.path.expanduser("~"))       # папка профиля, например C:\Users\<name>
    login = getpass.getuser()
    host = platform.node()
    pairs = []
    for name in sorted({profile, login}, key=len, reverse=True):
        if name:
            pairs.append((re.compile(r"(?i)([\\/]Users[\\/])" + re.escape(name) + r"(?=[\\/)\s'\"]|$)"),
                          r"\1<user>"))
    for name, tag in ((host, "<host>"), (login, "<user>"), (profile, "<user>")):
        if name:
            pairs.append((re.compile(r"(?i)(?<![\w-])" + re.escape(name) + r"(?![\w-])"), tag))
    return pairs


def anonymize_file(path, pairs):
    with open(path, encoding="utf-8", newline="") as f:      # переводы строк сохраняются как есть
        text = f.read()
    new = text
    for rx, rep in pairs:
        new = rx.sub(rep, new)
    if new != text:
        with open(path, "w", encoding="utf-8", newline="") as f:
            f.write(new)
        return True
    return False


def main():
    run = sys.argv[1]
    files = [p for p in glob.glob(os.path.join(EVIDENCE, f"*_{run}.*")) if p.endswith(TEXT_EXT)]
    files += [p for p in glob.glob(os.path.join(EVIDENCE, f"work_{run}", "**", "*"), recursive=True)
              if p.endswith(TEXT_EXT)]
    files += sys.argv[2:]
    pairs = replacements()
    changed = [os.path.relpath(p, A4) for p in files if anonymize_file(p, pairs)]
    print(f"anonymized {len(changed)} of {len(files)} files: " + ", ".join(changed))


if __name__ == "__main__":
    main()
