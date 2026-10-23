"""
ЭТАЛОН КОММИТА d753388 ДЛЯ СВЕРКИ (запускается один раз, не на защите)

Берёт клон GitHub-репозитория на коммите d753388 и сохраняет в a4/reference_d753388/:
  - копии пяти файлов, которые использует A4 (механизмы, атаки, бенчмарк);
  - files.json: SHA-256 каждого файла коммита (переводы строк приведены к LF).
run_a4.py сравнивает с этим эталоном локальный ~/audit-paper/code и пишет итог в environment.txt.

Запуск:  python a4/make_reference.py <путь к клону на d753388>
"""

import hashlib
import json
import os
import subprocess
import sys

A4_FILES = ["cert_chain.py", "cert_chain_hmac.py", "cert_block_baseline.py",
            "cert_tamper_extended.py", "cert_performance_revised.py"]
OUT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "reference_d753388")


def normalized(path):
    """Байты файла с переводами строк LF (Windows-клон может хранить CRLF)."""
    with open(path, "rb") as f:
        return f.read().replace(b"\r\n", b"\n")


def main():
    clone = sys.argv[1]
    commit = subprocess.run(["git", "-C", clone, "rev-parse", "HEAD"],
                            capture_output=True, text=True, check=True).stdout.strip()
    if not commit.startswith("d753388"):
        sys.exit(f"клон на коммите {commit}, а нужен d753388")
    os.makedirs(OUT, exist_ok=True)

    files = subprocess.run(["git", "-C", clone, "ls-files"],
                           capture_output=True, text=True, check=True).stdout.split("\n")
    hashes = {p: hashlib.sha256(normalized(os.path.join(clone, p))).hexdigest()
              for p in files if p}
    with open(os.path.join(OUT, "files.json"), "w", encoding="utf-8") as f:
        json.dump({"commit": commit, "files": hashes}, f, indent=1, ensure_ascii=False)

    for name in A4_FILES:
        with open(os.path.join(OUT, name), "wb") as f:
            f.write(normalized(os.path.join(clone, name)))
    print(f"эталон {commit[:7]}: {len(hashes)} файлов, копии {len(A4_FILES)} файлов в {OUT}")


if __name__ == "__main__":
    main()
