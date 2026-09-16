# -*- coding: utf-8 -*-
"""Обновить снимок списка отозванных ключей аттестации Google.

ЗАЧЕМ ЭТО ЕСТЬ. Google ведёт список ключей аттестации, которые скомпрометированы
или отозваны: https://android.googleapis.com/attestation/status

Обладатель такого ключа собирает цепочку сертификатов, которая проходит проверку
корня, и объявляет в ней что угодно — заблокированный загрузчик, StrongBox, свой
публичный ключ, — не притрагиваясь к телефону. То есть без этой проверки
утверждения об устройстве (раздел 4.2–4.4 спецификации) теряют смысл: все они
читаются из той же цепочки, которую нападающий и сочинил.

На 14 сентября 2026 в списке 1746 записей, из них 1720 с причиной
KEY_COMPROMISE.

ПОЧЕМУ СНИМОК, А НЕ ЗАПРОС ПРИ КАЖДОЙ ПРОВЕРКЕ. Проверка обязана работать без
сети: файл должен открываться через год на чужой машине с выключенным
интернетом. Ходить за списком в Google при каждой проверке это ломает.

Поэтому ядро несёт снимок с датой, и дата видна в тексте проверки: «список
отзыва на такое-то число». Честнее, чем молчать о том, что данные не свежие.
Тот, кто проверяет на сервере и всегда в сети, может передать свежий список
доводом `verifyPackage(entries, { revoked, revokedDate })` — тогда снимок не
используется.

ЧТО ДЕЛАЕТ ЭТОТ СКРИПТ. Берёт список (из сети или из готового файла) и
перезаписывает `src/verify-core/revoked-keys.ts`.

    python tools/update_revoked.py                    # скачать и записать
    python tools/update_revoked.py статус.json        # из файла, без сети
    python tools/update_revoked.py статус.json стр.html   # заодно обновить
                                                          # вторую копию

Второй довод нужен, только если у вас есть вторая реализация проверки со своим
встроенным списком (у нас это страница проверки в браузере). Тогда список
кладётся в неё между метками «ОТЗЫВ: начало/конец списка» — из одного источника,
чтобы копии не могли разойтись. Нет такой копии — довод не нужен.

ФОРМАТ КЛЮЧА по документации Google: серийный номер сертификата
шестнадцатерично, нижним регистром, без ведущих нулей — шаблон
`^[a-f1-9][a-f0-9]*$`. Проверять надо ВСЕ звенья цепочки, не только корень или
лист.
"""
import datetime
import io
import json
import os
import re
import sys
import urllib.request

URL = "https://android.googleapis.com/attestation/status"
HERE = os.path.dirname(os.path.abspath(__file__))
TS = os.path.join(HERE, "..", "src", "verify-core", "revoked-keys.ts")

BEGIN = "/* ── ОТЗЫВ: начало списка (обновляется tools/update_revoked.py) ── */"
END = "/* ── ОТЗЫВ: конец списка ── */"

PAT = re.compile(r"^[a-f1-9][a-f0-9]*$")


def load(src):
    if src and src != "-":
        with io.open(src, "r", encoding="utf-8") as fh:
            return json.load(fh)
    req = urllib.request.Request(URL, headers={"User-Agent": "trustvisor-revoked-updater"})
    with urllib.request.urlopen(req, timeout=60) as r:
        return json.loads(r.read().decode("utf-8"))


def write_ts(serials, entries, today):
    raw = ",".join(serials)
    revoked = sum(1 for v in entries.values() if v.get("status") == "REVOKED")
    compromise = sum(1 for v in entries.values() if v.get("reason") == "KEY_COMPROMISE")
    head = (
        "// SPDX-License-Identifier: Apache-2.0\n"
        "// Снимок списка отозванных ключей аттестации Google.\n"
        "//\n"
        "// Порождается tools/update_revoked.py — РУКАМИ НЕ ПРАВИТЬ.\n"
        "// Источник: %s\n"
        "//\n"
        "// Снимок взят: %s. Записей: %d, из них со статусом REVOKED: %d,\n"
        "// с причиной KEY_COMPROMISE: %d.\n"
        "//\n"
        "// Зачем снимок, а не запрос при каждой проверке: проверка обязана работать\n"
        "// без сети. Дата снимка уходит в текст проверки, чтобы читатель знал, на\n"
        "// какое число дан ответ. Кто проверяет онлайн, может передать свежий список\n"
        "// доводом verifyPackage(entries, { revoked, revokedDate }).\n"
        % (URL, today, len(entries), revoked, compromise)
    )
    body = (
        'export const REVOKED_SNAPSHOT_DATE = "%s";\n'
        'export const REVOKED_SERIALS_RAW =\n  "%s";\n'
        "/* Разбираем один раз при загрузке: проверка зовётся на каждое звено\n"
        "   цепочки каждого файла. */\n"
        'export const REVOKED_SERIALS: ReadonlySet<string> = new Set(REVOKED_SERIALS_RAW.split(","));\n'
        % (today, raw)
    )
    with io.open(os.path.abspath(TS), "w", encoding="utf-8", newline="\n") as fh:
        fh.write(head + "\n" + body)
    print("записано: %s (%d серийников, %.1f КБ строкой)"
          % (os.path.relpath(TS, os.path.join(HERE, "..")), len(serials), len(raw) / 1024.0))
    return raw


def write_page(path, raw, today):
    with io.open(path, "r", encoding="utf-8", newline="") as fh:
        page = fh.read()
    nl = "\r\n" if page.count("\r\n") * 2 > page.count("\n") else "\n"
    i, j = page.find(BEGIN), page.find(END)
    if i < 0 or j < 0:
        print("во второй копии нет меток «ОТЗЫВ» — она не тронута:", path)
        return
    block = (BEGIN + nl +
             "  var TV_REVOKED_DATE = '%s';" % today + nl +
             "  var TV_REVOKED_RAW =" + nl +
             "    '%s';" % raw + nl +
             "  " + END)
    page = page[:i] + block + page[j + len(END):]
    with io.open(path, "w", encoding="utf-8", newline="") as fh:
        fh.write(page)
    print("записано:", path)


def main():
    src = sys.argv[1] if len(sys.argv) > 1 else None
    page = sys.argv[2] if len(sys.argv) > 2 else None

    data = load(src)
    entries = data.get("entries") or {}
    if not entries:
        print("список пуст — не трогаю файлы")
        return 2

    bad = [k for k in entries if not PAT.match(k)]
    if bad:
        # Молча выбросить непонятное нельзя: это значит, что формат сменился, а
        # мы бы продолжили считать список полным.
        print("НЕ ПО ШАБЛОНУ GOOGLE (%d): %s" % (len(bad), bad[:5]))
        return 3

    # Дата снимка — сегодняшняя дата машины, и это честно: утверждается не
    # «список верен на эту дату», а «мы забрали его в этот день».
    today = datetime.date.today().isoformat()
    raw = write_ts(sorted(entries), entries, today)

    if page:
        write_page(os.path.abspath(page), raw, today)
    return 0


if __name__ == "__main__":
    sys.exit(main())
