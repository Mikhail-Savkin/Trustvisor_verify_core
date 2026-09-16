# -*- coding: utf-8 -*-
"""
Готовит из одного подлинного пакета два производных образца — чтобы можно
было увидеть вживую не только «ПОДЛИННО», но и другие вердикты.

    python make_samples.py [путь_к_подлинному.trustvisor]

По умолчанию берётся samples/genuine.trustvisor, результат кладётся рядом:

  tampered.trustvisor              один байт перевёрнут в середине файла — ровно
                                   байт в середине. Ожидаемый вердикт: ИЗМЕНЁН.
  unattested.trustvisor            из манифестов вырезано поле attestationChain.
                                   Оно не входит в подписываемые данные (§3
                                   спецификации), поэтому подпись остаётся
                                   верной, а аппаратного подтверждения нет.
                                   Ожидаемый вердикт: НЕ АТТЕСТОВАНО.

Подделки здесь нет: оба файла — честно описанные производные от подлинного, и
показывают ровно то, что случилось бы с настоящей съёмкой в тех же
обстоятельствах.

ВАЖНО: манифест нельзя пересобирать через json.dumps. Подпись считается по
байтам файла, а библиотека иначе экранирует косую черту — форма изменится, и
честный образец получит «ИЗМЕНЁН» вместо задуманного вердикта. Поэтому поле
вырезается из текста хирургически, все остальные байты остаются как были.
"""
import io
import json
import os
import sys
import zipfile

# Иначе в консоли Windows русский вывод превращается в кракозябры.
if hasattr(sys.stdout, 'reconfigure'):
    sys.stdout.reconfigure(encoding='utf-8')

HERE = os.path.dirname(os.path.abspath(__file__))
SRC = sys.argv[1] if len(sys.argv) > 1 else os.path.join(HERE, 'genuine.trustvisor')

MANIFESTS = ('manifest_start.json', 'manifest_end.json', 'manifest.json')
WS = ' \t\r\n'
BACKSLASH = chr(92)


def read_package(path):
    with zipfile.ZipFile(path) as z:
        names = z.namelist()
        return names, {n: z.read(n) for n in names}


def make_tampered(raw, dst):
    """Перевернуть один байт в середине файла."""
    b = bytearray(raw)
    off = len(b) // 2
    before = b[off]
    b[off] ^= 0xFF
    assert b[off] != before
    io.open(dst, 'wb').write(bytes(b))
    return off, before, b[off]


def _skip_string(s, i):
    """i указывает на открывающую кавычку; вернуть позицию сразу за строкой."""
    i += 1
    while i < len(s):
        if s[i] == BACKSLASH:
            i += 2
            continue
        if s[i] == '"':
            return i + 1
        i += 1
    return -1


def _skip_value(s, i):
    if s[i] == '"':
        return _skip_string(s, i)
    if s[i] in '{[':
        opener = s[i]
        closer = '}' if opener == '{' else ']'
        depth = 0
        while i < len(s):
            if s[i] == '"':
                i = _skip_string(s, i)
                if i < 0:
                    return -1
                continue
            if s[i] == opener:
                depth += 1
            elif s[i] == closer:
                depth -= 1
                if depth == 0:
                    return i + 1
            i += 1
        return -1
    while i < len(s) and s[i] not in ',}]':
        i += 1
    return i


def strip_field(text, field):
    """Вырезать поле верхнего уровня из JSON-текста, не трогая остальные байты."""
    i = text.index('{') + 1
    while i < len(text) and text[i] != '}':
        while i < len(text) and text[i] in WS:
            i += 1
        if i >= len(text) or text[i] != '"':
            return text, False
        ks = i
        i = _skip_string(text, i)
        if i < 0:
            return text, False
        key = json.loads(text[ks:i])
        while i < len(text) and text[i] in WS:
            i += 1
        if text[i] != ':':
            return text, False
        i += 1
        while i < len(text) and text[i] in WS:
            i += 1
        ve = _skip_value(text, i)
        if ve < 0:
            return text, False
        after = ve
        while after < len(text) and text[after] in WS:
            after += 1
        if key == field:
            if after < len(text) and text[after] == ',':
                return text[:ks] + text[after + 1:], True
            back = ks - 1
            while back >= 0 and text[back] in WS:
                back -= 1
            if back >= 0 and text[back] == ',':
                return text[:back] + text[ve:], True
            return text[:ks] + text[ve:], True
        i = after
        if i < len(text) and text[i] == ',':
            i += 1
    return text, False


def make_unattested(names, data, dst):
    out = {}
    removed = 0
    for n in names:
        if os.path.basename(n) in MANIFESTS:
            txt = data[n].decode('utf-8')
            new_txt, ok = strip_field(txt, 'attestationChain')
            removed += 1 if ok else 0
            out[n] = new_txt.encode('utf-8')
        else:
            out[n] = data[n]
    assert removed, 'в манифестах не было поля attestationChain — проверьте исходный пакет'
    with zipfile.ZipFile(dst, 'w', zipfile.ZIP_STORED) as z:
        for n in names:
            z.writestr(n, out[n])
    return removed


def main():
    assert os.path.exists(SRC), 'нет исходного пакета: ' + SRC
    raw = io.open(SRC, 'rb').read()
    names, data = read_package(SRC)
    print('исходный пакет: %s (%.1f МБ)' % (os.path.basename(SRC), len(raw) / 1048576))
    print('  записи:', names)
    for n in names:
        if os.path.basename(n) in MANIFESTS:
            obj = json.loads(data[n].decode('utf-8'))
            chain = obj.get('attestationChain')
            print('  %-20s полей %2d, цепочка: %s' % (n, len(obj),
                  ('%d сертификатов' % len(chain)) if chain else 'нет'))

    dst1 = os.path.join(HERE, 'tampered.trustvisor')
    off, a, b = make_tampered(raw, dst1)
    print('\n-> %s: перевёрнут байт №%d (0x%02X -> 0x%02X)' % (os.path.basename(dst1), off, a, b))

    dst2 = os.path.join(HERE, 'unattested.trustvisor')
    n = make_unattested(names, data, dst2)
    print('-> %s: цепочка вырезана из %d манифест(ов), %.1f МБ'
          % (os.path.basename(dst2), n, os.path.getsize(dst2) / 1048576))

    # самопроверка: остальные байты манифестов не изменились
    _, d2 = read_package(dst2)
    for k in names:
        if os.path.basename(k) in MANIFESTS:
            a_txt, _ = strip_field(data[k].decode('utf-8'), 'attestationChain')
            assert a_txt.encode('utf-8') == d2[k], 'манифест %s изменился сверх удаления поля' % k
        else:
            assert data[k] == d2[k], 'запись %s изменилась' % k
    print('   самопроверка: кроме вырезанного поля, байты манифестов не тронуты')
    print('\nГотово. Вердикты по этим файлам проверяет набор: npm run build && npm test')


if __name__ == '__main__':
    main()
