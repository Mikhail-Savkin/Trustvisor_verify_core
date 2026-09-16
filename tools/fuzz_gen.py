# -*- coding: utf-8 -*-
"""Генератор испорченных пакетов для перебора.

ЗАЧЕМ
-----
У нас два независимых верификатора одного формата: браузерный на сайте и
серверный в портале. Они обязаны отвечать одинаково на любой файл.

Искать их расхождения глазами — самый слабый способ. За один прогон таких
расхождений нашлось пять, и два из них поймали не глаза, а измерения; одно
я вдобавок сам же и создал починкой предыдущего.

Поэтому здесь не «ещё один круг чтения кода», а перебор: берём настоящую
съёмку и портим её сотнями разных способов, каждый — через оба верификатора.
Любое несовпадение вердиктов видно сразу.

ЧТО ВАЖНО ПОНИМАТЬ ПРО РЕЗУЛЬТАТ
--------------------------------
Перебор ищет расхождения, а не «правильность». Если оба верификатора одинаково
неправы, он этого не заметит. Он ловит ровно тот класс ошибок, который в этом
проекте оказался главным.

Набор порч детерминированный (фиксированное зерно): один и тот же прогон
всегда даёт те же файлы, иначе расхождение нельзя было бы воспроизвести.
"""
import io
import json
import os
import random
import struct
import sys
import zipfile

if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")

HERE = os.path.dirname(os.path.abspath(__file__))
# Каталог вывода можно задать вторым параметром: набор один, а мест,
# откуда его гоняют, несколько, и разводить копии скрипта ради этого
# нельзя — разойдутся.
OUT = os.path.join(HERE, "corpus")
SEED = 20260830

# ─────────────────────────────────────────────────────────────────────────
# Сборка ZIP с полным контролем над структурой.
# zipfile не даёт врать в концевой записи и оставлять промежутки, а именно
# на таком вранье ловились расхождения — поэтому собираем руками.
# ─────────────────────────────────────────────────────────────────────────
def crc32(data):
    import zlib
    return zlib.crc32(data) & 0xFFFFFFFF


def build_zip(entries, declared=None, gap=0, prefix=b"", comment=b"",
              cd_size_delta=0, cd_offset_delta=0, method=8,
              descriptor=None, descriptor_damage=None):
    """entries: список (имя, данные). method: 8=сжатие (как в настоящем файле),
    0=без сжатия.

    По умолчанию со сжатием — именно так пакует приложение. Без него набор
    распухал в пять раз, и перебор в браузере
    упирался бы в скачивание, а не в проверку.

    descriptor: None — размеры в локальном заголовке, флагов нет. Так пишет
    Python, и так собраны все 288 случаев. `"signed"` — как пишет телефон:
    флаг 8, размеры в локальном заголовке обнулены, после данных дескриптор
    из 16 байт с подписью PK\\x07\\x08. `"bare"` — то же, но дескриптор из
    12 байт, без подписи; стандарт разрешает обе формы.

    Это добавлено 12 сентября 2026, и вот зачем. Настоящие съёмки с телефона
    всегда идут с дескриптором, а весь перебор собирался без него — то есть
    ветка разбора, срабатывающая на каждом живом файле, не проверялась
    вовсе. Заодно в тех же 12 байтах нашёлся карман: их содержимое никто не
    сверял с оглавлением.

    descriptor_damage: имя поля дескриптора, которое надо испортить
    ("crc", "csize", "usize"), либо "truncate" — обрезать дескриптор."""
    import zlib
    locals_, central = [], []
    offset = len(prefix)
    flags = 8 if descriptor else 0
    for name, data in entries:
        nm = name.encode("utf-8")
        if method == 8:
            comp = zlib.compressobj(9, zlib.DEFLATED, -15)
            stored = comp.compress(data) + comp.flush()
        else:
            stored = data
        # При флаге 8 размеры в локальном заголовке обязаны быть нулевыми:
        # настоящие они только в дескрипторе и в оглавлении.
        lh_crc, lh_cs, lh_us = ((0, 0, 0) if descriptor
                                else (crc32(data), len(stored), len(data)))
        lh = struct.pack("<IHHHHHIIIHH", 0x04034B50, 20, flags, method, 0, 0,
                         lh_crc, lh_cs, lh_us, len(nm), 0)
        dd = b""
        if descriptor:
            crc, cs, us = crc32(data), len(stored), len(data)
            if descriptor_damage == "crc":
                crc ^= 0xFFFFFFFF
            elif descriptor_damage == "csize":
                cs += 1
            elif descriptor_damage == "usize":
                us += 1
            dd = struct.pack("<III", crc, cs, us)
            if descriptor == "signed":
                dd = struct.pack("<I", 0x08074B50) + dd
            if descriptor_damage == "truncate":
                dd = dd[:-4]
        locals_.append(lh + nm + stored + dd)
        ch = struct.pack("<IHHHHHHIIIHHHHHII", 0x02014B50, 20, 20, flags, method, 0, 0,
                         crc32(data), len(stored), len(data), len(nm), 0, 0, 0, 0, 0, offset)
        central.append(ch + nm)
        offset += len(lh) + len(nm) + len(stored) + len(dd)

    body = prefix + b"".join(locals_)
    cd = b"".join(central)
    cd_offset = len(body)
    n = declared if declared is not None else len(entries)
    eocd = struct.pack("<IHHHHIIH", 0x06054B50, 0, 0, n, n,
                       len(cd) + cd_size_delta, cd_offset + cd_offset_delta, len(comment))
    return body + cd + (b"\x00" * gap) + eocd + comment


def read_src(path):
    z = zipfile.ZipFile(path)
    return [(n, z.read(n)) for n in z.namelist()]


# ─────────────────────────────────────────────────────────────────────────
cases = {}


def emit(name, data):
    assert name not in cases, "повтор имени случая: " + name
    cases[name] = data


def gen(src_path):
    entries = read_src(src_path)
    names = [n for n, _ in entries]
    assert "manifest.json" in names and "photo.png" in names, names
    man = dict(entries)["manifest.json"]
    png = dict(entries)["photo.png"]
    clean = build_zip(entries)
    rnd = random.Random(SEED)

    emit("000_clean", clean)

    # ── 1. Порча случайных байт всего файла ─────────────────────────────
    for i in range(40):
        b = bytearray(clean)
        pos = rnd.randrange(len(b))
        b[pos] ^= 1 << rnd.randrange(8)
        emit("bitflip_file_%03d" % i, bytes(b))

    # ── 2. Порча байт внутри манифеста ──────────────────────────────────
    for i in range(40):
        b = bytearray(man)
        pos = rnd.randrange(len(b))
        b[pos] ^= 1 << rnd.randrange(8)
        emit("bitflip_manifest_%03d" % i, build_zip([("manifest.json", bytes(b)), ("photo.png", png)]))

    # ── 3. Обрезка файла ────────────────────────────────────────────────
    for frac in (0.99, 0.95, 0.9, 0.75, 0.5, 0.25, 0.05):
        emit("truncate_%02d" % int(frac * 100), clean[:int(len(clean) * frac)])

    # ── 4. Приписки снаружи структуры ───────────────────────────────────
    for n in (1, 2, 3, 16, 114, 1024):
        emit("append_tail_%d" % n, clean + b"A" * n)
        emit("prefix_%d" % n, b"A" * n + clean)
        emit("gap_before_eocd_%d" % n, build_zip(entries, gap=n))
    emit("eocd_comment_16", build_zip(entries, comment=b"C" * 16))
    emit("eocd_comment_65535", build_zip(entries, comment=b"C" * 65535))

    # ── 4a. Расхождения, найденные разбором 13 сентября 2026 ─────────────
    #
    # Обоих случаев в переборе не было, потому что build_zip пишет имя
    # одинаково в оба места и всегда обнуляет номера дисков. А расходились
    # проверяльщики именно здесь: yauzl берёт имя из оглавления, JSZip — из
    # локального заголовка; номера дисков yauzl читает, JSZip нет.
    def _local_name_changed(raw):
        """Один байт имени в локальном заголовке, оглавление не трогаем."""
        b = bytearray(raw)
        at = b.find(b"PK" + bytes([3, 4]))
        if at < 0:
            return None
        nlen = struct.unpack_from("<H", b, at + 26)[0]
        if nlen < 2:
            return None
        pos = at + 30 + nlen - 3
        b[pos] = (b[pos] ^ 0x20)
        return bytes(b)

    spoiled = _local_name_changed(clean)
    if spoiled:
        emit("local_name_mismatch", spoiled)

    def _eocd_field(raw, off, value):
        b = bytearray(raw)
        at = b.rfind(b"PK" + bytes([5, 6]))
        if at < 0:
            return None
        struct.pack_into("<H", b, at + off, value)
        return bytes(b)

    for label, off in (("eocd_disk_number", 4), ("eocd_disk_of_cd", 6)):
        spoiled = _eocd_field(clean, off, 1)
        if spoiled:
            emit(label, spoiled)
    spoiled = _eocd_field(clean, 8, 99)
    if spoiled:
        emit("eocd_count_on_disk", spoiled)

    # ── 5. Враньё в концевой записи ─────────────────────────────────────
    for d in (-2, -1, 1, 2):
        emit("declared_count_%+d" % d, build_zip(entries, declared=max(0, len(entries) + d)))
    for d in (-46, -1, 1, 46):
        emit("cd_size_%+d" % d, build_zip(entries, cd_size_delta=d))
        emit("cd_offset_%+d" % d, build_zip(entries, cd_offset_delta=d))

    # ── 6. Имена записей ────────────────────────────────────────────────
    variants = [
        ("subfolder_all", [("sub/manifest.json", man), ("sub/photo.png", png)]),
        ("subfolder_media", [("manifest.json", man), ("sub/photo.png", png)]),
        ("dotdot", [("../manifest.json", man), ("../photo.png", png)]),
        ("dotslash", [("./manifest.json", man), ("./photo.png", png)]),
        ("backslash", [("sub\\manifest.json", man), ("sub\\photo.png", png)]),
        ("upper_media", [("manifest.json", man), ("PHOTO.PNG", png)]),
        ("upper_manifest", [("MANIFEST.JSON", man), ("photo.png", png)]),
        ("trailing_space", [("manifest.json ", man), ("photo.png ", png)]),
        ("leading_slash", [("/manifest.json", man), ("/photo.png", png)]),
        ("nul_suffix", [("manifest.json\x00x", man), ("photo.png", png)]),
        ("dup_manifest", [("manifest.json", man), ("photo.png", png), ("manifest.json", b'{"fake":1}')]),
        ("dup_media", [("manifest.json", man), ("photo.png", png), ("photo.png", b"FAKE")]),
        ("extra_file", [("manifest.json", man), ("photo.png", png), ("readme.txt", b"hi")]),
        ("extra_dir_entry", [("manifest.json", man), ("photo.png", png), ("dir/", b"")]),
        ("both_media", [("manifest.json", man), ("photo.png", png), ("video.mp4", b"\x00\x00\x00\x18ftypmp42")]),
        ("stray_start_manifest", [("manifest.json", man), ("photo.png", png), ("manifest_start.json", b"{}")]),
        ("only_manifest", [("manifest.json", man)]),
        ("only_media", [("photo.png", png)]),
        ("empty_zip", []),
        ("reversed_order", [("photo.png", png), ("manifest.json", man)]),
    ]
    for label, ents in variants:
        emit("names_" + label, build_zip(ents))

    emit("stored_all", build_zip(entries, method=0))

    # ── 7. Порча самого манифеста как текста ────────────────────────────
    txt = man.decode("utf-8")
    m = json.loads(txt)

    def zip_with_manifest(raw_bytes):
        return build_zip([("manifest.json", raw_bytes), ("photo.png", png)])

    text_mutations = {
        "bom": b"\xef\xbb\xbf" + man,
        "bom_utf16": b"\xff\xfe" + man,
        "leading_space": b"   " + man,
        "leading_newline": b"\n" + man,
        "trailing_space": man + b"   ",
        "trailing_newline": man + b"\n",
        "trailing_nul": man + b"\x00",
        "trailing_garbage": man + b"garbage",
        "compact": json.dumps(m, ensure_ascii=False, separators=(",", ":")).encode("utf-8"),
        "indent4": json.dumps(m, ensure_ascii=False, indent=4).encode("utf-8"),
        "tabs": txt.replace("  ", "\t").encode("utf-8"),
        "crlf": txt.replace("\n", "\r\n").encode("utf-8"),
        "ascii_escaped": json.dumps(m, ensure_ascii=True, indent=2).encode("utf-8"),
        "empty": b"",
        "not_json": b"hello",
        "array": b"[1,2,3]",
        "nested_object": b'{"m":' + man + b"}",
        "double_object": man + man,
        "unterminated": man[:-1],
    }
    for label, data in text_mutations.items():
        emit("text_" + label, zip_with_manifest(data))

    # невалидный UTF-8 в разных местах
    for i, frac in enumerate((0.05, 0.25, 0.5, 0.75, 0.95)):
        b = bytearray(man)
        b[int(len(b) * frac)] = 0xFF
        emit("text_invalid_utf8_%02d" % i, zip_with_manifest(bytes(b)))
    # невалидный UTF-8 точно внутри неподписываемого поля
    i = man.find(b"SHA256withECDSA")
    if i > 0:
        b = bytearray(man); b[i] = 0xFF
        emit("text_invalid_utf8_in_dropped", zip_with_manifest(bytes(b)))

    # ── 8. Порча полей манифеста ────────────────────────────────────────
    keys = list(m.keys())
    for k in keys:
        v = m[k]
        # удалить поле
        d = {kk: vv for kk, vv in m.items() if kk != k}
        emit("field_drop_" + k, zip_with_manifest(json.dumps(d, ensure_ascii=False, indent=2).encode("utf-8")))
        # обнулить поле
        d = dict(m); d[k] = None
        emit("field_null_" + k, zip_with_manifest(json.dumps(d, ensure_ascii=False, indent=2).encode("utf-8")))
        # изменить значение
        d = dict(m)
        if isinstance(v, bool):
            d[k] = not v
        elif isinstance(v, (int, float)):
            d[k] = v + 1
        elif isinstance(v, str):
            d[k] = v + "x"
        elif isinstance(v, list):
            d[k] = list(reversed(v))
        else:
            d[k] = "changed"
        emit("field_change_" + k, zip_with_manifest(json.dumps(d, ensure_ascii=False, indent=2).encode("utf-8")))

    # дописанные посторонние поля в разные позиции
    for label, ins in (("head", 0), ("tail", None)):
        items = list(m.items())
        extra = ("постороннееПоле", "вписано снаружи")
        items = ([extra] + items) if ins == 0 else (items + [extra])
        emit("field_inject_" + label,
             zip_with_manifest(json.dumps(dict(items), ensure_ascii=False, indent=2).encode("utf-8")))
    # ── карманы в служебных полях ──────────────────────────────────────
    # Три поля выброшены из подписываемых байтов, значит подписью не покрыты.
    # У signature и attestationChain границу задаёт употребление: мусор в них
    # ломает проверку подписи и разбор цепочки. У signatureAlgorithm границы
    # не было, и к настоящей съёмке приклеивался мегабайт байтов с вердиктом
    # ПОДЛИННО — найдено сторонним разбором 15 сентября 2026.
    for label, size in (("small", 100), ("big", 300000)):
        d = dict(m)
        d["signatureAlgorithm"] = d.get("signatureAlgorithm", "SHA256withECDSA") + "A" * size
        emit("pocket_alg_" + label,
             zip_with_manifest(json.dumps(d, ensure_ascii=False, indent=2).encode("utf-8")))
    for k in ("signature", "attestationChain"):
        d = dict(m)
        if isinstance(d.get(k), list):
            d[k] = ["A" * 100000] + list(d[k])
        else:
            d[k] = str(d.get(k, "")) + "A" * 100000
        emit("pocket_" + k, zip_with_manifest(json.dumps(d, ensure_ascii=False, indent=2).encode("utf-8")))

    # дубль ключа в сыром тексте (json.dumps так не умеет)
    emit("field_duplicate_key",
         zip_with_manifest(txt.replace("{", '{\n  "type": "ПОДДЕЛКА",', 1).encode("utf-8")))

    # Числовые формы. Одно число JSON разрешает записать по-разному - 10, 10.0,
    # 1e1, -0.0, "10.0", - и уплощение манифеста не должно считать эти записи
    # взаимозаменяемыми. Поля берём те, что в манифесте есть: раньше тут стояли
    # намертво три поля координат, и на съёмке с выключенной геолокацией весь
    # класс случаев тихо пропадал из набора.
    def numeric(key):
        v = m.get(key)
        return isinstance(v, (int, float)) and not isinstance(v, bool)

    preferred = ("latitude", "longitude", "locationAccuracy", "anchorServerMs",
                 "anchorElapsedMs", "serverTimeDeltaMs", "capturedAt")
    keys = [k for k in preferred if numeric(k)]
    keys += [k for k in m if k not in keys and numeric(k)]
    for k in keys[:3]:
        for label, raw in (("int", "10"), ("float", "10.0"), ("exp", "1e1"),
                           ("negzero", "-0.0"), ("string", '"10.0"')):
            t2 = json.dumps(m, ensure_ascii=False, indent=2)
            t2 = t2.replace('"%s": %s' % (k, json.dumps(m[k])), '"%s": %s' % (k, raw))
            emit("num_%s_%s" % (k, label), zip_with_manifest(t2.encode("utf-8")))

    # подпись и цепочка
    if "signature" in m:
        for label, fn in (
            ("empty", lambda v: ""),
            ("truncated", lambda v: v[:-4]),
            ("padded", lambda v: v + "=="),
            ("whitespace", lambda v: v[:8] + " \n\t" + v[8:]),
            ("not_base64", lambda v: "!!!" + v[3:]),
        ):
            d = dict(m); d["signature"] = fn(m["signature"])
            emit("sig_" + label, zip_with_manifest(json.dumps(d, ensure_ascii=False, indent=2).encode("utf-8")))
    if "attestationChain" in m and isinstance(m["attestationChain"], list) and m["attestationChain"]:
        ch = m["attestationChain"]
        for label, newch in (
            ("reversed", list(reversed(ch))),
            ("truncated", ch[:1]),
            ("empty", []),
            ("duplicated", ch + ch),
            ("leaf_twice", [ch[0]] + ch),
            ("whitespace", [c[:8] + "\n " + c[8:] for c in ch]),
        ):
            d = dict(m); d["attestationChain"] = newch
            emit("chain_" + label, zip_with_manifest(json.dumps(d, ensure_ascii=False, indent=2).encode("utf-8")))

    # ── дескриптор данных ────────────────────────────────────────────────
    # Раскладка, которой пишет телефон. Первые две — честные файлы, и они
    # обязаны давать ПОДЛИННО: это проверка, что мы не сломали живые съёмки.
    # Остальные — порча содержимого дескриптора, того самого кармана.
    emit("descriptor_signed", build_zip(entries, descriptor="signed"))
    emit("descriptor_bare", build_zip(entries, descriptor="bare"))
    for field in ("crc", "csize", "usize"):
        emit("descriptor_bad_" + field,
             build_zip(entries, descriptor="signed", descriptor_damage=field))
        emit("descriptor_bare_bad_" + field,
             build_zip(entries, descriptor="bare", descriptor_damage=field))
    emit("descriptor_truncated",
         build_zip(entries, descriptor="signed", descriptor_damage="truncate"))

    return cases


def main():
    if len(sys.argv) < 2:
        print("использование: fuzz_gen.py <настоящий .trustvisor с фото> [каталог вывода]")
        return 1
    src = sys.argv[1]
    global OUT
    if len(sys.argv) > 2:
        OUT = os.path.abspath(sys.argv[2])
    gen(src)
    if not os.path.isdir(OUT):
        os.makedirs(OUT)
    for f in os.listdir(OUT):
        if f.endswith(".trustvisor"):
            os.remove(os.path.join(OUT, f))
    total = 0
    for name, data in cases.items():
        io.open(os.path.join(OUT, name + ".trustvisor"), "wb").write(data)
        total += len(data)
    io.open(os.path.join(OUT, "cases.json"), "w", encoding="utf-8").write(
        json.dumps(sorted(cases), ensure_ascii=False))
    print("случаев: %d, суммарно %.1f МБ" % (len(cases), total / 1024 / 1024))
    return 0


if __name__ == "__main__":
    sys.exit(main())
