# -*- coding: utf-8 -*-
"""Набор проверочных файлов для сверки ДВУХ верификаторов.

Расхождение между браузерным и серверным верификатором мы 30 августа 2026
ловили дважды, оба раза случайно. Здесь набор специально сконструированных случаев:
каждый прогоняется через оба и сравнивается вердикт. Разошлись — это баг,
даже если по отдельности каждый ответ выглядит разумным.
"""
import io, json, os, shutil, zipfile

SP = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(SP)

# Свой каталог, не общий с fuzz_gen.py: наборы разные по смыслу, а этот
# скрипт чистит выходной каталог перед сборкой — сложенные вместе, они
# затирали бы друг друга.
OUT = os.path.join(SP, "corpus-divergence")
# Каталог вывода можно задать параметром — по той же причине, что в
# fuzz_gen.py: один скрипт, несколько мест запуска.
import sys as _sys
if len(_sys.argv) > 1:
    OUT = os.path.abspath(_sys.argv[1])
shutil.rmtree(OUT, ignore_errors=True)
os.makedirs(OUT)

BASE_PHOTO = os.path.join(ROOT, "samples", "genuine-photo.trustvisor")
BASE_VIDEO = os.path.join(ROOT, "samples", "genuine.trustvisor")

def rewrite(src, dst, mutate_entry=None, add_entries=None, drop_entries=(), rename=None):
    zin = zipfile.ZipFile(src)
    zo = zipfile.ZipFile(os.path.join(OUT, dst), "w", zipfile.ZIP_STORED)
    for n in zin.namelist():
        if n in drop_entries:
            continue
        data = zin.read(n)
        if mutate_entry and n in mutate_entry:
            data = mutate_entry[n](data)
        name = rename.get(n, n) if rename else n
        zo.writestr(name, data)
    for name, data in (add_entries or {}).items():
        zo.writestr(name, data)
    zo.close()

def json_edit(fn):
    def inner(raw):
        txt = raw.decode("utf-8")
        return fn(txt).encode("utf-8")
    return inner

cases = []

# 0-1. Эталоны — должны быть ПОДЛИННО в обоих
shutil.copy(BASE_PHOTO, os.path.join(OUT, "01_legit_photo.trustvisor")); cases.append("01_legit_photo")
shutil.copy(BASE_VIDEO, os.path.join(OUT, "02_legit_video.trustvisor")); cases.append("02_legit_video")

# 2. Дописанное неподписанное поле
rewrite(BASE_PHOTO, "03_extra_field.trustvisor",
        {"manifest.json": json_edit(lambda t: t.replace('"signature"', '"camera": "FRONT",\n  "signature"', 1))})
cases.append("03_extra_field")

# 3. XSS в хэше
rewrite(BASE_PHOTO, "04_xss_in_hash.trustvisor",
        {"manifest.json": json_edit(lambda t: t.replace(
            json.loads(t)["photoSha256"], '"><img src=x onerror=1>', 1))})
cases.append("04_xss_in_hash")

# 4. XSS во времени
rewrite(BASE_PHOTO, "05_xss_in_time.trustvisor",
        {"manifest.json": json_edit(lambda t: t.replace(
            str(json.loads(t)["capturedAt"]), '"<img src=x onerror=1>"', 1))})
cases.append("05_xss_in_time")

# 5. Видео, спрятанное в подпапку рядом с фото
rewrite(BASE_PHOTO, "06_subfolder_video.trustvisor",
        add_entries={"evidence/video.mp4": b"\x00\x00\x00\x18ftypmp42" + b"X" * 3000})
cases.append("06_subfolder_video")

# 6. Посторонний файл в пакете
rewrite(BASE_PHOTO, "07_extra_file.trustvisor",
        add_entries={"readme_attacker.txt": b"never signed"})
cases.append("07_extra_file")

# 7. Испорченный байт медиа — хэш не сойдётся
def flip(data):
    b = bytearray(data); b[len(b) // 2] ^= 0xFF; return bytes(b)
rewrite(BASE_PHOTO, "08_media_tampered.trustvisor", {"photo.png": flip})
cases.append("08_media_tampered")

# 8. Подпись удалена
rewrite(BASE_PHOTO, "09_signature_removed.trustvisor",
        {"manifest.json": json_edit(lambda t: (lambda m: json.dumps(
            {k: v for k, v in m.items() if k != "signature"}, ensure_ascii=False))(json.loads(t)))})
cases.append("09_signature_removed")

# 9. Цепочка аттестации усечена до одного сертификата
rewrite(BASE_PHOTO, "10_chain_truncated.trustvisor",
        {"manifest.json": json_edit(lambda t: (lambda m: json.dumps(
            {**m, "attestationChain": m["attestationChain"][:1]}, ensure_ascii=False))(json.loads(t)))})
cases.append("10_chain_truncated")

# 10. Цепочка удалена вовсе
rewrite(BASE_PHOTO, "11_chain_removed.trustvisor",
        {"manifest.json": json_edit(lambda t: (lambda m: json.dumps(
            {k: v for k, v in m.items() if k != "attestationChain"}, ensure_ascii=False))(json.loads(t)))})
cases.append("11_chain_removed")

# 11. Порядок цепочки перевёрнут (корень первым)
rewrite(BASE_PHOTO, "12_chain_reversed.trustvisor",
        {"manifest.json": json_edit(lambda t: (lambda m: json.dumps(
            {**m, "attestationChain": list(reversed(m["attestationChain"]))}, ensure_ascii=False))(json.loads(t)))})
cases.append("12_chain_reversed")

# 12. Стартовый манифест выдан за конечный
zin = zipfile.ZipFile(BASE_VIDEO)
start = zin.read("manifest_start.json")
rewrite(BASE_VIDEO, "13_start_as_end.trustvisor",
        {"manifest_end.json": (lambda _d: start)})
cases.append("13_start_as_end")

# 13. Пустое медиа
rewrite(BASE_PHOTO, "14_empty_media.trustvisor", {"photo.png": (lambda _d: b"")})
cases.append("14_empty_media")

# 14. Оба медиа в корне
rewrite(BASE_PHOTO, "15_photo_and_video.trustvisor",
        add_entries={"video.mp4": b"\x00\x00\x00\x18ftypmp42" + b"Y" * 3000})
cases.append("15_photo_and_video")

# 15. Манифест с отступами пересобран (пересериализация ломает подпись)
rewrite(BASE_PHOTO, "16_reserialized.trustvisor",
        {"manifest.json": json_edit(lambda t: json.dumps(json.loads(t), ensure_ascii=False, indent=2))})
cases.append("16_reserialized")

# ═══ Случаи расхождения двух верификаторов, найденные перебором ═══════
# Каждый ниже давал РАЗНЫЕ ответы у сервера и у сайта. Это главный класс
# ошибок проекта, поэтому им место именно здесь, в постоянном наборе.

# 16. Невалидный байт UTF-8 внутри поля, которое в подпись НЕ входит.
#     Было: сервер ПОДЛИННО (нестрогое декодирование + уцелевший откат на
#     реконструкцию по списку полей), сайт ИЗМЕНЁН (строгое декодирование).
#     Самое опасное из найденного: настоящая съёмка одним байтом
#     объявлялась подделкой на публичном сайте.
def _bad_utf8(data):
    i = data.find(b"SHA256withECDSA")
    assert i > 0, "в манифесте нет поля signatureAlgorithm — случай собран неверно"
    out = bytearray(data)
    out[i] = 0xFF
    return bytes(out)

rewrite(BASE_PHOTO, "17_utf8_in_dropped_field.trustvisor",
        {"manifest.json": _bad_utf8})
cases.append("17_utf8_in_dropped_field")

# 17. Весь пакет уложен в подпапку.
#     Было: сайт ПОДЛИННО (сравнивал имена без пути), сервер ОТКАЗ.
rewrite(BASE_PHOTO, "18_all_in_subfolder.trustvisor",
        rename={"photo.png": "sub/photo.png", "manifest.json": "sub/manifest.json"})
cases.append("18_all_in_subfolder")

# 18. Лишний манифест ЧУЖОГО типа рядом с настоящими.
#     Было: сервер ПОДЛИННО (общий список допустимых имён, лишнее просто не
#     читалось), сайт ОТКАЗ.
rewrite(BASE_VIDEO, "19_stray_photo_manifest.trustvisor",
        add_entries={"manifest.json": b'{"stray":"manifest"}'})
cases.append("19_stray_photo_manifest")

# 19. Манифест больше мегабайта.
#     Было: сервер ОТКАЗ (предел 1 МБ), сайт читал и отвечал ИЗМЕНЁН.
rewrite(BASE_PHOTO, "20_huge_manifest.trustvisor",
        {"manifest.json": (lambda d: d + b" " * (1024 * 1024 + 100 - len(d)))})
cases.append("20_huge_manifest")

# 20. Лишний байт между оглавлением архива и его концом.
#     Было: сервер принимал файл, сайт отказывался открыть его вовсе.
#     Собирается не через rewrite: нужен байт СНАРУЖИ структуры zip.
_src = io.open(BASE_PHOTO, "rb").read()
_gapped = _src[:-22] + b"A" + _src[-22:]
io.open(os.path.join(OUT, "21_gap_before_eocd.trustvisor"), "wb").write(_gapped)
cases.append("21_gap_before_eocd")

# 21. Невидимая метка порядка байт (BOM) перед манифестом.
#     Случай особый: это РЕГРЕССИЯ ОТ СОБСТВЕННОЙ ПОЧИНКИ, найденная в тот же
#     день. Переводя проверку подписи на сырые байты, я стал получать текст
#     через TextDecoder — а он по умолчанию молча срезает метку. Сервер начал
#     отвечать ПОДЛИННО там, где сайт отвечает «не валидный JSON».
#     Стоит в наборе как напоминание: починка расхождения сама может создать
#     расхождение.
rewrite(BASE_PHOTO, "22_bom_before_manifest.trustvisor",
        {"manifest.json": (lambda d: bytes([0xEF, 0xBB, 0xBF]) + d)})
cases.append("22_bom_before_manifest")

print("сформировано случаев:", len(cases))
for c in cases:
    p = os.path.join(OUT, c + ".trustvisor")
    print("  %-26s %8d байт" % (c, os.path.getsize(p)))
io.open(os.path.join(OUT, "cases.txt"), "w", encoding="utf-8").write("\n".join(cases))
