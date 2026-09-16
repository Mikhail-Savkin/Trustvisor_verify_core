# -*- coding: utf-8 -*-
"""Собрать подписанное медиа из пакета `.trustvisor`. Оба формата.

    python tools/make_signed_media.py <пакет.trustvisor> <куда.jpg|.mp4>

Подписанное медиа собирают приложение (`GalleryViewModel.kt`) и
страница проверки (`buildSignedJpeg`/`buildSignedMp4`). Стенду нужен третий,
независимый сборщик: иначе разборщик формата 2.0 в медиаконтейнерах нечем
проверить до выпуска приложения, а проверять сборщик им же самим — это не
проверка.

РАСКЛАДКА (разделы 1.2, 1.4 и 2.0.1 спецификации):

    формат 1.x   магия · 1 · вид · u32 длина · манифест [· u32 · манифест конца]
    формат 2.0   магия · 2 · вид · u32 · манифест · u32 · подпись
                                  [· u32 · манифест конца · u32 · подпись конца]

Версия блока — 1 или 2 — определяется наличием записей `.jws` в пакете, то
есть тем же признаком, что и в архиве. Смешивать нельзя: пакет либо целиком
старый, либо целиком новый.
"""
import io
import os
import struct
import sys
import zipfile

MAGIC = b"TVSR-TrustVisor1"


def be32(n):
    return struct.pack(">I", n)


def build(src, dst):
    z = zipfile.ZipFile(src)
    names = z.namelist()
    is_photo = "photo.png" in names
    jws_names = [n for n in names if n.endswith(".jws")]
    # Версия блока выводится из состава пакета, а не задаётся отдельно: так
    # её нельзя рассогласовать с тем, что в блок реально положено.
    has_sensors = "sensors.bin" in names
    ver = (3 if has_sensors else 2) if jws_names else 1
    assert not (has_sensors and not jws_names), (
        "журнал датчиков существует только в формате 2.0; в файле 1.x он посторонний")

    if is_photo:
        media = z.read("photo.png")
        parts = [z.read("manifest.json")]
        if ver >= 2:
            parts.append(z.read("manifest.json.jws"))
        kind = 2
    else:
        media = z.read("video.mp4")
        parts = [z.read("manifest_start.json")]
        if ver >= 2:
            parts.append(z.read("manifest_start.json.jws"))
        parts.append(z.read("manifest_end.json"))
        if ver >= 2:
            parts.append(z.read("manifest_end.json.jws"))
        kind = 1

    # Журнал — последняя часть блока, и только в версии 3.
    if ver == 3:
        parts.append(z.read("sensors.bin"))

    payload = bytes([ver, kind]) + b"".join(be32(len(p)) + p for p in parts)

    if is_photo and media[:4] == b"\x89PNG":
        # PNG: чанк `tvSg` перед IEND. Так выглядит каждое бесплатное фото —
        # водяной знак пересохраняет кадр в PNG (ManifestWriter.kt). На платном
        # тарифе знака нет и кадр остаётся JPEG.
        import zlib
        off = 8
        while off + 12 <= len(media):
            ln = struct.unpack(">I", media[off:off + 4])[0]
            if media[off + 4:off + 8] == b"IEND":
                break
            off += 12 + ln
        else:
            raise SystemExit("в PNG не найден IEND")
        crc = zlib.crc32(b"tvSg" + payload) & 0xFFFFFFFF
        chunk = be32(len(payload)) + b"tvSg" + payload + be32(crc)
        out = media[:off] + chunk + media[off:]
    elif is_photo:
        # JPEG: блок дописывается в самый хвост, после конца изображения.
        if media[:3] != b"\xff\xd8\xff":
            raise SystemExit("запись photo.png — ни JPEG, ни PNG")
        out = media + MAGIC + payload
    else:
        # MP4: бокс uuid после последнего top-level бокса.
        box = be32(len(MAGIC) + len(payload) + 8) + b"uuid" + MAGIC + payload
        out = media + box

    io.open(dst, "wb").write(out)
    print("формат блока: %d, частей: %d, размер: %.1f МБ"
          % (ver, len(parts), len(out) / 1048576.0))
    print("записано:", dst)


def main():
    if len(sys.argv) != 3:
        print(__doc__)
        return 2
    build(sys.argv[1], os.path.abspath(sys.argv[2]))
    return 0


if __name__ == "__main__":
    sys.exit(main())
