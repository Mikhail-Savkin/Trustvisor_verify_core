# -*- coding: utf-8 -*-
"""Перебор для ПОДПИСАННОГО МЕДИА: MP4 и JPEG.

    python tools/fuzz_media.py <подписанный .mp4|.jpg> [каталог вывода]

Набор из `fuzz_gen.py` портит только ZIP-пакет. Подписанное медиа —
второй контейнер формата, и до сих пор его стерегли три теста про лишний хвост.
Между тем читают и пишут этот блок в обеих реализациях: проверяльщик на сервере
разбирает, страница разбирает и **сама собирает** (кнопка «скачать подписанное
медиа»), приложение собирает. Мест, где раскладка блока задана байтами, около
двух десятков, и половина из них — запись.

Раскладка (раздел 1.2–1.4 и 1.6 спецификации):

    MP4   бокс `uuid`: магия(16) · версия=1 · вид=1 · u32 длина · манифест
                                              · u32 длина · манифест конца
    JPEG  хвост файла: магия(16) · версия=1 · вид=2 · u32 длина · манифест

ЧТО ВАЖНО ПОНИМАТЬ ПРО РЕЗУЛЬТАТ. Набор не знает правильных ответов и не
пытается их знать. Его смысл — прогнать одни и те же байты через обе
реализации и сравнить вердикты: расходятся — дефект, даже если каждый ответ по
отдельности выглядит разумным. Если обе реализации ошибутся одинаково, набор
этого не заметит.

Прогон: `node tools/fuzz_server.mjs <каталог вывода>`
"""
import io
import os
import struct
import sys

MAGIC = b"TVSR-TrustVisor1"
HERE = os.path.dirname(os.path.abspath(__file__))
OUT = os.path.join(HERE, "corpus-media")

cases = {}


def emit(name, data, ext):
    cases[name + ext] = data


# ── разбор исходного файла ───────────────────────────────────────────────

def split_jpeg(buf):
    i = buf.rfind(MAGIC)
    if i < 3:
        raise SystemExit("в JPEG нет блока подписи")
    q = i + len(MAGIC)
    mlen = struct.unpack(">I", buf[q + 2:q + 6])[0]
    return {"media": buf[:i], "ver": buf[q], "kind": buf[q + 1],
            "man": buf[q + 6:q + 6 + mlen]}


def split_mp4(buf):
    off = 0
    while off + 8 <= len(buf):
        size = struct.unpack(">I", buf[off:off + 4])[0]
        hdr = 8
        is_uuid = buf[off + 4:off + 8] == b"uuid"
        if size == 1:
            size = struct.unpack(">Q", buf[off + 8:off + 16])[0]
            hdr = 16
        elif size == 0:
            size = len(buf) - off
        if size < hdr or off + size > len(buf):
            break
        if is_uuid and buf[off + hdr:off + hdr + 16] == MAGIC:
            p = off + hdr + 16
            ls = struct.unpack(">I", buf[p + 2:p + 6])[0]
            le = struct.unpack(">I", buf[p + 6 + ls:p + 10 + ls])[0]
            return {"head": buf[:off], "tail": buf[off + size:],
                    "ver": buf[p], "kind": buf[p + 1],
                    "start": buf[p + 6:p + 6 + ls],
                    "end": buf[p + 10 + ls:p + 10 + ls + le]}
        off += size
    raise SystemExit("в MP4 нет бокса uuid с подписью")


# ── сборка ───────────────────────────────────────────────────────────────

def be32(n):
    return struct.pack(">I", n & 0xFFFFFFFF)


def build_jpeg(d, ver=None, kind=None, declared=None, man=None, tail=b"", magic=MAGIC):
    man = d["man"] if man is None else man
    declared = len(man) if declared is None else declared
    return (d["media"] + magic + bytes([d["ver"] if ver is None else ver,
                                        d["kind"] if kind is None else kind])
            + be32(declared) + man + tail)


def build_mp4(d, ver=None, kind=None, ls=None, le=None, start=None, end=None,
              pad=b"", size_override=None):
    start = d["start"] if start is None else start
    end = d["end"] if end is None else end
    payload = (MAGIC + bytes([d["ver"] if ver is None else ver,
                              d["kind"] if kind is None else kind])
               + be32(len(start) if ls is None else ls) + start
               + be32(len(end) if le is None else le) + end + pad)
    size = len(payload) + 8 if size_override is None else size_override
    return d["head"] + be32(size) + b"uuid" + payload + d["tail"]


def flip(b, pos):
    a = bytearray(b)
    a[pos % len(a)] ^= 0xFF
    return bytes(a)


# ── случаи ───────────────────────────────────────────────────────────────

def gen_jpeg(buf):
    d = split_jpeg(buf)
    e = ".jpg"
    emit("000_clean", build_jpeg(d), e)
    emit("tail_1", build_jpeg(d, tail=b"A"), e)
    emit("tail_1024", build_jpeg(d, tail=b"A" * 1024), e)
    emit("len_plus_1", build_jpeg(d, declared=len(d["man"]) + 1), e)
    emit("len_minus_1", build_jpeg(d, declared=len(d["man"]) - 1), e)
    emit("len_zero", build_jpeg(d, declared=0), e)
    emit("len_huge", build_jpeg(d, declared=0xFFFFFFFF), e)
    emit("len_over_manifest_cap", build_jpeg(d, declared=2 * 1024 * 1024), e)
    emit("version_2", build_jpeg(d, ver=2), e)
    emit("version_0", build_jpeg(d, ver=0), e)
    emit("kind_1", build_jpeg(d, kind=1), e)
    emit("manifest_empty", build_jpeg(d, man=b""), e)
    emit("manifest_flip", build_jpeg(d, man=flip(d["man"], len(d["man"]) // 2)), e)
    emit("media_flip", build_jpeg({**d, "media": flip(d["media"], len(d["media"]) // 2)}), e)
    # магия встречается дважды: разбор обязан брать последнюю
    emit("magic_twice", d["media"] + MAGIC + b"\x01\x02" + be32(4) + b"junk"
         + MAGIC + bytes([d["ver"], d["kind"]]) + be32(len(d["man"])) + d["man"], e)
    emit("magic_only", d["media"] + MAGIC, e)
    emit("no_block", d["media"], e)


def gen_mp4(buf):
    d = split_mp4(buf)
    e = ".mp4"
    emit("000_clean", build_mp4(d), e)
    emit("pad_after_end", build_mp4(d, pad=b"A" * 64), e)
    emit("box_bigger", build_mp4(d, size_override=None if False else
                                 len(MAGIC) + 2 + 8 + len(d["start"]) + len(d["end"]) + 8 + 64), e)
    emit("lenStart_plus_1", build_mp4(d, ls=len(d["start"]) + 1), e)
    emit("lenEnd_plus_1", build_mp4(d, le=len(d["end"]) + 1), e)
    emit("lenStart_zero", build_mp4(d, ls=0), e)
    emit("lenEnd_huge", build_mp4(d, le=0xFFFFFFFF), e)
    emit("version_2", build_mp4(d, ver=2), e)
    emit("kind_2", build_mp4(d, kind=2), e)
    emit("start_as_end", build_mp4(d, end=d["start"]), e)
    emit("manifests_swapped", build_mp4(d, start=d["end"], end=d["start"]), e)
    emit("start_flip", build_mp4(d, start=flip(d["start"], len(d["start"]) // 2)), e)
    emit("media_flip", build_mp4({**d, "head": flip(d["head"], len(d["head"]) // 2)}), e)
    emit("no_box", d["head"] + d["tail"], e)


def main():
    if len(sys.argv) < 2:
        print(__doc__)
        return 2
    src = sys.argv[1]
    out = os.path.abspath(sys.argv[2]) if len(sys.argv) > 2 else OUT
    buf = io.open(src, "rb").read()

    if buf[:3] == b"\xff\xd8\xff":
        gen_jpeg(buf)
    elif buf[:4] == b"\x89PNG":
        # PNG убран 12 сентября 2026 вместе с разбором: приложение его не
        # снимает. Отвечаем внятно, а не молча возвращаем «не тот формат».
        return print("PNG больше не поддерживается: приложение снимает JPEG") or 2
    elif buf[4:8] == b"ftyp":
        gen_mp4(buf)
    else:
        return print("не похоже на JPEG или MP4") or 2

    if not os.path.isdir(out):
        os.makedirs(out)
    for f in os.listdir(out):
        if f.endswith((".jpg", ".mp4")):
            os.remove(os.path.join(out, f))
    total = 0
    for name, data in sorted(cases.items()):
        io.open(os.path.join(out, name), "wb").write(data)
        total += len(data)
    print("случаев: %d, суммарно %.1f МБ" % (len(cases), total / 1048576.0))
    print("каталог:", out)
    print("прогон:  node tools/fuzz_server.mjs \"%s\"" % out)
    return 0


if __name__ == "__main__":
    sys.exit(main())
