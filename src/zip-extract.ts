// SPDX-License-Identifier: Apache-2.0
// Разбор пакета на сервере. Он строже браузерного, и намеренно: браузер
// открывает файл, который человек принёс сам, а сюда файл приходит из
// открытой точки загрузки, куда может обратиться кто угодно.
//
// Размеры — сжатый и исходный — читаются из оглавления самого архива до того,
// как что-либо распаковано. Браузерная проверка берёт их из недокументированного
// внутреннего поля библиотеки JSZip: во вкладке у одного человека это
// допустимо, для открытой точки загрузки — нет.
import { createHash } from "node:crypto";
import { createInflateRaw, inflateRawSync } from "node:zlib";
import { createReadStream, createWriteStream } from "node:fs";
import { open, readFile, stat, type FileHandle } from "node:fs/promises";

// Подписанное фото — PNG или JPEG — читается в память целиком: нужен и вырез
// блока подписи, и хэш. Отсюда верхняя граница, иначе большой файл кладёт
// процесс. Тот же потолок стоит и на фото внутри архива (см. проверку размера
// при разборе): правила не должны расходиться.
const MAX_SIGNED_MEDIA_BYTES = 256 * 1024 * 1024;
/* Видео в память не читается (ядро 1.4.0). Ядру от его байтов нужен только
   SHA-256, и разборщик считает его по ходу чтения: в памяти лежат лишь
   манифесты и блок подписи. Поэтому и потолок другой — гигабайт: столько
   принимает портал, и это около получаса съёмки в качестве HD.
   До 1.4.0 видео читалось целиком и упиралось в те же 256 МБ, что и фото, —
   это около семи минут, и приложению приходилось останавливать запись. */
const MAX_STREAMED_VIDEO_BYTES = 1024 * 1024 * 1024;

async function peekBytes(path: string, n: number): Promise<Buffer> {
  const fh = await open(path, "r");
  try {
    const b = Buffer.alloc(n);
    const { bytesRead } = await fh.read(b, 0, n, 0);
    return b.subarray(0, bytesRead);
  } finally {
    await fh.close();
  }
}

function isMp4Magic(b: Buffer): boolean {
  return b.length >= 8 && b[4] === 0x66 && b[5] === 0x74 && b[6] === 0x79 && b[7] === 0x70; // ftyp
}

function isSignedMediaMagic(b: Buffer): boolean {
  if (isMp4Magic(b)) return true;
  if (b.length >= 8 && b[0] === 0x89 && b[1] === 0x50 && b[2] === 0x4e && b[3] === 0x47) return true; // PNG
  if (b.length >= 3 && b[0] === 0xff && b[1] === 0xd8 && b[2] === 0xff) return true;                  // JPEG (SOI)
  return false;
}
import { unlink } from "node:fs/promises";
import { open as openZip, type Entry, type ZipFile } from "yauzl";
import type { PackageEntries } from "./verify-core/verify-core.js";

const MAX_ENTRIES = 8;
const MAX_EXPANSION_RATIO = 20; // должно совпадать с браузерной проверкой
const MAX_MANIFEST_BYTES = 1024 * 1024; // манифест — небольшой JSON; законных причин быть больше нет

const MEDIA_ENTRIES = new Set(["photo.png", "video.mp4"]);
const MANIFEST_ENTRIES = new Set(["manifest.json", "manifest_start.json", "manifest_end.json"]);
/* Формат 2.0: подпись лежит отдельной записью «имя манифеста + .jws».
   Предел размера ей нужен свой, и он обязателен: пределы навешиваются
   по принадлежности к набору имён, и запись, не попавшая ни в один набор,
   осталась бы вовсе без ограничения, хотя читается в память целиком.
   Цепочка аттестации занимает около 6 КиБ — запас десятикратный. */
const JWS_ENTRIES = new Set([...MANIFEST_ENTRIES].map((n) => n + ".jws"));
const MAX_JWS_BYTES = 64 * 1024;
/* Журнал датчиков — единственная запись пакета, которой позволено
   отсутствовать, и потому единственная, чью судьбу список имён не решает.
   Решает подписанный манифест: есть поле `sensorLogSha256` — запись обязана
   быть и обязана сойтись по хэшу; поля нет — записи быть не должно.

   Обе половины правила стоят в verify-core, после проверки подписи. Будь
   они раньше, нападающему хватило бы вырезать поле из манифеста, чтобы
   разрешить себе подложить любой журнал; вырезать поле нельзя — рассыплется
   подпись. Раздел 1.7 спецификации. */
const SENSORS_ENTRY = "sensors.bin";
const MAX_SENSOR_BYTES = 1024 * 1024;
const ALLOWED_ENTRIES = new Set([...MEDIA_ENTRIES, ...MANIFEST_ENTRIES, ...JWS_ENTRIES, SENSORS_ENTRY]);

/* Класс переехал в verify-core/errors.ts: его обязаны бросать обе стороны —
   и чтение архива, и само ядро, — а маршруты портала ловят через instanceof.
   Реэкспорт оставлен, чтобы все прежние импортирующие продолжали работать. */
export { PackageRejectedError } from "./verify-core/errors.js";
import { PackageRejectedError } from "./verify-core/errors.js";

function openZipFile(path: string): Promise<ZipFile> {
  return new Promise((resolve, reject) => {
    /* `validateEntrySizes` — умолчание yauzl, и на нём висит граница степени
       сжатия: без него библиотека отдаст распакованный поток длиннее
       объявленного, и потолок, который мы сверяем по оглавлению, перестанет
       что-либо значить. Умолчание может смениться с версией; выставляем явно,
       чтобы правило жило в нашем коде, а не в чужом. */
    openZip(path, { lazyEntries: true, autoClose: false, validateEntrySizes: true }, (err, zipfile) => {
      if (err || !zipfile) return reject(err ?? new Error("не удалось открыть архив"));
      resolve(zipfile);
    });
  });
}

/* Сжатая запись обязана кончаться ровно там, где кончается её сжатый поток
   (правка 106). Распаковщики — zlib здесь, JSZip на сайте — останавливаются на
   конце потока deflate, а остаток записи молча пропускают. Замерено 23.09.2026:
   64 КБ произвольных байтов после конца сжатого видео давали ПОДЛИННО и здесь,
   и на сайте. Подделкой содержимого это не было, но было карманом — как
   закрытые раньше комментарии и промежутки между записями: байты лежат в
   подлинном файле, подпись их не покрывает, никто их не видит.

   Поэтому сжатые записи читаются сырыми и распаковываются своим zlib: он
   сообщает, сколько сжатых байт съел (bytesWritten). Выход распаковки ограничен
   объявленным размером — лживое оглавление не раздует память. */
function deflateLeftover(entry: Entry): PackageRejectedError {
  return new PackageRejectedError(`После конца сжатых данных записи ${entry.fileName} есть лишние байты`);
}
function deflateSizeMismatch(entry: Entry): PackageRejectedError {
  return new PackageRejectedError(`Размер записи ${entry.fileName} после распаковки не совпадает с оглавлением`);
}

function openRawStream(zipfile: ZipFile, entry: Entry): Promise<NodeJS.ReadableStream> {
  return new Promise((resolve, reject) => {
    /* decompress: false — сырые сжатые байты ровно длиной записи по оглавлению. */
    zipfile.openReadStream(entry, { decompress: false, decrypt: null, start: null, end: null }, (err, stream) => {
      if (err || !stream) return reject(err ?? new Error("не удалось прочитать запись архива"));
      resolve(stream);
    });
  });
}

function readEntryBuffer(zipfile: ZipFile, entry: Entry): Promise<Buffer> {
  if (entry.compressionMethod === 8) return readDeflatedEntry(zipfile, entry);
  return new Promise((resolve, reject) => {
    zipfile.openReadStream(entry, (err, stream) => {
      if (err || !stream) return reject(err ?? new Error("не удалось прочитать запись архива"));
      const chunks: Buffer[] = [];
      stream.on("data", (c) => chunks.push(c as Buffer));
      stream.on("end", () => resolve(Buffer.concat(chunks)));
      stream.on("error", reject);
    });
  });
}

async function readDeflatedEntry(zipfile: ZipFile, entry: Entry): Promise<Buffer> {
  const stream = await openRawStream(zipfile, entry);
  const raw = await new Promise<Buffer>((resolve, reject) => {
    const chunks: Buffer[] = [];
    stream.on("data", (c) => chunks.push(c as Buffer));
    stream.on("end", () => resolve(Buffer.concat(chunks)));
    stream.on("error", reject);
  });
  type Inflated = { buffer: Buffer; engine: { bytesWritten: number } };
  let out: Inflated;
  try {
    out = (inflateRawSync as unknown as (b: Buffer, o: object) => Inflated)(
      raw, { info: true, maxOutputLength: entry.uncompressedSize + 1 });
  } catch (e) {
    if ((e as { code?: string }).code === "ERR_BUFFER_TOO_LARGE") throw deflateSizeMismatch(entry);
    throw e;
  }
  if (out.engine.bytesWritten !== raw.length) throw deflateLeftover(entry);
  if (out.buffer.length !== entry.uncompressedSize) throw deflateSizeMismatch(entry);
  return out.buffer;
}

/* Запись архива — через SHA-256, не в память. Так читается только видео:
   ядру от его байтов нужен лишь хэш (PackageEntries.videoDigest).
   Строгость та же, что у чтения в буфер: у записи без сжатия yauzl сверяет
   размер сам; сжатая распаковывается своим zlib с теми же правилами —
   конец сжатого потока ровно на конце записи, размер ровно объявленный. */
function hashEntryStream(zipfile: ZipFile, entry: Entry): Promise<{ sha256Hex: string; size: number }> {
  if (entry.compressionMethod === 8) return hashDeflatedEntry(zipfile, entry);
  return new Promise((resolve, reject) => {
    zipfile.openReadStream(entry, (err, stream) => {
      if (err || !stream) return reject(err ?? new Error("не удалось прочитать запись архива"));
      const h = createHash("sha256");
      let size = 0;
      stream.on("data", (c) => {
        h.update(c as Buffer);
        size += (c as Buffer).length;
      });
      stream.on("end", () => resolve({ sha256Hex: h.digest("hex"), size }));
      stream.on("error", reject);
    });
  });
}

async function hashDeflatedEntry(zipfile: ZipFile, entry: Entry): Promise<{ sha256Hex: string; size: number }> {
  const raw = await openRawStream(zipfile, entry);
  return new Promise((resolve, reject) => {
    const inf = createInflateRaw();
    const h = createHash("sha256");
    let size = 0;
    let done = false;
    const fail = (e: unknown) => {
      if (done) return;
      done = true;
      (raw as unknown as { unpipe?: (d: unknown) => void; destroy?: () => void }).unpipe?.(inf);
      (raw as unknown as { destroy?: () => void }).destroy?.();
      inf.destroy();
      reject(e);
    };
    raw.on("error", fail);
    inf.on("error", fail);
    inf.on("data", (c: Buffer) => {
      if (done) return;
      size += c.length;
      /* Больше объявленного — дальше не распаковываем: иначе объявленный в
         оглавлении размер не значил бы ничего. */
      if (size > entry.uncompressedSize) return fail(deflateSizeMismatch(entry));
      h.update(c);
    });
    inf.on("end", () => {
      if (done) return;
      if (inf.bytesWritten !== entry.compressedSize) return fail(deflateLeftover(entry));
      if (size !== entry.uncompressedSize) return fail(deflateSizeMismatch(entry));
      done = true;
      resolve({ sha256Hex: h.digest("hex"), size });
    });
    raw.pipe(inf);
  });
}

function toArrayBuffer(buf: Buffer): ArrayBuffer {
  return buf.buffer.slice(buf.byteOffset, buf.byteOffset + buf.byteLength) as ArrayBuffer;
}

/**
 * Принимает файл из запроса во временный, разбирает его строгим разбором
 * архива и отдаёт записи в том виде, какой нужен verifyPackage.
 *
 * Временный файл удаляется всегда — и при успехе, и при ошибке.
 *
 * На всё, что выглядит враждебным (посторонняя запись, подозрительная степень
 * сжатия, слишком большой манифест), выбрасывается PackageRejectedError:
 * вызывающий обязан отвечать на него ошибкой запроса, а не ошибкой сервера, —
 * это разные вещи, и путать их нельзя.
 */

// ── Подписанный MP4: манифесты в хвостовом uuid-боксе "TVSR-TrustVisor1" ─────
// Возвращает PackageEntries, если buf — MP4 с нашим боксом; null, если это не
// MP4 вовсе; кидает PackageRejectedError для MP4 без бокса (вежливое
// объяснение про пересжатие мессенджером — главный жизненный случай провала).
const SIGNED_MP4_UUID = Buffer.from("TVSR-TrustVisor1", "ascii");

/* Читатель блока подписи с проверкой границ по построению.
 *
 * В формате 1.x полей длины было два у видео и одно у фото, и границы
 * проверялись вручную рядом с каждым чтением. В формате 2.0 их вдвое больше:
 * за каждым манифестом идёт его подпись. Ручные проверки в таком количестве —
 * это гарантированная пропущенная, а пропущенная проверка границы означает
 * чтение за пределами блока.
 *
 * Поэтому читатель один, и мимо него прочитать нельзя: и длина, и данные
 * берутся только через него, и оба упираются в конец блока.
 */
function blockReader(buf: Buffer, start: number, end: number, where: string) {
  let p = start;
  return {
    u32(): number {
      if (p + 4 > end) throw new PackageRejectedError("Повреждён блок подписи в " + where);
      const v = buf.readUInt32BE(p);
      p += 4;
      return v;
    },
    take(n: number, cap: number, what: string): Buffer {
      if (n > cap) throw new PackageRejectedError(what + " в " + where + " слишком большой");
      if (p + n > end) throw new PackageRejectedError("Повреждён блок подписи в " + where);
      const b = buf.subarray(p, p + n);
      p += n;
      return b;
    },
    /* Блок обязан кончиться ровно там, где кончились данные. «Не меньше»
       здесь было карманом: лишние байты вырезались вместе с блоком, в
       манифест не попадали и никому не показывались. */
    requireEnd(msg: string): void {
      if (p !== end) throw new PackageRejectedError(msg);
    },
  };
}

/* Окно чтения файла по смещениям. Обход боксов MP4 читает по заголовку на
   бокс; без окна файл из миллионов крошечных боксов превратил бы гигабайт в
   миллионы системных вызовов. С окном — один запрос на мегабайт, почти как
   прежний обход в памяти. Вызывающий сам следит, чтобы pos + n <= len. */
const FILE_WINDOW_BYTES = 1024 * 1024;

function fileWindow(fh: FileHandle, len: number) {
  let wStart = 0;
  let wBuf: Buffer = Buffer.alloc(0);
  /* peek — без ожидания, когда байты уже в окне (почти всегда); at — с
     чтением диска. Ожидание на каждый бокс стоило секунду с лишним на
     миллион боксов — замерено; так обход идёт со скоростью прежнего. */
  const peek = (pos: number, n: number): Buffer | null =>
    pos >= wStart && pos + n <= wStart + wBuf.length ? wBuf.subarray(pos - wStart, pos - wStart + n) : null;
  const at = async (pos: number, n: number): Promise<Buffer> => {
    const hit = peek(pos, n);
    if (hit) return hit;
    wBuf = await readExact(fh, pos, Math.min(Math.max(n, FILE_WINDOW_BYTES), len - pos));
    wStart = pos;
    return wBuf.subarray(0, n);
  };
  return { peek, at };
}

async function readExact(fh: FileHandle, pos: number, n: number): Promise<Buffer> {
  const b = Buffer.alloc(n);
  let got = 0;
  while (got < n) {
    const { bytesRead } = await fh.read(b, got, n - got, pos + got);
    if (bytesRead === 0) throw new PackageRejectedError("Файл изменился во время проверки");
    got += bytesRead;
  }
  return b;
}

/* Больше этого блок подписи в MP4 быть не может: каждая часть ограничена
   своим пределом, и читатель блока (blockReader) дальше не уйдёт. Потому и в
   память берётся не больше — даже если бокс объявлен гигабайтным. Лишнее за
   этой границей отвергается тем же requireEnd, что и раньше: концом блока
   служит конец бокса, а не конец прочитанного. */
const MAX_MP4_BLOCK_BYTES = 2 + 5 * 4 + 2 * MAX_MANIFEST_BYTES + 2 * MAX_JWS_BYTES + MAX_SENSOR_BYTES;

/* SHA-256 файла без выреза [cutFrom, cutTo) — то есть MP4 без блока подписи.
   Раньше для этого собиралась «чистая» копия в памяти. */
async function sha256FileExcept(path: string, len: number, cutFrom: number, cutTo: number): Promise<{ sha256Hex: string; size: number }> {
  const h = createHash("sha256");
  let size = 0;
  for (const [s, e] of [[0, cutFrom], [cutTo, len]]) {
    if (e <= s) continue;
    for await (const c of createReadStream(path, { start: s, end: e - 1, highWaterMark: FILE_WINDOW_BYTES })) {
      h.update(c as Buffer);
      size += (c as Buffer).length;
    }
  }
  if (size !== len - (cutTo - cutFrom)) throw new PackageRejectedError("Файл изменился во время проверки");
  return { sha256Hex: h.digest("hex"), size };
}

/* Подписанный MP4, прочитанный с диска по частям (ядро 1.4.0).

   Правила разбора — ровно прежние, когда файл целиком лежал в памяти:
   обход боксов верхнего уровня (размер 1 — 64-битный, 0 — до конца файла,
   сломанная структура — выход из обхода), наш бокс узнаётся по метке,
   блок разбирает тот же читатель с теми же текстами отказов. Разница
   одна: байты видео не складываются в память, а идут в хэш.

   Вызывается только для файла с меткой ftyp не короче 16 байт; на MP4 без
   нашего бокса — вежливый отказ про пересжатие мессенджером (главный
   жизненный случай провала). */
async function parseSignedMp4File(path: string, len: number, fileName: string): Promise<PackageEntries> {
  const fh = await open(path, "r");
  let cut: { from: number; to: number } | null = null;
  let parts: {
    startB: Buffer; startJws?: Buffer; endB: Buffer; endJws?: Buffer; sensorLog?: Buffer;
  } | null = null;
  try {
    const win = fileWindow(fh, len);
    let off = 0;
    while (off + 8 <= len) {
      const k = Math.min(16, len - off);
      const h = win.peek(off, k) ?? await win.at(off, k);
      let size = h.readUInt32BE(0);
      let hdr = 8;
      const isUuid = h[4] === 0x75 && h[5] === 0x75 && h[6] === 0x69 && h[7] === 0x64;
      if (size === 1) {
        if (off + 16 > len) break;
        size = Number(h.readBigUInt64BE(8));
        hdr = 16;
      } else if (size === 0) {
        size = len - off;
      }
      if (size < hdr || off + size > len) break; // повреждённая структура — пусть ответит общий путь
      if (isUuid && size >= hdr + 16 + 2 + 8 && (await win.at(off + hdr, 16)).equals(SIGNED_MP4_UUID)) {
        const bodyStart = off + hdr + 16;
        const bodyLen = off + size - bodyStart;
        const body = await readExact(fh, bodyStart, Math.min(bodyLen, MAX_MP4_BLOCK_BYTES));
        const ver = body[0];
        if ((ver !== 1 && ver !== 2 && ver !== 3) || body[1] !== 1)
          throw new PackageRejectedError("Неизвестная версия подписи в MP4 — обновите верификатор");
        /* Формат 2.0: за каждым манифестом идёт его запись подписи. Порядок
           полей тот же, что в архиве, и различаются форматы тем же признаком —
           байтом версии. Откатиться некуда: версия 1 на новом файле уводит в
           старое правило, которое требует отсутствующее поле `signature`. */
        /* Версия 3 — то же, что 2, плюс журнал датчиков последней частью.
           Отдельная версия, а не «часть нулевой длины»: два способа сказать
           «журнала нет» — это два разбора и повод разойтись. Здесь способ
           один, и он сверяется с манифестом в verify-core. */
        const r = blockReader(body, 2, bodyLen, "MP4");
        const startB = r.take(r.u32(), MAX_MANIFEST_BYTES, "Манифест");
        const startJws = ver >= 2 ? r.take(r.u32(), MAX_JWS_BYTES, "Запись подписи") : undefined;
        const endB = r.take(r.u32(), MAX_MANIFEST_BYTES, "Манифест");
        const endJws = ver >= 2 ? r.take(r.u32(), MAX_JWS_BYTES, "Запись подписи") : undefined;
        const sensorLog = ver === 3 ? r.take(r.u32(), MAX_SENSOR_BYTES, "Журнал датчиков") : undefined;
        r.requireEnd("После манифестов в блоке подписи MP4 остались лишние байты");
        parts = { startB, startJws, endB, endJws, sensorLog };
        cut = { from: off, to: off + size };
        break;
      }
      off += size;
    }
  } finally {
    await fh.close();
  }
  if (!cut || !parts) {
    throw new PackageRejectedError(
      "Это обычный MP4 без подписи TrustVisor. Если файл переслали — вероятно, мессенджер пересжал его при отправке «как видео»: попросите отправить как файл/документ либо пришлите исходный .trustvisor.",
    );
  }
  return {
    fileName,
    manifestStartJson: parts.startB.toString("utf-8"),
    manifestEndJson: parts.endB.toString("utf-8"),
    manifestStartJsonBytes: new Uint8Array(parts.startB),
    manifestEndJsonBytes: new Uint8Array(parts.endB),
    manifestStartJwsBytes: parts.startJws ? new Uint8Array(parts.startJws) : undefined,
    manifestEndJwsBytes: parts.endJws ? new Uint8Array(parts.endJws) : undefined,
    sensorLogBytes: parts.sensorLog ? new Uint8Array(parts.sensorLog) : undefined,
    videoDigest: await sha256FileExcept(path, len, cut.from, cut.to),
  };
}

/* Подписанный PNG: манифест в приватном чанке `tvSg` перед IEND.

   ВАЖНО, ПОЧЕМУ ЭТА ВЕТКА ЖИВАЯ. На бесплатном тарифе приложение накладывает
   водяной знак, а рисование знака идёт через Bitmap и заканчивается
   `compress(Bitmap.CompressFormat.PNG, ...)` — то есть каждое бесплатное фото
   является настоящим PNG. На платном знака нет и фото остаётся JPEG.

   12 сентября 2026 эту ветку убрали как «недостижимую», опираясь на
   комментарий в приложении вместо замера, и бесплатные фото, отданные «как
   медиа», стали получать ответ «обычный PNG без подписи». Вернули 13 сентября
   после живой съёмки владельца. Вывод на будущее: прежде чем удалять ветку
   как мёртвую, надо предъявить замер, а не цитату. */
const PNG_SIG = Buffer.from([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a]);

function tryParseSignedPng(buf: Buffer, fileName: string): PackageEntries | null {
  if (buf.length < 8 || !buf.subarray(0, 8).equals(PNG_SIG)) return null;
  let off = 8;
  while (off + 12 <= buf.length) {
    const len = buf.readUInt32BE(off);
    const isTvsg = buf[off + 4] === 0x74 && buf[off + 5] === 0x76 && buf[off + 6] === 0x53 && buf[off + 7] === 0x67;
    if (isTvsg) {
      const p = off + 8;
      if (off + 12 + len > buf.length) throw new PackageRejectedError("Повреждён блок подписи в PNG");
      const ver = buf[p];
      if (len < 6 || (ver !== 1 && ver !== 2 && ver !== 3) || buf[p + 1] !== 2)
        throw new PackageRejectedError("Неизвестная версия подписи в PNG — обновите верификатор");
      /* Концом блока служит конец чанка: чанк не должен быть длиннее, чем
         нужно его содержимому — лишнее было бы карманом. */
      const r = blockReader(buf, p + 2, p + len, "PNG");
      const manifest = r.take(r.u32(), MAX_MANIFEST_BYTES, "Манифест");
      const jws = ver >= 2 ? r.take(r.u32(), MAX_JWS_BYTES, "Запись подписи") : undefined;
      const sensorLog = ver === 3 ? r.take(r.u32(), MAX_SENSOR_BYTES, "Журнал датчиков") : undefined;
      r.requireEnd("После манифеста в чанке подписи PNG остались лишние байты");
      const total = 12 + len;
      const clean = Buffer.concat([buf.subarray(0, off), buf.subarray(off + total)]);
      return {
        fileName,
        manifestJson: manifest.toString("utf-8"),
        manifestJsonBytes: new Uint8Array(manifest),
        manifestJwsBytes: jws ? new Uint8Array(jws) : undefined,
        sensorLogBytes: sensorLog ? new Uint8Array(sensorLog) : undefined,
        photoBuffer: toArrayBuffer(clean),
      };
    }
    if (buf[off + 4] === 0x49 && buf[off + 5] === 0x45 && buf[off + 6] === 0x4e && buf[off + 7] === 0x44) break; // IEND
    off += 12 + len;
  }
  throw new PackageRejectedError(
    "Это обычный PNG без подписи TrustVisor. Если файл переслали — вероятно, мессенджер пересжал его при отправке «как фото»: попросите отправить как файл/документ либо пришлите исходный .trustvisor.",
  );
}

const TVSR_MAGIC = Buffer.from("TVSR-TrustVisor1", "ascii");

/* Подписанный JPEG: блок дописан в хвост, после конца самого изображения.
   Тот же формат, что у MP4 и PNG: магия + версия(1) + вид(2) + длина
   манифеста (4 байта, старшим байтом вперёд) + манифест.

   Ищем магию с конца: в самом изображении такая последовательность байтов
   встретиться может, а дописанный блок всегда последний. Так же поступает и
   браузерный верификатор — расходиться им нельзя.

   Подписанные байты — это изображение БЕЗ хвоста; в пакет они попадают под
   именем photo.png. Это имя записи в пакете, а не расширение файла:
   содержимое (JPEG) хэшируется как есть, ровно так же делает браузер. */
function tryParseSignedJpeg(buf: Buffer, fileName: string): PackageEntries | null {
  if (buf.length < 4 || !(buf[0] === 0xff && buf[1] === 0xd8 && buf[2] === 0xff)) return null;
  const idx = buf.lastIndexOf(TVSR_MAGIC);
  if (idx < 3) {
    throw new PackageRejectedError(
      "Это обычный JPEG без подписи TrustVisor. Если файл переслали — вероятно, мессенджер пересжал его при отправке «как фото»: попросите отправить как файл/документ либо пришлите исходный .trustvisor.",
    );
  }
  const q = idx + TVSR_MAGIC.length;
  if (q + 6 > buf.length) throw new PackageRejectedError("Повреждён блок подписи в JPEG");
  const ver = buf[q];
  if ((ver !== 1 && ver !== 2 && ver !== 3) || buf[q + 1] !== 2)
    throw new PackageRejectedError("Неизвестная версия подписи в JPEG — обновите верификатор");
  /* Блок дописан в самый хвост, поэтому концом блока служит конец файла.
     Проверка «ровно» здесь особенно важна: на настоящей съёмке 1120
     дописанных байт давали ПОДЛИННО. */
  const r = blockReader(buf, q + 2, buf.length, "JPEG");
  const manifest = r.take(r.u32(), MAX_MANIFEST_BYTES, "Манифест");
  const jws = ver >= 2 ? r.take(r.u32(), MAX_JWS_BYTES, "Запись подписи") : undefined;
  const sensorLog = ver === 3 ? r.take(r.u32(), MAX_SENSOR_BYTES, "Журнал датчиков") : undefined;
  r.requireEnd("После манифеста в блоке подписи JPEG остались лишние байты");
  const clean = buf.subarray(0, idx);
  return {
    fileName,
    manifestJson: manifest.toString("utf-8"),
    manifestJsonBytes: new Uint8Array(manifest),
    manifestJwsBytes: jws ? new Uint8Array(jws) : undefined,
    sensorLogBytes: sensorLog ? new Uint8Array(sensorLog) : undefined,
    photoBuffer: toArrayBuffer(clean),
  };
}

/* Имена записей, прочитанные из оглавления архива напрямую.

   Зачем не довериться разборщику: yauzl читает ровно столько записей,
   сколько объявлено в концевой записи, а это число пишет тот, кто собрал
   файл. Занизив его, можно спрятать от сервера лишнюю запись, которую
   браузерный JSZip (он объявленное число игнорирует) прекрасно увидит и
   предпочтёт. Проверено вживую: так один и тот же файл получал у сервера
   «подлинно», а на сайте «изменён».

   Поэтому идём по оглавлению сами и смотрим, что там есть на самом деле.
   Точно такой же разбор стоит в браузерном верификаторе. */
const ZIP64_SENTINEL_16 = 0xffff;
const ZIP64_SENTINEL_32 = 0xffffffff;
const MAX_CENTRAL_DIRECTORY_BYTES = 1024 * 1024;

async function readCentralDirectoryNames(path: string): Promise<{ declared: number; names: string[] } | null> {
  const fh = await open(path, "r");
  try {
    const { size } = await fh.stat();
    if (size < 22) return null;
    /* Концевую запись ищем с конца: её подпись может встретиться и внутри
       данных, но настоящая всегда последняя. Комментарий архива ограничен
       65535 байтами, отсюда размер окна. */
    const tailLen = Math.min(size, 65535 + 22);
    const tail = Buffer.alloc(tailLen);
    await fh.read(tail, 0, tailLen, size - tailLen);
    let eocd = -1;
    for (let i = tail.length - 22; i >= 0; i--) {
      if (tail[i] === 0x50 && tail[i + 1] === 0x4b && tail[i + 2] === 0x05 && tail[i + 3] === 0x06) { eocd = i; break; }
    }
    if (eocd < 0) return null;   /* не наш формат — пусть решает разборщик */

    /* Номера дисков обязаны быть нулевыми, а «записей на этом диске» —
       совпадать с общим числом.

       yauzl читает только номер диска (+4) и на многотомном архиве
       отказывается сам, своим английским текстом; поля +6 и +8 не смотрит
       никто. Браузер после правки 13 сентября проверяет все три, и заслон
       сразу показал расхождение в другую сторону: два байта в +6 или +8
       давали ПОДЛИННО на сервере и ОТКАЗ на сайте. Проверяем явно и тем же
       текстом, что браузер. */
    if (tail.readUInt16LE(eocd + 4) !== 0 || tail.readUInt16LE(eocd + 6) !== 0) {
      throw new PackageRejectedError(
        "Архив объявлен многотомным",
      );
    }
    if (tail.readUInt16LE(eocd + 8) !== tail.readUInt16LE(eocd + 10)) {
      throw new PackageRejectedError(
        "Числа записей в концевой записи не совпадают между собой",
      );
    }
    const declared = tail.readUInt16LE(eocd + 10);
    const cdSize = tail.readUInt32LE(eocd + 12);
    const cdOffset = tail.readUInt32LE(eocd + 16);
    if (declared === ZIP64_SENTINEL_16 || cdSize === ZIP64_SENTINEL_32 || cdOffset === ZIP64_SENTINEL_32) {
      /* ZIP64. Наши пакеты его не порождают никогда: до восьми записей,
         видео до гигабайта (ZIP64 нужен начиная с 4 ГБ). Поддерживать второй формат оглавления значит
         завести второй разборщик и второй повод двум верификаторам
         разойтись — отвергаем в обоих одинаково. */
      throw new PackageRejectedError("Формат ZIP64 не поддерживается — настоящая съёмка его не создаёт");
    }
    if (cdSize > MAX_CENTRAL_DIRECTORY_BYTES || cdOffset + cdSize > size) {
      throw new PackageRejectedError("Оглавление архива повреждено или неправдоподобно большое");
    }
    /* Число записей отсекаем ЗДЕСЬ, до обхода оглавления. Предел в восемь
       записей стоял ниже, в разборщике, а сюда доходил обход всего
       объявленного: на архиве из 22 000 пустых записей (1,64 МБ, помещается
       под потолок оглавления) разбор занимал 1 337 мс против 234 мс на
       настоящей съёмке. Точка приёма файла открытая, и учетверять на ней
       работу полутора мегабайтами не стоит. Настоящий пакет — не больше
       восьми записей по построению: медиа, манифесты, подписи, журнал. */
    if (declared > MAX_ENTRIES) {
      throw new PackageRejectedError(`В архиве объявлено записей: ${declared}, больше ${MAX_ENTRIES} в пакете быть не может`);
    }
    /* Оглавление обязано упираться в концевую запись, без промежутка.
       Промежуток — это то, на что опирается поддержка самораспаковывающихся
       архивов в браузерном JSZip: увидев его, он сдвигает ВСЕ смещения на его
       величину, а yauzl здесь читает смещения как есть. Один и тот же файл
       два разборщика тогда читают по-разному, и это воспроизведено: файл с
       дописанным вторым оглавлением сервер принимает, а сайт отказывается
       открыть. Достаточно дописать сотню байт к настоящей съёмке, чтобы
       получатель увидел «не удалось открыть файл» и счёл доказательство
       поддельным.
       У всех настоящих съёмок промежуток равен нулю: архив пишется подряд. */
    const eocdAbsolute = size - tailLen + eocd;
    if (cdOffset + cdSize !== eocdAbsolute) {
      throw new PackageRejectedError(
        "Между оглавлением архива и его концом есть лишние данные",
      );
    }

    /* После концевой записи законен только объявленный в ней комментарий.

       Найдено перебором: на файле с дописанными в конец байтами (хватало
       ОДНОГО) сайт отвечал ПОДЛИННО, а сервер — ОТКАЗ, причём отвергал не сам,
       а руками yauzl, английским текстом про extra bytes. Проверяем явно и
       одинаковым текстом с браузером.

       Так было до запрета комментария (см. ниже): тогда архив с настоящим
       комментарием проходил, потому что его длина записана здесь же. */
    const archiveCommentLen = tail.readUInt16LE(eocd + 20);
    /* Комментарий архива запрещаем вовсе, а не только сверяем его длину.
       Он законен по формату ZIP и вмещает до 64 КБ чего угодно — то есть был
       карманом для произвольных байтов в файле с вердиктом ПОДЛИННО.
       ZipOutputStream в приложении комментарий не пишет никогда. */
    if (archiveCommentLen !== 0) {
      throw new PackageRejectedError(
        "В конце архива есть комментарий — настоящая съёмка его не пишет",
      );
    }
    if (size !== eocdAbsolute + 22 + archiveCommentLen) {
      throw new PackageRejectedError(
        "После конца архива есть лишние данные",
      );
    }

    /* Раз концевая запись и оглавление на месте — перед нами архив, и он
       обязан начинаться с локального заголовка первой записи.

       Спецификация утверждала, что приставки перед архивом нет — как следствие
       правила о нулевом промежутке. Следствие не работало: приставка с
       пересчитанными смещениями даёт нулевой промежуток и проходила. Проверено
       на приставке в 1 МБ: файл был одновременно подлинной съёмкой и
       исполняемым файлом.

       Проверка стоит здесь, а не в начале: формат допускает второй контейнер —
       подписанное изображение без всякого ZIP, — и до этой строки такой файл
       не доходит, потому что концевой записи у него нет. Первая версия правки
       стояла выше и роняла разбор подписанных JPEG; поймано набором проверок. */
    const head = Buffer.alloc(4);
    const { bytesRead: headRead } = await fh.read(head, 0, 4, 0);
    if (headRead < 4 || !(head[0] === 0x50 && head[1] === 0x4b && head[2] === 0x03 && head[3] === 0x04)) {
      throw new PackageRejectedError(
        "Перед архивом есть посторонние данные",
      );
    }

    const cd = Buffer.alloc(cdSize);
    await fh.read(cd, 0, cdSize, cdOffset);
    const names: string[] = [];
    const layout: { offset: number; nameBytes: Buffer; csize: number; flags: number;
                    crc: number; usize: number }[] = [];
    let p = 0;
    while (p + 46 <= cd.length) {
      if (!(cd[p] === 0x50 && cd[p + 1] === 0x4b && cd[p + 2] === 0x01 && cd[p + 3] === 0x02)) break;
      const nameLen = cd.readUInt16LE(p + 28);
      const extraLen = cd.readUInt16LE(p + 30);
      const commentLen = cd.readUInt16LE(p + 32);
      /* Дополнительное поле и комментарий записи по формату законны и вмещают
         по 64 КБ каждое. Приложение их не пишет, а нам они давали карман:
         байты лежат в файле с вердиктом ПОДЛИННО, в подпись не входят и
         никому не показываются. */
      if (extraLen !== 0 || commentLen !== 0) {
        throw new PackageRejectedError(
          "В записи оглавления есть дополнительное поле или комментарий — настоящая съёмка их не пишет",
        );
      }
      if (p + 46 + nameLen > cd.length) break;
      layout.push({
        offset: cd.readUInt32LE(p + 42),
        /* Байты имени из оглавления — их надо будет сверить с локальным
           заголовком. Сравниваем именно байты, а не разобранную строку:
           разные декодирования одних байтов дают одну строку, и сверка по
           строке пропустила бы подмену. */
        nameBytes: Buffer.from(cd.subarray(p + 46, p + 46 + nameLen)),
        csize: cd.readUInt32LE(p + 20),
        flags: cd.readUInt16LE(p + 8),
        crc: cd.readUInt32LE(p + 16),
        usize: cd.readUInt32LE(p + 24),
      });
      const entryName = cd.subarray(p + 46, p + 46 + nameLen).toString("utf-8");
      /* Путей в именах нет ни одного.

         Проверяем здесь, по сырому имени из оглавления, а не после разборщика:
         JSZip в браузере молча выпрямляет `../manifest.json` и `./manifest.json`
         в `manifest.json`, и проверка, смотрящая на имена после разбора, их
         пропускает. Найдено перебором — ровно так сайт и отвечал
         ПОДЛИННО там, где сервер отвергал.

         Приложение путей не пишет: ZipOutputStream кладёт записи в корень. */
      if (entryName.indexOf("/") >= 0) {
        throw new PackageRejectedError("Неожиданный файл в архиве: " + entryName);
      }
      names.push(entryName);
      p += 46 + nameLen + extraLen + commentLen;
    }
    /* Разбор обязан дойти ровно до конца объявленного оглавления. Раньше цикл
       просто обрывался на первом байте без подписи PK\x01\x02 — и всё, что
       лежало дальше внутри объявленного размера, молча игнорировалось.
       Достаточно было увеличить объявленный размер оглавления и дописать туда
       что угодно: проверка «оглавление упирается в концевую запись» сходилась,
       а лишние байты никто не читал. Проверено на 64 КБ 9 сентября 2026. */
    if (p !== cd.length) {
      throw new PackageRejectedError(
        "В оглавлении архива есть лишние данные",
      );
    }
    /* Записи лежат подряд, без единого свободного байта: первая начинается с
       нуля, каждая следующая — сразу за предыдущей, оглавление — сразу за
       последней. Так пишет ZipOutputStream, и так же требует раздел 1.5
       спецификации; в коде этого не было.

       Без правила между записями помещалось сколько угодно посторонних байтов:
       оба разборщика ходят по смещениям из оглавления и промежутки просто
       перешагивают. Проверено на 5 МБ — вердикт оставался ПОДЛИННО, причём и
       на сервере, и в браузере. */
    layout.sort((a, b) => a.offset - b.offset);
    let expect = 0;
    for (const rec of layout) {
      if (rec.offset !== expect) {
        throw new PackageRejectedError(
          "Между записями архива есть свободное место",
        );
      }
      const lh = Buffer.alloc(30);
      const { bytesRead: lhRead } = await fh.read(lh, 0, 30, rec.offset);
      if (lhRead < 30 || lh.readUInt32LE(0) !== 0x04034b50) {
        throw new PackageRejectedError("Запись архива не начинается с локального заголовка");
      }
      if (lh.readUInt16LE(28) !== 0) {
        throw new PackageRejectedError(
          "В заголовке записи есть дополнительное поле — настоящая съёмка его не пишет",
        );
      }
      /* Имя в локальном заголовке обязано совпасть с именем в оглавлении.

         Без этой сверки один байт разводил два проверяльщика: yauzl берёт
         имя из оглавления, JSZip — из локального заголовка (документированное
         поведение readLocalPart). Меняем `photo.png` на `photo.qng` только в
         локальном заголовке, оглавление не трогаем — сервер отвечал
         ПОДЛИННО, а публичная страница отказывалась открыть файл как
         содержащий постороннее. Проверено на настоящей съёмке. */
      const nameLenLocal = lh.readUInt16LE(26);
      if (nameLenLocal !== rec.nameBytes.length) {
        throw new PackageRejectedError(
          "Имя записи в заголовке не совпадает с оглавлением",
        );
      }
      const nameLocal = Buffer.alloc(nameLenLocal);
      const { bytesRead: nRead } = await fh.read(nameLocal, 0, nameLenLocal, rec.offset + 30);
      if (nRead < nameLenLocal || !nameLocal.equals(rec.nameBytes)) {
        throw new PackageRejectedError(
          "Имя записи в заголовке не совпадает с оглавлением",
        );
      }
      expect = rec.offset + 30 + lh.readUInt16LE(26) + rec.csize;
      if (rec.flags & 8) {
        /* Размер записан не в заголовке, а в дескрипторе после данных — так
           пишет поток, и настоящие съёмки с телефона именно такие. Дескриптор
           бывает с подписью (16 байт) и без неё (12); различаем по подписи, а
           не по догадке. */
        const dd = Buffer.alloc(16);
        const { bytesRead: ddRead } = await fh.read(dd, 0, 16, expect);
        const ddSigned = ddRead >= 4 && dd.readUInt32LE(0) === 0x08074b50;
        const ddLen = ddSigned ? 16 : 12;
        if (ddRead < ddLen) {
          throw new PackageRejectedError("Дескриптор записи обрывается за границей архива");
        }
        /* Три числа дескриптора обязаны совпасть с оглавлением. Без этой
           сверки они были свободны: разборщик брал размеры из оглавления, а
           дескриптор только перешагивал. Проверено на настоящей съёмке —
           12 подменённых байт на запись не меняли вердикт ПОДЛИННО. */
        const ddAt = ddSigned ? 4 : 0;
        if (dd.readUInt32LE(ddAt) !== rec.crc
            || dd.readUInt32LE(ddAt + 4) !== rec.csize
            || dd.readUInt32LE(ddAt + 8) !== rec.usize) {
          throw new PackageRejectedError(
            "Дескриптор записи не совпадает с оглавлением",
          );
        }
        expect += ddLen;
      }
    }
    if (expect !== cdOffset) {
      throw new PackageRejectedError(
        "Между последней записью и оглавлением есть свободное место",
      );
    }
    return { declared, names };
  } finally {
    await fh.close();
  }
}

export async function extractPackage(fileStream: NodeJS.ReadableStream, fileName: string, tempPath: string): Promise<PackageEntries> {
  await new Promise<void>((resolve, reject) => {
    const out = createWriteStream(tempPath);
    fileStream.pipe(out);
    fileStream.on("error", reject);
    out.on("error", reject);
    out.on("finish", () => resolve());
  });

  try {
    return await extractPackageFromPath(tempPath, fileName);
  } finally {
    await unlink(tempPath).catch(() => {});
  }
}

/* Тот же разбор для файла, который уже лежит на диске и должен там остаться.
   Копировать его во временный файл только ради проверки значило бы удваивать
   пик занятого места на каждую загрузку. */
export async function extractPackageFromPath(tempPath: string, fileName: string): Promise<PackageEntries> {
  /* Магию смотрим ПЕРВОЙ. Оглавление архива ищется в последних 65 557 байтах,
     и у подписанного медиа там может случайно оказаться подпись концевой записи
     — четыре байта. Тогда честное фото получало отказ «архив объявлен
     многотомным» и до проверки подписи не доходило вовсе. Воспроизведено 15
     сентября 2026. Браузерная копия проверяет магию первой с самого начала. */
  const magic = await peekBytes(tempPath, 16);
  const isMedia = isSignedMediaMagic(magic);

  // Состав оглавления проверяем ДО того, как отдать файл разборщику:
  // разборщик читает ровно столько записей, сколько объявлено, и спрятанную
  // запись просто не покажет. Подробности — в readCentralDirectoryNames.
  const cdInfo = isMedia ? null : await readCentralDirectoryNames(tempPath);
  if (cdInfo) {
    const seen = new Set<string>();
    for (const n of cdInfo.names) {
      if (seen.has(n)) {
        throw new PackageRejectedError(`Повторяющееся имя в архиве: ${n}`);
      }
      seen.add(n);
    }
    if (cdInfo.names.length !== cdInfo.declared) {
      // Оглавление содержит не то число записей, которое объявлено. Даже
      // без дублей это опасно: разные разборщики прочитают разный набор,
      // а значит два верификатора могут дать разные вердикты на одном файле.
      throw new PackageRejectedError(
        `Оглавление архива не сходится: записей ${cdInfo.names.length}, объявлено ${cdInfo.declared}`,
      );
    }
  }

  // DoS-защита: НЕ читаем весь файл в память ради детекции. Сначала пикаем
  // 16 байт магии; целиком в Buffer берём только распознанное MP4/PNG и
  // только в пределах лимита. Всё остальное (zip-пакеты) — потоковым путём.
  if (isMedia) {
    const { size } = await stat(tempPath);
    /* Видео — по частям и до гигабайта; фото — в память и до 256 МБ.
       MP4 короче 16 байт не разбирался и прежде — идёт общим путём. */
    if (isMp4Magic(magic) && size >= 16) {
      if (size > MAX_STREAMED_VIDEO_BYTES)
        throw new PackageRejectedError("Файл слишком большой для подписанного MP4/PNG");
      return await parseSignedMp4File(tempPath, size, fileName);
    }
    if (size > MAX_SIGNED_MEDIA_BYTES)
      throw new PackageRejectedError("Файл слишком большой для подписанного MP4/PNG");
    const head = await readFile(tempPath);
    const signedPng = tryParseSignedPng(head, fileName);
    if (signedPng) return signedPng;
    const signedJpeg = tryParseSignedJpeg(head, fileName);
    if (signedJpeg) return signedJpeg;
  }

  const zipfile = await openZipFile(tempPath);
  /* Мелкие записи — в память; видео — только отпечатком (videoDigest).
     Поэтому состав пакета ведётся отдельным набором имён, а не ключами
     буферов: видео в буферах нет. */
  const buffers = new Map<string, Buffer>();
  const names = new Set<string>();
  let videoDigest: { sha256Hex: string; size: number } | undefined;
  let entryCount = 0;

  await new Promise<void>((resolve, reject) => {
    zipfile.on("error", reject);
    zipfile.on("end", () => resolve());
    zipfile.on("entry", (entry: Entry) => {
      if (/\/$/.test(entry.fileName)) {
        zipfile.readEntry();
        return;
      }
      entryCount++;
      if (entryCount > MAX_ENTRIES) {
        reject(new PackageRejectedError(`Слишком много файлов в архиве (>${MAX_ENTRIES})`));
        return;
      }
      if (!ALLOWED_ENTRIES.has(entry.fileName)) {
        reject(new PackageRejectedError(`Неожиданный файл в архиве: ${entry.fileName}`));
        return;
      }
      // Второй рубеж. Основную проверку делает readCentralDirectoryNames
      // выше — она читает оглавление напрямую и не верит заявленному числу
      // записей. Здесь дубль ловится только если его выдал сам разборщик;
      // проверка дешёвая, поэтому оставлена.
      if (names.has(entry.fileName)) {
        reject(new PackageRejectedError(`Повторяющееся имя в архиве: ${entry.fileName}`));
        return;
      }
      // Абсолютный размер медиа внутри архива. Проверка степени сжатия
      // выше ловит «архивную бомбу», но не ловит честно несжатый файл:
      // у него степень сжатия 1.0, и он проходил. Фото читается в память
      // целиком — одна гигабайтная запись означала бы гигабайт в памяти
      // процесса. Видео идёт потоком в хэш, но и у него потолок есть: время
      // проверки тоже ресурс. Потолки те же, что у отдельного подписанного
      // медиа, чтобы правила не расходились.
      const mediaCap = entry.fileName === "video.mp4" ? MAX_STREAMED_VIDEO_BYTES : MAX_SIGNED_MEDIA_BYTES;
      if (MEDIA_ENTRIES.has(entry.fileName) && entry.uncompressedSize > mediaCap) {
        reject(new PackageRejectedError(`Медиафайл в архиве слишком большой: ${entry.fileName}`));
        return;
      }
      if (entry.compressedSize > 0 && entry.uncompressedSize / entry.compressedSize > MAX_EXPANSION_RATIO) {
        reject(new PackageRejectedError(`Подозрительная степень сжатия (${entry.fileName})`));
        return;
      }
      if (MANIFEST_ENTRIES.has(entry.fileName) && entry.uncompressedSize > MAX_MANIFEST_BYTES) {
        reject(new PackageRejectedError(`Манифест слишком большой: ${entry.fileName}`));
        return;
      }
      /* Предел на запись подписи проверяется ДО чтения в память, как и у
         манифеста: иначе объявленный размер решает, сколько мы прочитаем. */
      if (JWS_ENTRIES.has(entry.fileName) && entry.uncompressedSize > MAX_JWS_BYTES) {
        reject(new PackageRejectedError(`Запись подписи слишком большая: ${entry.fileName}`));
        return;
      }
      /* Тот же порядок и для журнала: сначала объявленный размер, потом
         чтение. Журнал читается в память целиком, и без этого предела
         объявленный размер решал бы, сколько памяти мы займём. */
      if (entry.fileName === SENSORS_ENTRY && entry.uncompressedSize > MAX_SENSOR_BYTES) {
        reject(new PackageRejectedError("Журнал датчиков слишком большой"));
        return;
      }
      names.add(entry.fileName);
      if (entry.fileName === "video.mp4") {
        hashEntryStream(zipfile, entry)
          .then((d) => {
            videoDigest = d;
            zipfile.readEntry();
          })
          .catch(reject);
        return;
      }
      readEntryBuffer(zipfile, entry)
        .then((buf) => {
          buffers.set(entry.fileName, buf);
          zipfile.readEntry();
        })
        .catch(reject);
    });
    zipfile.readEntry();
  });
  zipfile.close();

  const isPhoto = names.has("photo.png");
  /* Настоящая съёмка — всегда либо фото, либо видео: пути, который положил
     бы в один пакет и то и другое, в приложении нет. Пакет с обоими может
     быть только собран руками — например, к честному проверенному фото
     подшили постороннее видео, чтобы оно проехало на чужом вердикте.
     Раньше такое видео лежало здесь же, доступное для чтения, но его никто
     не смотрел: ветка по типу выбирала фото и на этом останавливалась.
     Отвергаем целиком, а не разбираем одно и молчим про другое. */
  if (isPhoto && names.has("video.mp4")) {
    throw new PackageRejectedError("Пакет содержит и photo.png, и video.mp4 — настоящая съёмка никогда не производит оба одновременно");
  }
  /* Набор допустимых имён зависит от типа пакета, а не общий на оба.

     Раньше ALLOWED_ENTRIES был объединением всех пяти имён, поэтому
     видеопакет с дописанным manifest.json проходил допуск, а дальше ветка
     по типу его просто не читала: сервер отвечал ПОДЛИННО, а сайт —
     «посторонние файлы». Воспроизведено на настоящем demo.trustvisor.

     Молча игнорировать лишнее нельзя: ровно на «оно просто лежит рядом»
     и строится подмена — к проверенному фото подшивают чужое видео. */
  /* Формат определяется наличием записи подписи, и «хоть одна» здесь важнее,
     чем «все». Если считать форматом 2.0 только полный набор, то видеопакет
     с одной удалённой подписью соскользнул бы в правила 1.x и получил отказ
     по другой причине — «в манифесте нет поля signature». Это отказ, но не
     тот: он прячет настоящую причину и открывает путь понижения формата.
     Поэтому: увидели хоть одну `.jws` — разбираем как 2.0 и требуем все. */
  const jwsNames = [...names].filter((n) => JWS_ENTRIES.has(n));
  const isV2 = jwsNames.length > 0;
  /* `sensors.bin` стоит в наборе только у 2.0 и только как разрешённая:
     здесь она может отсутствовать, не вызвав отказа. Файл 1.x её нести не
     может — там она посторонняя запись и пакет отвергается. */
  const expected = isPhoto
    ? (isV2 ? ["manifest.json", "manifest.json.jws", "photo.png", SENSORS_ENTRY]
            : ["manifest.json", "photo.png"])
    : (isV2 ? ["manifest_start.json", "manifest_start.json.jws",
               "manifest_end.json", "manifest_end.json.jws", "video.mp4", SENSORS_ENTRY]
            : ["manifest_start.json", "manifest_end.json", "video.mp4"]);
  const strayNames = [...names].filter((n) => expected.indexOf(n) < 0);
  if (strayNames.length) {
    throw new PackageRejectedError(
      "Пакет содержит посторонние файлы: " + strayNames.join(", ") +
      ". Подписан только заявленный набор — остальное к доказательству отношения не имеет",
    );
  }

  /* Недостающая запись подписи — отдельная ошибка с отдельным текстом.
     Список `expected` ловит лишнее, но не ловит недостающее, и без этой
     проверки видеопакет с одной подписью дошёл бы до проверки вердикта. */
  if (isV2) {
    for (const name of expected.filter((n) => JWS_ENTRIES.has(n))) {
      if (!names.has(name)) {
        throw new PackageRejectedError("В пакете нет записи подписи " + name);
      }
    }
  }

  const sensorsRaw = buffers.get(SENSORS_ENTRY);
  const sensorLog = sensorsRaw ? new Uint8Array(sensorsRaw) : undefined;

  if (isPhoto) {
    const manifestJson = buffers.get("manifest.json");
    const photoBuffer = buffers.get("photo.png");
    if (!manifestJson || !photoBuffer) throw new PackageRejectedError("Пакет не содержит manifest.json и photo.png вместе");
    return {
      fileName,
      manifestJson: manifestJson.toString("utf-8"),
      manifestJsonBytes: new Uint8Array(manifestJson),
      manifestJwsBytes: isV2 ? new Uint8Array(buffers.get("manifest.json.jws")!) : undefined,
      sensorLogBytes: sensorLog,
      photoBuffer: toArrayBuffer(photoBuffer),
    };
  }
  const manifestStart = buffers.get("manifest_start.json");
  const manifestEnd = buffers.get("manifest_end.json");
  if (!manifestStart || !manifestEnd || !videoDigest)
    throw new PackageRejectedError("Пакет не содержит manifest_start.json, manifest_end.json и video.mp4 вместе");
  return {
    fileName,
    manifestStartJson: manifestStart.toString("utf-8"),
    manifestEndJson: manifestEnd.toString("utf-8"),
    manifestStartJsonBytes: new Uint8Array(manifestStart),
    manifestEndJsonBytes: new Uint8Array(manifestEnd),
    manifestStartJwsBytes: isV2 ? new Uint8Array(buffers.get("manifest_start.json.jws")!) : undefined,
    manifestEndJwsBytes: isV2 ? new Uint8Array(buffers.get("manifest_end.json.jws")!) : undefined,
    sensorLogBytes: sensorLog,
    videoDigest,
  };
}
