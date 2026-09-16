// SPDX-License-Identifier: Apache-2.0
/* Модульные тесты ядра проверки.
 *
 * ЗАЧЕМ. По каждому закрытому способу обмана — два теста: отрицательный
 * (подделка отвергается) и положительный (настоящая съёмка проходит).
 * Второй не менее важен: заслон, который отвергает честный файл, — это
 * тоже поломка, и без такого теста её легко не заметить.
 *
 * ЗАПУСК: npm run build && npm test
 *         Сборка обязательна: тесты идут по собранному коду, то есть по
 *         тому, который реально работает.
 *
 * Тесты не ходят в сеть и ничего не меняют — их можно гонять при каждой сборке.
 */
import { strict as assert } from "node:assert";
import { test, describe } from "node:test";
import { createReadStream, existsSync, writeFileSync, unlinkSync, readFileSync } from "node:fs";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { randomUUID, createHash, generateKeyPairSync, sign } from "node:crypto";
import { crc32 } from "node:zlib";
/* Импорт из dist, а не из src — намеренно: проверяем ровно тот код, который
   реально работает в проде. Заодно это единственный способ, который не
   спотыкается о цепочку .js-импортов внутри самих модулей при запуске из
   исходников. Перед тестами обязателен npm run build. */
import { extractPackage, extractPackageFromPath, PackageRejectedError } from "../../dist/zip-extract.js";
import {
  verifyPackage,
  checkAttestationChallengeFreshness,
  CHALLENGE_TTL_MS,
  CHALLENGE_TTL_LEGACY_MS,
  CHALLENGE_TTL_SWITCH_MS,
  challengeTtlMs,
  downgradeReasonsOf,
  isTimeOnlyDowngrade,
  checkServerAnchor,
  withAnchorWitness,
  checkDeviceClock,
  checkGpsTime,
  checkLocationMock,
  checkLocationSecondOpinion,
  checkGnssPortrait,
  parseDetachedJws,
  verifyDetachedJws,
  assertNoV1Fields,
  parseSensorLog,
  checkSensorLog,
  derTLV,
  parseCertMeta,
  parseAndroidKeystoreExt,
  checkOid,
  checkRootOfTrust,
} from "../../dist/verify-core/verify-core.js";

/* Путь к настоящей подписанной съёмке для положительных тестов.
   Задаётся переменной окружения: заслон, отвергающий честный файл, —
   такая же поломка, как пропущенная подделка, и без реального файла
   эту половину проверок не сделать. */
const REAL_PHOTO = process.env.TV_REAL_PACKAGE ?? "samples/genuine-photo.trustvisor";
const haveReal = existsSync(REAL_PHOTO);

/* То же для видео. У него другой путь: два манифеста, две подписи и сверка
   сессии, — и без отдельной положительной проверки он оставался незакрытым. */
const REAL_VIDEO = process.env.TV_REAL_VIDEO ?? "samples/genuine.trustvisor";
const haveVideo = existsSync(REAL_VIDEO);

/* То же для формата 2.0. Отдельные файлы, а не переключатель: оба формата
   живут одновременно — файлы 1.x у людей на руках останутся навсегда, — и
   проверять надо оба, а не тот, что новее. */
const REAL_2_0_PHOTO = process.env.TV_REAL_2_0_PHOTO ?? "samples/genuine-2.0-photo.trustvisor";
const REAL_2_0_VIDEO = process.env.TV_REAL_2_0_VIDEO ?? "samples/genuine-2.0-video.trustvisor";
const have20Photo = existsSync(REAL_2_0_PHOTO);
const have20Video = existsSync(REAL_2_0_VIDEO);

/* Производные образцы делает samples/make_samples.py; в репозитории их нет,
   поэтому проверки по ним включаются, только если файлы уже сделаны. */
const TAMPERED = "samples/tampered.trustvisor";
const UNATTESTED = "samples/unattested.trustvisor";

/* ── Минимальный сборщик ZIP без сжатия ──────────────────────────────────
   Собираем архивы РУКАМИ, а не библиотекой: атакующий тоже не связан её
   ограничениями. Библиотека, например, не даст положить два файла с одним
   именем — а именно это и надо проверить. */
function buildZip(entries: { name: string; data: Buffer }[], declaredCount?: number): Buffer {
  /* declaredCount — намеренная ЛОЖЬ в концевой записи. Нужна для проверки
     найденного обхода: разборщики по-разному относятся к этому числу,
     и это давало два разных вердикта на одном файле. */
  const locals: Buffer[] = [], central: Buffer[] = [];
  let offset = 0;
  for (const { name, data } of entries) {
    const nameBuf = Buffer.from(name, "utf-8");
    const crc = crc32(data);
    const lh = Buffer.alloc(30);
    lh.writeUInt32LE(0x04034b50, 0); lh.writeUInt16LE(20, 4);
    lh.writeUInt32LE(crc, 14); lh.writeUInt32LE(data.length, 18); lh.writeUInt32LE(data.length, 22);
    lh.writeUInt16LE(nameBuf.length, 26);
    locals.push(lh, nameBuf, data);

    const ch = Buffer.alloc(46);
    ch.writeUInt32LE(0x02014b50, 0); ch.writeUInt16LE(20, 4); ch.writeUInt16LE(20, 6);
    ch.writeUInt32LE(crc, 16); ch.writeUInt32LE(data.length, 20); ch.writeUInt32LE(data.length, 24);
    ch.writeUInt16LE(nameBuf.length, 28); ch.writeUInt32LE(offset, 42);
    central.push(ch, nameBuf);
    offset += 30 + nameBuf.length + data.length;
  }
  const cd = Buffer.concat(central);
  const eocd = Buffer.alloc(22);
  eocd.writeUInt32LE(0x06054b50, 0);
  const declared = declaredCount ?? entries.length;
  eocd.writeUInt16LE(declared, 8); eocd.writeUInt16LE(declared, 10);
  eocd.writeUInt32LE(cd.length, 12); eocd.writeUInt32LE(offset, 16);
  return Buffer.concat([...locals, cd, eocd]);
}

async function extract(buf: Buffer, fileName = "x.trustvisor") {
  const src = join(tmpdir(), "t-" + randomUUID());
  writeFileSync(src, buf);
  const tmp = join(tmpdir(), "t-" + randomUUID() + ".zip");
  try {
    return await extractPackage(createReadStream(src), fileName, tmp);
  } finally {
    try { unlinkSync(src); } catch { /* уже удалён */ }
  }
}

const TINY_MANIFEST = Buffer.from('{"a":1}', "utf-8");
const TINY_PNG = Buffer.from([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a]);

/* ═══════════════════════════════════════════════════════════════════════ */
describe("Состав архива", () => {
  test("два файла с одним именем — отказ", async () => {
    /* ZIP не запрещает дубли, и разные разборщики берут разное: кто первый,
       кто последний. Мы клали в словарь по имени и молча брали последний.
       Такой пакет — заготовка для расхождения браузерного и серверного
       верификаторов на одном файле, а это главная опасность в проекте. */
    const zip = buildZip([
      { name: "manifest.json", data: TINY_MANIFEST },
      { name: "manifest.json", data: Buffer.from('{"a":2}', "utf-8") },
      { name: "photo.png", data: TINY_PNG },
    ]);
    await assert.rejects(() => extract(zip), (e: Error) =>
      e instanceof PackageRejectedError && /Повторяющееся имя/.test(e.message));
  });

  test("медиа сверх 256 МБ — отказ, даже несжатое", async () => {
    /* Проверка степени сжатия ловит архивную бомбу, но НЕ ловит честно
       несжатый файл: у него степень сжатия 1.0. А содержимое читается в
       память целиком — гигабайтная запись останавливает портал целиком. */
    const zip = buildZip([
      { name: "manifest.json", data: TINY_MANIFEST },
      { name: "photo.png", data: Buffer.alloc(260 * 1024 * 1024, 7) },
    ]);
    await assert.rejects(() => extract(zip), (e: Error) =>
      e instanceof PackageRejectedError && /слишком большой/.test(e.message));
  });

  test("дубль, спрятанный ложью о числе записей, — отказ", async () => {
    /* Обход, найденный перебором испорченных файлов.
       Первая версия проверки на дубли сравнивала ЗАЯВЛЕННОЕ в концевой
       записи число записей с числом различимых имён. Это обходится ложью
       в два байта: yauzl читает ровно объявленное число и третью запись не
       видит, а JSZip в браузере читает всё оглавление и берёт ПОСЛЕДНЮЮ.

       Измерено на настоящем пакете: сервер взял настоящее фото и сказал бы
       ПОДЛИННО, браузер взял поддельное и сказал ИЗМЕНЁН. Один файл, два
       вердикта — ровно то, ради чего проверка и писалась. */
    const zip = buildZip([
      { name: "manifest.json", data: TINY_MANIFEST },
      { name: "photo.png", data: TINY_PNG },
      { name: "photo.png", data: Buffer.from([1, 2, 3, 4]) },
    ], 2);   // записей три, объявлено две
    await assert.rejects(() => extract(zip), (e: Error) =>
      e instanceof PackageRejectedError && /Повторяющееся имя/.test(e.message));
  });

  test("завышенное число записей — отказ", async () => {
    /* Обратная ложь. Дублей нет, но разборщики прочитают разный набор —
       значит могут разойтись в вердикте. */
    const zip = buildZip([
      { name: "manifest.json", data: TINY_MANIFEST },
      { name: "photo.png", data: TINY_PNG },
    ], 5);
    await assert.rejects(() => extract(zip), (e: Error) =>
      e instanceof PackageRejectedError && /не сходится/.test(e.message));
  });

  test("посторонний файл в архиве — отказ", async () => {
    const zip = buildZip([
      { name: "manifest.json", data: TINY_MANIFEST },
      { name: "photo.png", data: TINY_PNG },
      { name: "readme.txt", data: Buffer.from("hi") },
    ]);
    await assert.rejects(() => extract(zip), (e: Error) =>
      e instanceof PackageRejectedError && /Неожиданный файл/.test(e.message));
  });

  test("фото и видео вместе — отказ", async () => {
    /* Настоящая съёмка никогда не производит оба сразу. Такой пакет — способ
       протащить непроверенное видео на чистом вердикте фотографии. */
    const zip = buildZip([
      { name: "manifest.json", data: TINY_MANIFEST },
      { name: "photo.png", data: TINY_PNG },
      { name: "video.mp4", data: Buffer.from([0, 0, 0, 0]) },
    ]);
    await assert.rejects(() => extract(zip), (e: Error) => /photo.png/.test(e.message));
  });

  test("лишние байты между оглавлением и концом архива — отказ", async () => {
    /* Найдено перебором. JSZip, увидев промежуток между концом оглавления и
       концевой записью, сдвигает на его величину ВСЕ смещения — так он
       поддерживает самораспаковывающиеся архивы. yauzl читает смещения как
       есть. Один и тот же файл два разборщика читают по-разному.

       Воспроизведено: к архиву дописано второе оглавление той же длины —
       сервер файл принимал и разбирал, а сайт отказывался открыть вовсе.
       Опасно это не подделкой (сдвиг ломает и локальные смещения), а
       обратным: достаточно дописать сотню байт к НАСТОЯЩЕЙ съёмке, чтобы
       получатель на сайте увидел «не удалось открыть файл» и счёл
       доказательство поддельным.

       У всех настоящих съёмок промежуток равен нулю (проверено на 19
       файлах с полки, включая демонстрационный на сайте). */
    const clean = buildZip([
      { name: "manifest.json", data: TINY_MANIFEST },
      { name: "photo.png", data: TINY_PNG },
    ]);
    /* Вставляю лишний байт прямо перед концевой записью, оставляя саму
       запись нетронутой: смещение и размер оглавления в ней прежние. */
    const withGap = Buffer.concat([
      clean.subarray(0, clean.length - 22),
      Buffer.from([0x41]),
      clean.subarray(clean.length - 22),
    ]);
    await assert.rejects(() => extract(withGap), (e: Error) => /лишние данные/.test(e.message));
  });

  test("обычный пакет из двух файлов разбирается", async () => {
    const zip = buildZip([
      { name: "manifest.json", data: TINY_MANIFEST },
      { name: "photo.png", data: TINY_PNG },
    ]);
    const entries = await extract(zip);
    assert.equal(entries.manifestJson, '{"a":1}');
  });
});

/* ═══════════════════════════════════════════════════════════════════════ */
describe("Подписанный JPEG", () => {
  /* Браузерный верификатор понимал этот формат, серверный — нет: один и тот
     же файл на сайте проверялся, а через портал отвергался как неизвестный.
     Это то же расхождение двух верификаторов, только с обратным знаком. */
  function signedJpeg(manifest: Buffer): Buffer {
    const body = Buffer.from([
      0xff, 0xd8, 0xff, 0xe0, 0x00, 0x10, 0x4a, 0x46, 0x49, 0x46, 0x00,
      0x01, 0x01, 0x00, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0xff, 0xd9,
    ]);
    const len = Buffer.alloc(4);
    len.writeUInt32BE(manifest.length);
    return Buffer.concat([body, Buffer.from("TVSR-TrustVisor1", "ascii"),
                          Buffer.from([0x01, 0x02]), len, manifest]);
  }

  test("разбирается, манифест достаётся целиком", async () => {
    const m = Buffer.from('{"mediaSha256":"deadbeef"}', "utf-8");
    const entries = await extract(signedJpeg(m), "probe.jpg");
    assert.equal(entries.manifestJson, m.toString("utf-8"));
    assert.ok(entries.photoBuffer, "изображение должно попасть в пакет");
  });

  test("подписанные байты — изображение БЕЗ хвостового блока", async () => {
    /* Хэшируется именно изображение, а не файл с приклеенным манифестом:
       иначе подпись никогда бы не сошлась. */
    const m = Buffer.from('{"a":1}', "utf-8");
    const entries = await extract(signedJpeg(m), "probe.jpg");
    const photo = Buffer.from(entries.photoBuffer as ArrayBuffer);
    assert.equal(photo.length, 22, "должно остаться только само JPEG-изображение");
    assert.equal(photo[0], 0xff);
    assert.equal(photo[1], 0xd8);
  });

  test("обычный JPEG без подписи — понятный отказ, а не молчание", async () => {
    const plain = Buffer.from([0xff, 0xd8, 0xff, 0xe0, 0x00, 0x10, 0xff, 0xd9]);
    await assert.rejects(() => extract(plain, "plain.jpg"), (e: Error) =>
      /без подписи TrustVisor/.test(e.message));
  });

  test("манифест сверх мегабайта — отказ", async () => {
    await assert.rejects(() => extract(signedJpeg(Buffer.alloc(2 * 1024 * 1024, 0x20)), "big.jpg"),
      (e: Error) => /слишком большой/.test(e.message));
  });
});

/* ═══════════════════════════════════════════════════════════════════════ */
describe("Настоящая съёмка", { skip: haveReal ? false : "нет samples/genuine-photo.trustvisor" }, () => {
  test("проходит как ПОДЛИННАЯ", async () => {
    /* Главный положительный тест: все заслоны выше не должны мешать
       честному файлу. Заслон, отвергающий настоящую съёмку, — тоже поломка. */
    const entries = await extract(readFileSync(REAL_PHOTO));
    const r = await verifyPackage(entries);
    assert.equal(r.allPass, true, "настоящая съёмка обязана пройти все проверки");
    assert.equal(r.trustDowngrade, false, "и не должна понижаться в доверии");
  });

  test("изменённый байт медиа ломает вердикт", async () => {
    const raw = readFileSync(REAL_PHOTO);
    const entries = await extract(raw);
    const photo = Buffer.from(entries.photoBuffer as ArrayBuffer);
    photo[Math.floor(photo.length / 2)] ^= 0xff;
    const tampered = { ...entries, photoBuffer: photo.buffer.slice(
      photo.byteOffset, photo.byteOffset + photo.byteLength) as ArrayBuffer };
    const r = await verifyPackage(tampered);
    assert.equal(r.allPass, false, "подмена байта обязана ломать проверку");
  });

  test("изменённое значение в манифесте ломает подпись", async () => {
    /* Меняем время съёмки — самое безобидное на вид поле. Подпись обязана
       развалиться от любого изменённого значения, а не только от «важных».

       Первая версия этого теста правила поле "timestamp", которого в
       манифесте нет вовсе (время называется capturedAt). Замена молча не
       срабатывала, файл оставался нетронутым и честно проходил проверку —
       а тест кричал «подделка прошла!». Отсюда явная проверка ниже: тест,
       который не изменил то, что собирался, обязан падать с внятным
       объяснением, а не выдавать чужую ошибку за находку. */
    const entries = await extract(readFileSync(REAL_PHOTO));
    const before = entries.manifestJson!;
    const m = JSON.parse(before) as Record<string, unknown>;
    assert.ok("capturedAt" in m, "в манифесте должно быть поле capturedAt");
    const after = before.replace(String(m.capturedAt), String(m.capturedAt).replace(/.$/, "0"));
    assert.notEqual(after, before, "тест обязан реально изменить манифест");

    /* Правим БАЙТЫ, а не только строку. Настоящая подделка выглядит именно
       так, и теперь подпись проверяется по байтам: тест, менявший одну лишь
       строку, перестал что-либо проверять и честно упал. */
    const r = await verifyPackage({
      ...entries,
      manifestJson: after,
      manifestJsonBytes: new TextEncoder().encode(after),
    });
    assert.equal(r.allPass, false, "правка манифеста обязана ломать подпись");
  });

  test("метка BOM перед манифестом — отказ, как и в браузере", async () => {
    /* Регрессия от собственной правки, пойманная тестом. TextDecoder по
       умолчанию МОЛЧА срезает метку порядка байт, а прежний Buffer.toString
       и JSZip в браузере её оставляют. Из-за этого сервер начал отвечать
       ПОДЛИННО на файл, который сайт отвергает как невалидный JSON, — то
       есть починка одного расхождения открыла другое, в ту же сторону.

       Приложение метку не пишет: JSONObject.toString() её не создаёт. */
    const entries = await extract(readFileSync(REAL_PHOTO));
    const bom = new Uint8Array([0xef, 0xbb, 0xbf]);
    const orig = entries.manifestJsonBytes!;
    const withBom = new Uint8Array(bom.length + orig.length);
    withBom.set(bom, 0);
    withBom.set(orig, bom.length);

    await assert.rejects(
      () => verifyPackage({ ...entries, manifestJson: undefined, manifestJsonBytes: withBom }),
      (e: Error) => /не валидный JSON/.test(e.message),
    );
  });

  test("строка и байты разошлись — верят байтам, а не строке", async () => {
    /* Ловушка, ради которой всё и переделывалось: если показ берётся из
       строки, а подпись из байтов, то в отчёт попадут поля, которых подпись
       не покрывала. Подсовываем расходящуюся пару и требуем, чтобы
       верификатор целиком опирался на байты. */
    const entries = await extract(readFileSync(REAL_PHOTO));
    const before = entries.manifestJson!;
    const m = JSON.parse(before) as Record<string, unknown>;
    const lie = before.replace(String(m.capturedAt), String(m.capturedAt).replace(/.$/, "0"));
    assert.notEqual(lie, before, "тест обязан реально подменить строку");

    const r = await verifyPackage({ ...entries, manifestJson: lie });
    assert.equal(r.allPass, true, "подложенная строка не должна ломать настоящий файл");
    assert.equal(
      (r.meta as Record<string, unknown>).capturedAt,
      m.capturedAt,
      "в отчёте обязано быть значение из подписанных байт, а не из подложенной строки",
    );
  });
});


/* ═══════════════════════════════════════════════════════════════════════ */
describe("Настоящая видеосъёмка", { skip: haveVideo ? false : "нет samples/genuine.trustvisor" }, () => {
  test("проходит как ПОДЛИННАЯ", async () => {
    const r = await verifyPackage(await extract(readFileSync(REAL_VIDEO)));
    assert.equal(r.allPass, true, "настоящая видеосъёмка обязана пройти все проверки");
    assert.equal(r.trustDowngrade, false, "и не должна понижаться в доверии");
  });

  test("изменённый байт видео ломает вердикт", async () => {
    const entries = await extract(readFileSync(REAL_VIDEO));
    const v = Buffer.from(entries.videoBuffer as ArrayBuffer);
    v[Math.floor(v.length / 2)] ^= 0xff;
    const r = await verifyPackage({ ...entries, videoBuffer: v.buffer.slice(
      v.byteOffset, v.byteOffset + v.byteLength) as ArrayBuffer });
    assert.equal(r.allPass, false, "подмена байта обязана ломать проверку");
  });

  test("время съёмки впереди часов проверяющего вердикт НЕ решает", async () => {
    /* Часы того, кто открыл файл, доказательством не являются: севшая
       батарейка на плате иначе объявляла бы подлинную съёмку подделкой.
       Подмену времени ловят сверка с сервером и разовый вызов — оба записаны
       в сам файл. Здесь отматываем часы на год назад и требуем, чтобы вердикт
       не изменился. */
    const entries = await extract(readFileSync(REAL_VIDEO));
    const real = Date.now;
    const shift = 365 * 24 * 60 * 60 * 1000;
    let r;
    try {
      Date.now = () => real.call(Date) - shift;
      r = await verifyPackage(entries);
    } finally {
      Date.now = real;
    }
    assert.equal(r.allPass, true, "отставшие часы читателя не должны давать ИЗМЕНЁН");
    assert.equal(r.trustDowngrade, false, "и не должны понижать доверие");
  });

  test("дописанное поле с именем служебного члена объекта ломает подпись", async () => {
    /* До 4 сентября 2026 список неподписываемых полей был обычным объектом, и
       поиск ключа находил метод прототипа: поле с именем constructor молча
       выпадало из подписываемых байтов, а файл признавался подлинным. */
    const entries = await extract(readFileSync(REAL_VIDEO));
    const before = entries.manifestStartJson!;
    const i = before.indexOf("{") + 1;
    const after = before.slice(0, i) + '"constructor":"дописано после подписания",' + before.slice(i);
    assert.notEqual(after, before, "тест обязан реально изменить манифест");
    JSON.parse(after);
    const r = await verifyPackage({
      ...entries,
      manifestStartJson: after,
      manifestStartJsonBytes: new TextEncoder().encode(after),
    });
    assert.equal(r.allPass, false, "дописанное поле обязано ломать подпись");
  });
});

/* ═══════════════════════════════════════════════════════════════════════ */
describe("Производные образцы", () => {
  test("изменённый байт — ИЗМЕНЁН", { skip: existsSync(TAMPERED) ? false : "нет samples/tampered.trustvisor" },
    async () => {
      const r = await verifyPackage(await extract(readFileSync(TAMPERED)));
      assert.equal(r.allPass, false);
    });

  test("без цепочки аттестации — НЕ АТТЕСТОВАНО", { skip: existsSync(UNATTESTED) ? false : "нет samples/unattested.trustvisor" },
    async () => {
      /* Цепочка не входит в подписанные байты, поэтому подпись обязана
         сойтись, а доверие — понизиться. Это ровно то, что случилось бы с
         настоящей съёмкой на устройстве без пригодной аттестации. */
      const r = await verifyPackage(await extract(readFileSync(UNATTESTED)));
      assert.equal(r.allPass, true, "подпись обязана сойтись: цепочка не подписана");
      assert.equal(r.trustDowngrade, true, "но доверие обязано понизиться");
    });
});

describe("Подтверждение момента: срок и привязка к серверному времени", { skip: haveReal ? false : "нет samples/genuine-photo.trustvisor" }, () => {
  const H = 60 * 60 * 1000;
  async function realManifest(): Promise<Record<string, unknown>> {
    const entries = await extract(readFileSync(REAL_PHOTO));
    return JSON.parse((entries as unknown as { manifestJson: string }).manifestJson) as Record<string, unknown>;
  }
  function fresh(m: Record<string, unknown>, ref: number) {
    return checkAttestationChallengeFreshness(true, m.attestationChain as string[], m, ref);
  }
  /* Привязка: последняя связь в момент выдачи токена, дальше без сети. */
  function anchorAt(exp: number, ttl: number, offlineMs: number) {
    return checkServerAnchor({ anchorServerMs: exp - ttl, anchorElapsedMs: offlineMs, anchorState: "ok" }, { state: "pass", notBeforeMs: exp - ttl, notAfterMs: exp });
  }

  test("свежий токен: pass и обе границы момента", async () => {
    const m = await realManifest();
    const exp = m.attestationChallengeExpiresAt as number;
    const r = await fresh(m, exp - 1000);
    assert.equal(r.state, "pass");
    assert.equal(r.notAfterMs, exp, "«не позже» — это срок токена");
    const ttl = exp - CHALLENGE_TTL_MS >= CHALLENGE_TTL_SWITCH_MS ? CHALLENGE_TTL_MS : CHALLENGE_TTL_LEGACY_MS;
    assert.equal(r.notBeforeMs, exp - ttl, "«не раньше» — срок минус длина токена (по дате перехода)");
  });

  test("датирован раньше выдачи подтверждения → warn; привязка снимает; перезагрузка — нет", async () => {
    /* Симметрия к «позже exp»: раньше выдачи токена съёмки быть не могло,
       токен вшит в её же сертификат. Без привязки — понижение по времени. */
    const m = await realManifest();
    const exp = m.attestationChallengeExpiresAt as number;
    const ttl = exp - Number((await fresh(m, exp - 1000)).notBeforeMs);
    const early = await fresh(m, exp - ttl - 2 * H);
    assert.equal(early.state, "warn");
    assert.ok(/раньше выдачи/.test(String(early.msg)));
    assert.deepEqual(downgradeReasonsOf({ challengeFreshness: early }), ["challengeFreshness"]);
    const witnessed = withAnchorWitness(early, anchorAt(exp, ttl, 30 * 60 * 1000));
    assert.equal(witnessed.state, "pass", "по серверу съёмка была внутри срока");
    const reboot = checkServerAnchor({ anchorServerMs: exp - ttl, anchorState: "reboot" }, null);
    assert.equal(withAnchorWitness(early, reboot).state, "warn", "без привязки понижение остаётся");
    const slack = await fresh(m, exp - ttl - 30 * 1000);
    assert.equal(slack.state, "pass", "полминуты — допуск на часы при выдаче");
  });

  test("просрочен на 3 ч, привязка цела → не понижается", async () => {
    const m = await realManifest();
    const exp = m.attestationChallengeExpiresAt as number;
    const ttl = exp - Number((await fresh(m, exp - 1000)).notBeforeMs);
    const r = withAnchorWitness(await fresh(m, exp + 3 * H), anchorAt(exp, ttl, ttl + 3 * H));
    assert.equal(r.state, "pass");
    assert.equal(r.anchorWitness, true);
  });

  test("просрочен на 3 ч, привязка потеряна перезагрузкой → понижается", async () => {
    const m = await realManifest();
    const exp = m.attestationChallengeExpiresAt as number;
    const a = checkServerAnchor({ anchorServerMs: exp - H, anchorState: "reboot" }, null);
    assert.equal(a.state, "warn");
    const r = withAnchorWitness(await fresh(m, exp + 3 * H), a);
    assert.equal(r.state, "warn");
  });

  test("просрочен на 5 суток, привязка цела → не понижается (потолка нет)", async () => {
    const m = await realManifest();
    const exp = m.attestationChallengeExpiresAt as number;
    const ttl = exp - Number((await fresh(m, exp - 1000)).notBeforeMs);
    const r = withAnchorWitness(await fresh(m, exp + 120 * H), anchorAt(exp, ttl, ttl + 120 * H));
    assert.equal(r.state, "pass");
  });

  /* Сквозная проверка на настоящем файле. Съёмка может быть сделана и
     приложением с привязкой к серверному времени, и без неё — ранние версии
     её не писали. Поэтому проверяется не одна из веток, а их связность: есть
     привязка — момент берут из неё и часы телефона есть с чем сверить; нет —
     момент берут из границ токена, и сверять часы не с чем. Вердикт честной
     съёмки в обоих случаях один и тот же. */
  test("настоящий файл целиком: момент и сверки согласованы, вердикт не меняется", async () => {
    const entries = await extract(readFileSync(REAL_PHOTO));
    const r = await verifyPackage(entries);
    const state = (name: string) => (r.checks as Record<string, { state: string }>)[name].state;
    const cf = r.checks.challengeFreshness as { state: string; notBeforeMs?: number; notAfterMs?: number };
    assert.equal(cf.state, "pass");
    assert.ok(typeof cf.notBeforeMs === "number" && typeof cf.notAfterMs === "number", "границы момента заполнены");
    if (state("anchor") === "skip") {
      assert.equal(r.momentSource, "token");
      assert.equal(state("deviceClock"), "skip");
    } else {
      assert.equal(state("anchor"), "pass");
      assert.equal(r.momentSource, "anchor");
      assert.equal(state("deviceClock"), "pass");
    }
    assert.equal(r.allPass, true);
    assert.equal(r.trustDowngrade, false);
  });
});

/* ═══════════════════════════════════════════════════════════════════════
   Привязка к серверному времени, часы телефона, спутник против сервера,
   подмена места (5 сентября 2026, вечер). Чистые функции, образец не нужен.
   ═══════════════════════════════════════════════════════════════════════ */
describe("Привязка к серверному времени и её сверки", () => {
  const H = 60 * 60 * 1000;
  const T0 = 1_788_600_000_000; /* серверное время при последней связи */
  const okAnchor = { anchorServerMs: T0, anchorElapsedMs: 30 * H, anchorState: "ok" };

  test("привязка цела: момент = серверное время + счётчик", () => {
    const a = checkServerAnchor(okAnchor, { state: "pass", notBeforeMs: T0 - 5 * 60 * 1000, notAfterMs: T0 + 12 * H });
    assert.equal(a.state, "pass");
    assert.equal(a.momentMs, T0 + 30 * H);
    assert.equal(a.offlineMs, 30 * H);
  });
  test("привязки нет / перезагрузка / неправдоподобная", () => {
    assert.equal(checkServerAnchor({}, null).state, "skip");
    const reboot = checkServerAnchor({ anchorServerMs: T0, anchorState: "reboot" }, null);
    assert.equal(reboot.state, "warn");
    assert.ok(!reboot.inconsistent, "потеря привязки — не признак вмешательства");
    const neg = checkServerAnchor({ anchorServerMs: T0, anchorElapsedMs: -5, anchorState: "ok" }, null);
    assert.equal(neg.state, "warn"); assert.equal(neg.inconsistent, true);
    const old = checkServerAnchor(okAnchor, { state: "pass", notBeforeMs: T0 + 10 * 60 * 1000, notAfterMs: T0 + 12 * H });
    assert.equal(old.state, "warn"); assert.equal(old.inconsistent, true, "связь не может быть старше токена, полученного при ней");
  });
  test("часы телефона: перевод на 3 ч — «Момент не подтверждён», на 10 мин — только отчёт", () => {
    /* 9 сентября 2026: до этого перевод часов был только строкой в отчёте, и
       файл с датой из будущего получал ПОДЛИННО — при том что в заголовке
       печаталась именно эта дата. Порог 30 минут: честный дрейф — секунды,
       рука на часах — минуты, подлог ради спора — часы. */
    const a = checkServerAnchor(okAnchor, null);
    const shifted = checkDeviceClock(T0 + 27 * H, a, { autoTimeEnabled: false });
    assert.equal(shifted.state, "warn");
    assert.equal(shifted.shiftMs, -3 * H);
    assert.equal(shifted.downgrade, true);
    assert.ok(/выключена/.test(String(shifted.msg)));
    const reasons = downgradeReasonsOf({ anchor: a, deviceClock: shifted });
    assert.deepEqual(reasons, ["deviceClock"]);
    assert.equal(isTimeOnlyDowngrade({ downgradeReasons: reasons }), true, "это про время, не про устройство");
    const small = checkDeviceClock(T0 + 30 * H + 10 * 60 * 1000, a, {});
    assert.equal(small.state, "warn");
    assert.ok(!small.downgrade, "десять минут — не подлог");
    assert.deepEqual(downgradeReasonsOf({ anchor: a, deviceClock: small }), []);
    const future = checkDeviceClock(T0 + 30 * H + 48 * H, a, {});
    assert.equal(future.downgrade, true, "дата из будущего на двое суток");
    const fine = checkDeviceClock(T0 + 30 * H + 20_000, a, {});
    assert.equal(fine.state, "pass");
  });
  test("спутниковое время против сервера: расхождение — подмена сигнала, причина «location»", () => {
    const moment = T0 + 30 * H;
    const spoof = checkGpsTime(moment - 2 * H, moment - 2 * H, moment, "gps");
    assert.equal(spoof.state, "fail"); assert.equal(spoof.vsAnchor, true);
    const reasons = downgradeReasonsOf({ gpstime: spoof });
    assert.deepEqual(reasons, ["location"]);
    assert.equal(isTimeOnlyDowngrade({ downgradeReasons: reasons }), false, "место — не время");
    const real = checkGpsTime(moment + 3000, moment + 200_000, moment, "gps");
    assert.equal(real.state, "pass");
    const fused = checkGpsTime(moment - 2 * H, moment - 2 * H, moment, "fused");
    assert.equal(fused.state, "pass", "сетевой фикс сверяется с часами телефона, как раньше");
    assert.ok(!fused.vsAnchor);
  });
  test("подмена места: флаг в отчёт, вердикт не трогает", () => {
    const seen = checkLocationMock({ manifestVersion: "1.2", locationMockSeen: true });
    assert.equal(seen.state, "warn");
    assert.deepEqual(downgradeReasonsOf({ locationMock: seen }), []);
    assert.equal(checkLocationMock({ manifestVersion: "1.2" }).state, "pass");
    assert.equal(checkLocationMock({ manifestVersion: "1.1" }).state, "skip");
  });
  test("неправдоподобная привязка понижает доверие не по времени", () => {
    const bad = checkServerAnchor({ anchorServerMs: T0, anchorElapsedMs: 500 * 24 * H, anchorState: "ok" }, null);
    const reasons = downgradeReasonsOf({ anchor: bad });
    assert.deepEqual(reasons, ["anchor"]);
    assert.equal(isTimeOnlyDowngrade({ downgradeReasons: reasons }), false);
  });
  test("истёкший токен при часах, переведённых вперёд: по серверу он был свеж", () => {
    const f = { state: "warn" as const, notBeforeMs: T0 - 12 * H, notAfterMs: T0 + 1 * H };
    const a = checkServerAnchor({ anchorServerMs: T0, anchorElapsedMs: 30 * 60 * 1000, anchorState: "ok" }, f);
    const r = withAnchorWitness(f, a);
    assert.equal(r.state, "pass");
    assert.ok(/спешили/.test(String(r.msg)));
  });
});

/* ═══════════════════════════════════════════════════════════════════════
   Срок из префикса токена и причины понижения доверия (5 сентября 2026).
   ═══════════════════════════════════════════════════════════════════════ */
describe("Длина срока из токена и причины понижения", () => {
  const H = 60 * 60 * 1000;
  test("префикс h<часы>. задаёт длину срока", () => {
    assert.equal(challengeTtlMs("h12.abcDEF", 0), 12 * H);
    assert.equal(challengeTtlMs("h24.xyz", 0), 24 * H);
    assert.equal(challengeTtlMs("h1.q", 0), 1 * H);
  });
  test("токен без префикса — по дате перехода", () => {
    const sw = CHALLENGE_TTL_SWITCH_MS;
    assert.equal(challengeTtlMs("plainToken", sw + 13 * H), CHALLENGE_TTL_MS, "выдан после перехода — 12 ч");
    assert.equal(challengeTtlMs("plainToken", sw + 1 * H), CHALLENGE_TTL_LEGACY_MS, "выдан до перехода — час");
  });
  test("понижение только по времени отличается от понижения по устройству", () => {
    const base = { attestation: true, oid: { state: "pass" }, rootOfTrust: { state: "pass" }, keybound: { state: "pass" },
      challengeFreshness: { state: "warn" }, serverClock: { state: "pass" }, gpstime: { state: "skip" } };
    assert.deepEqual(downgradeReasonsOf(base), ["challengeFreshness"]);
    assert.equal(isTimeOnlyDowngrade({ downgradeReasons: downgradeReasonsOf(base) }), true);
    const dev = { ...base, rootOfTrust: { state: "warn" } };
    assert.deepEqual(downgradeReasonsOf(dev), ["rootOfTrust", "challengeFreshness"]);
    assert.equal(isTimeOnlyDowngrade({ downgradeReasons: downgradeReasonsOf(dev) }), false);
    assert.equal(isTimeOnlyDowngrade({ downgradeReasons: [] }), false, "без понижения — не «только время»");
  });
  test("настоящая съёмка: причин понижения нет", { skip: haveReal ? false : "нет samples/genuine-photo.trustvisor" }, async () => {
    const entries = await extract(readFileSync(REAL_PHOTO));
    const r = await verifyPackage(entries);
    assert.deepEqual(r.downgradeReasons, []);
    assert.equal(r.trustDowngrade, false);
  });
});

/* ═══════════════════════════════════════════════════════════════════════
   Второе мнение о месте: сетевой фикс против спутникового (6 сентября 2026).
   ═══════════════════════════════════════════════════════════════════════ */
describe("Второе мнение о месте", () => {
  const base = { latitude: 55.751244, longitude: 37.618423, locationAccuracy: 12, locationProvider: "gps" };
  test("сеть и спутник совпадают → pass с расстоянием", () => {
    const r = checkLocationSecondOpinion({ ...base, netLatitude: 55.7530, netLongitude: 37.6210, netAccuracy: 800 });
    assert.equal(r.state, "pass");
    assert.ok(typeof r.distM === "number" && r.distM < 1000);
    assert.deepEqual(downgradeReasonsOf({ locationNet: r }), []);
  });
  test("сеть в 30 км от спутника → warn, причина «location», не «только время»", () => {
    const r = checkLocationSecondOpinion({ ...base, netLatitude: 56.02, netLongitude: 37.62, netAccuracy: 1500 });
    assert.equal(r.state, "warn");
    assert.ok(typeof r.distM === "number" && r.distM > 25000);
    const reasons = downgradeReasonsOf({ locationNet: r });
    assert.deepEqual(reasons, ["location"]);
    assert.equal(isTimeOnlyDowngrade({ downgradeReasons: reasons }), false);
  });
  test("без сетевого фикса или без спутникового — skip, вердикт не трогает", () => {
    assert.equal(checkLocationSecondOpinion(base).state, "skip", "старое приложение или нет покрытия");
    const fused = checkLocationSecondOpinion({ ...base, locationProvider: "fused", netLatitude: 56.02, netLongitude: 37.62 });
    assert.equal(fused.state, "skip", "fused-фикс сам сетевой — сравнивать не с чем");
    assert.deepEqual(downgradeReasonsOf({ locationNet: fused }), []);
  });
});

/* ═══════════════════════════════════════════════════════════════════════
   Портрет спутникового сигнала (6 сентября 2026).
   ═══════════════════════════════════════════════════════════════════════ */
describe("Портрет спутникового сигнала", () => {
  test("честное небо: несколько созвездий, разброс сигнала → pass с портретом", () => {
    const r = checkGnssPortrait({ locationProvider: "gps", gnssUsed: 11, gnssVisible: 19, gnssConst: "G,R,E,C", gnssCn0Mean: "33.4", gnssCn0Std: "5.2", gnssBands: "L1+L5", gnssAgcDb: "38.5" });
    assert.equal(r.state, "pass");
    assert.ok(/GPS, ГЛОНАСС, Galileo, BeiDou/.test(String(r.msg)) && /L1\+L5/.test(String(r.msg)));
    assert.deepEqual(r.flags, []);
  });
  test("передатчик: одно созвездие, ровный и сильный сигнал → warn, причина «location»", () => {
    const r = checkGnssPortrait({ locationProvider: "gps", gnssUsed: 8, gnssVisible: 8, gnssConst: "G", gnssCn0Mean: "47.0", gnssCn0Std: "0.4", gnssBands: "L1" });
    assert.equal(r.state, "warn");
    assert.ok((r.flags as string[]).length >= 2);
    const reasons = downgradeReasonsOf({ gnssPortrait: r });
    assert.deepEqual(reasons, ["location"]);
    assert.equal(isTimeOnlyDowngrade({ downgradeReasons: reasons }), false);
    const one = checkGnssPortrait({ locationProvider: "gps", gnssUsed: 7, gnssConst: "G", gnssCn0Mean: "30.0", gnssCn0Std: "6.0" });
    assert.equal(one.state, "pass", "один признак сам по себе не показатель");
    assert.deepEqual(downgradeReasonsOf({ gnssPortrait: one }), []);
  });
  test("без портрета или без спутникового фикса → skip", () => {
    assert.equal(checkGnssPortrait({ locationProvider: "gps" }).state, "skip");
    assert.equal(checkGnssPortrait({ locationProvider: "fused", gnssUsed: 8, gnssConst: "G", gnssCn0Std: "0.4", gnssCn0Mean: "47.0" }).state, "skip");
  });
});

/* ═══════════════════════════════════════════════════════════════════════
   Хвост после манифеста в подписанном медиа.

   Во всех трёх контейнерах длина блока подписи сверялась как «не меньше
   нужного», а не «ровно». Разница в том, что байты сверх нужного никуда не
   попадали: из медиа блок вырезается целиком, в манифест лишнее не входит,
   показать их некому. То есть в файле с вердиктом ПОДЛИННО можно было
   провезти произвольное содержимое. Подделать съёмку так нельзя — подпись и
   хэш держат, — но карман это карман.

   Воспроизведено на настоящей съёмке: 1120 дописанных байт, вердикт остался
   ПОДЛИННО. У честного файла хвоста нет — блок кончается ровно на конце
   файла, поэтому строгая сверка не задевает ни одну настоящую съёмку.
   ═══════════════════════════════════════════════════════════════════════ */
describe("Хвост после манифеста в подписанном медиа", () => {
  const MAGIC = Buffer.from("TVSR-TrustVisor1", "ascii");
  const M = Buffer.from('{"a":1}', "utf-8");
  const be32 = (n: number) => {
    const b = Buffer.alloc(4);
    b.writeUInt32BE(n);
    return b;
  };
  const JUNK = Buffer.alloc(64, 0x5a);

  function signedJpeg(tail: Buffer): Buffer {
    const image = Buffer.from([
      0xff, 0xd8, 0xff, 0xe0, 0x00, 0x10, 0x4a, 0x46, 0x49, 0x46, 0x00,
      0x01, 0x01, 0x00, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0xff, 0xd9,
    ]);
    return Buffer.concat([image, MAGIC, Buffer.from([1, 2]), be32(M.length), M, tail]);
  }

  function signedPng(pad: number): Buffer {
    const payload = Buffer.concat([Buffer.from([1, 2]), be32(M.length), M,
                                   Buffer.alloc(pad, 0x5a)]);
    const chunk = Buffer.concat([be32(payload.length), Buffer.from("tvSg", "ascii"),
                                 payload, be32(0)]);
    const iend = Buffer.concat([be32(0), Buffer.from("IEND", "ascii"), be32(0)]);
    return Buffer.concat([Buffer.from([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a]),
                          chunk, iend]);
  }

  function signedMp4(pad: number): Buffer {
    const ftyp = Buffer.concat([be32(16), Buffer.from("ftypisom", "ascii"), be32(0)]);
    const payload = Buffer.concat([MAGIC, Buffer.from([1, 1]), be32(M.length), M,
                                   be32(M.length), M, Buffer.alloc(pad, 0x5a)]);
    const box = Buffer.concat([be32(payload.length + 8), Buffer.from("uuid", "ascii"), payload]);
    return Buffer.concat([ftyp, box]);
  }

  test("JPEG: блок кончается ровно на конце файла — иначе отказ", async () => {
    await extract(signedJpeg(Buffer.alloc(0)), "ok.jpg");
    await assert.rejects(() => extract(signedJpeg(JUNK), "pad.jpg"),
      (e: Error) => /лишние байты/.test(e.message));
  });

  /* ИСТОРИЯ ЭТОГО ТЕСТА, и она полезнее самого теста.

     12 сентября 2026 подписанный PNG убрали из формата, а этот тест
     перевернули: стал требовать отказа. Основанием был комментарий в
     приложении «камера снимает JPEG», без замера.

     13 сентября живая съёмка владельца показала обратное: на бесплатном
     тарифе водяной знак пересохраняет кадр в PNG, то есть КАЖДОЕ бесплатное
     фото — настоящий PNG. Перевёрнутый тест при этом был зелёным: он
     добросовестно подтверждал неверное поведение.

     Вывод, который стоит помнить: зелёный тест доказывает только то, что
     код делает написанное в тесте. Если написанное неверно, тест становится
     не заслоном, а печатью на ошибке. */
  test("PNG: чанк не длиннее, чем нужно манифесту", async () => {
    await extract(signedPng(0), "ok.png");
    await assert.rejects(() => extract(signedPng(64), "pad.png"),
      (e: Error) => /лишние байты/.test(e.message));
  });

  test("MP4: бокс не длиннее, чем нужно двум манифестам", async () => {
    await extract(signedMp4(0), "ok.mp4");
    await assert.rejects(() => extract(signedMp4(64), "pad.mp4"),
      (e: Error) => /лишние байты/.test(e.message));
  });

  test("настоящая съёмка с дописанным хвостом отвергается", { skip: haveReal ? false : "нет samples/genuine-photo.trustvisor" }, async () => {
    /* Тот самый файл, на котором дыра и была найдена: подписанный JPEG из
       архива-образца, к которому приклеили посторонние байты. */
    const zip = readFileSync(REAL_PHOTO);
    const entries = await extract(zip);
    const photo = Buffer.from(entries.photoBuffer as ArrayBuffer);
    const manifest = Buffer.from(entries.manifestJsonBytes as Uint8Array);
    const media = Buffer.concat([photo, MAGIC, Buffer.from([1, 2]),
                                 be32(manifest.length), manifest]);
    const r = await verifyPackage(await extract(media, "real.jpg"));
    assert.equal(r.allPass, true, "без хвоста настоящая съёмка проходит");
    await assert.rejects(() => extract(Buffer.concat([media, JUNK]), "real-pad.jpg"),
      (e: Error) => /лишние байты/.test(e.message));
  });
});

/* ── Формат 2.0: запись подписи ───────────────────────────────────────────
   Проверяем ровно то, ради чего конверт сменили с плоского JSON на
   компактную форму. Первая редакция проекта закрывала запись шестью
   запретами, и шесть обходов из шести её прошли: экранирование имени члена,
   пробел внутри строкового литерала, дубликат ключа, метка BOM, набивка `=`,
   чужой алфавит. В компактной форме четыре из них просто нечем выразить —
   в записи нет JSON, — а оставшиеся закрыты побайтным правилом.

   Тесты написаны так, чтобы ловить возврат каждого из них. */
describe("Формат 2.0: запись подписи", () => {
  const { privateKey, publicKey } = generateKeyPairSync("ec", { namedCurve: "prime256v1" });
  const spkiB64 = publicKey.export({ type: "spki", format: "der" }).toString("base64");
  const b64u = (b: Buffer | Uint8Array) => Buffer.from(b).toString("base64url");

  const HEADER = {
    alg: "ES256", b64: false, crit: ["b64"],
    typ: "application/trustvisor-manifest+json",
    x5c: ["MIIBAgMBAAE="],
  };
  const MANIFEST = Buffer.from('{\n  "manifestVersion": "2.0"\n}', "utf8");

  function makeJws(header: object = HEADER, manifest: Buffer = MANIFEST): string {
    const prot = b64u(Buffer.from(JSON.stringify(header), "utf8"));
    const input = Buffer.concat([Buffer.from(prot, "ascii"), Buffer.from("."), manifest]);
    const sig = sign("sha256", input, { key: privateKey, dsaEncoding: "ieee-p1363" });
    return prot + ".." + b64u(sig);
  }

  const bytes = (s: string) => new Uint8Array(Buffer.from(s, "utf8"));

  test("честная запись разбирается и подпись сходится", async () => {
    const rec = parseDetachedJws(bytes(makeJws()));
    assert.equal(rec.signature.length, 64);
    assert.deepEqual(rec.x5c, HEADER.x5c);
    const key = await crypto.subtle.importKey(
      "spki", Buffer.from(spkiB64, "base64"),
      { name: "ECDSA", namedCurve: "P-256" }, false, ["verify"]);
    assert.equal(await verifyDetachedJws(rec, MANIFEST, key), true);
  });

  test("подпись не сходится на другом манифесте", async () => {
    const rec = parseDetachedJws(bytes(makeJws()));
    const key = await crypto.subtle.importKey(
      "spki", Buffer.from(spkiB64, "base64"),
      { name: "ECDSA", namedCurve: "P-256" }, false, ["verify"]);
    const other = Buffer.from('{\n  "manifestVersion": "2.0" \n}', "utf8"); // один пробел
    assert.equal(await verifyDetachedJws(rec, other, key), false);
  });

  test("шесть обходов из первой редакции отбиты", () => {
    const good = makeJws();
    const at = good.indexOf("..");
    const prot = good.slice(0, at), sig = good.slice(at + 2);
    const cases: [string, string | Uint8Array][] = [
      /* Слэш собирается кодом, а не литералом, и это не педантизм. При первой
         попытке записать его литералом он схлопнулся в обычную букву e —
         и тест молча проверял ИСХОДНУЮ верную строку вместо испорченной.
         Заметил только потому, что тест не упал там, где обязан был. */
      ["экранирование: обратный слэш в заголовке",
        String.fromCharCode(92) + "u0065" + prot.slice(1) + ".." + sig],
      ["пробел внутри подписи", prot + ".." + sig.slice(0, 10) + " " + sig.slice(10)],
      ["перевод строки внутри подписи", prot + ".." + sig.slice(0, 10) + "\n" + sig.slice(10)],
      ["метка BOM в начале", bytes("\uFEFF" + good)],
      ["набивка = у подписи", prot + ".." + sig + "="],
      /* Раньше здесь стояла замена - на + и _ на /. Она ничего не делала,
         если в коротком заголовке этих символов не оказалось, и случай молча
         проходил. Подставляем символ чужого алфавита прямо. */
      ["чужой алфавит: +", "+" + prot.slice(1) + ".." + sig],
      ["чужой алфавит: /", "/" + prot.slice(1) + ".." + sig],
      ["лишний член заголовка", makeJws({ ...HEADER, tvExtra: 1 })],
      ["подпись на символ короче", prot + ".." + sig.slice(0, 85)],
      ["подпись на символ длиннее", prot + ".." + sig + "A"],
      ["одна точка вместо двух", prot + "." + sig],
      ["три точки", prot + "..." + sig],
      ["alg не ES256", makeJws({ ...HEADER, alg: "ES384" })],
      ["alg none", makeJws({ ...HEADER, alg: "none" })],
      ["b64 true", makeJws({ ...HEADER, b64: true })],
      ["crit пуст", makeJws({ ...HEADER, crit: [] })],
      ["x5c пуст", makeJws({ ...HEADER, x5c: [] })],
      ["чужой typ", makeJws({ ...HEADER, typ: "application/jose" })],
    ];
    for (const [label, rec] of cases) {
      assert.throws(() => parseDetachedJws(typeof rec === "string" ? bytes(rec) : rec),
        Error, "должно было отвергнуться: " + label);
    }
  });

  test("неканонический последний символ подписи отвергается", () => {
    const good = makeJws();
    const at = good.indexOf("..");
    const prot = good.slice(0, at), sig = good.slice(at + 2);
    /* Последний символ несёт всего два значащих бита: 16 разных символов
       дают одну и ту же подпись. Канонический — с нулевыми младшими битами.
       Берём соседний по той же группе: подпись не изменится, а запись — да. */
    const ALPH = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    const idx = ALPH.indexOf(sig[85]);
    const twin = ALPH[idx + 1];
    assert.equal(Buffer.from(sig.slice(0, 85) + twin, "base64url").toString("hex"),
      Buffer.from(sig, "base64url").toString("hex"), "проверка теста: подпись та же");
    assert.throws(() => parseDetachedJws(bytes(prot + ".." + sig.slice(0, 85) + twin)),
      /неканонически/);
  });

  test("поля формата 1.x в манифесте 2.0 запрещены", () => {
    assertNoV1Fields({ manifestVersion: "2.0" });
    for (const f of ["signature", "signatureAlgorithm", "attestationChain"]) {
      assert.throws(() => assertNoV1Fields({ manifestVersion: "2.0", [f]: "x" }),
        new RegExp(f));
    }
  });
});

/* ── Журнал датчиков ─────────────────────────────────────────────────────── */

/** Собирает журнал по раскладке раздела 1.7. Умеет портиться по требованию,
 *  чтобы каждый красный случай отличался от зелёного ровно одним местом. */
function makeSensors(opts: {
  streams?: Array<{ kind: number; axes?: number; hz?: number; count?: number; rawCount?: number; byteLen?: number }>;
  magic?: string;
  streamsByte?: number;
  reserved?: number[];
  tail?: number;
  cutPayload?: number;
} = {}): Uint8Array {
  const streams = opts.streams ?? [
    { kind: 1, count: 3 },
    { kind: 4, count: 2 },
  ];
  const heads = streams.map((s) => {
    const axes = s.axes ?? (s.kind === 4 ? 1 : 3);
    const count = s.count ?? 1;
    return {
      kind: s.kind,
      axes,
      hz: s.hz ?? 10,
      count,
      rawCount: s.rawCount ?? count,
      byteLen: s.byteLen ?? count * axes * 2,
    };
  });
  const payload = heads.reduce((n, h) => n + h.count * h.axes * 2, 0);
  const total = 12 + heads.length * 16 + payload + (opts.tail ?? 0) - (opts.cutPayload ?? 0);
  const out = new Uint8Array(total);
  const view = new DataView(out.buffer);
  const magic = opts.magic ?? "TVSENS01";
  for (let i = 0; i < 8 && i < magic.length; i++) out[i] = magic.charCodeAt(i);
  out[8] = opts.streamsByte ?? heads.length;
  const res = opts.reserved ?? [0, 0, 0];
  out[9] = res[0]; out[10] = res[1]; out[11] = res[2];
  heads.forEach((h, i) => {
    const o = 12 + i * 16;
    view.setUint8(o, h.kind);
    view.setUint8(o + 1, h.axes);
    view.setUint16(o + 2, h.hz);
    view.setUint32(o + 4, h.count);
    view.setUint32(o + 8, h.rawCount);
    view.setUint32(o + 12, h.byteLen);
  });
  // Значения: что-нибудь непостоянное, чтобы нулевой журнал не проходил случайно.
  let p = 12 + heads.length * 16;
  for (const h of heads) {
    for (let i = 0; i < h.count * h.axes; i++) {
      if (p + 2 <= out.byteLength) view.setInt16(p, (i + 1) * 100 - 300);
      p += 2;
    }
  }
  return out;
}

const sha256hex = (b: Uint8Array) => createHash("sha256").update(b).digest("hex");

/* Вставляет лишний пробел сразу после открывающей скобки манифеста. JSON
   остаётся действительным, значения не меняются — меняются только байты.
   Ровно так выглядит безобидная пересборка чужим инструментом. */
function spaceAfterBrace(bytes: Uint8Array): Uint8Array {
  const i = bytes.indexOf(0x7b); // "{"
  assert.ok(i >= 0, "в манифесте обязана быть открывающая скобка");
  const out = new Uint8Array(bytes.length + 1);
  out.set(bytes.subarray(0, i + 1), 0);
  out[i + 1] = 0x20;
  out.set(bytes.subarray(i + 1), i + 2);
  return out;
}

describe("Настоящая съёмка формата 2.0", { skip: have20Photo ? false : "нет samples/genuine-2.0-photo.trustvisor" }, () => {
  test("фотография проходит как ПОДЛИННАЯ", async () => {
    const entries = await extract(readFileSync(REAL_2_0_PHOTO));
    assert.ok(entries.manifestJwsBytes, "у файла 2.0 обязана быть запись подписи");
    const r = await verifyPackage(entries);
    assert.equal(r.allPass, true, "настоящая съёмка 2.0 обязана пройти все проверки");
    assert.equal(r.trustDowngrade, false, "и не должна понижаться в доверии");
  });

  test("в настоящем манифесте 2.0 нет полей формата 1.x", async () => {
    /* Проверено на живом файле, а не на собранном тут же: правило «в 2.0 не
       осталось signature» стоит того, чтобы хоть раз спросить его у того, что
       телефон пишет на самом деле. */
    const entries = await extract(readFileSync(REAL_2_0_PHOTO));
    const m = JSON.parse(entries.manifestJson!) as Record<string, unknown>;
    assert.equal("signature" in m, false, "signature обязан был уехать в запись .jws");
    assert.doesNotThrow(() => assertNoV1Fields(m));
  });

  test("лишний пробел в манифесте ломает подпись 2.0", async () => {
    /* Половина пары. Подписаны СЫРЫЕ байты, поэтому любая пересборка
       манифеста — даже не меняющая ни одного значения — обязана ломать
       подпись. Это и есть то, ради чего формат переделывали. */
    const entries = await extract(readFileSync(REAL_2_0_PHOTO));
    const spaced = spaceAfterBrace(entries.manifestJsonBytes!);
    assert.notDeepEqual(Array.from(spaced), Array.from(entries.manifestJsonBytes!),
      "тест обязан реально изменить байты");
    const r = await verifyPackage({
      ...entries,
      manifestJsonBytes: spaced,
      manifestJson: new TextDecoder().decode(spaced),
    });
    assert.equal(r.allPass, false, "пересборка манифеста обязана ломать подпись 2.0");
    /* Сломаться обязана именно подпись. Медиа не трогали — хэш обязан
       остаться целым, иначе проверка ругается не на то. */
    assert.equal(r.checks.sig, false, "ломаться обязана подпись");
    assert.equal(r.checks.hash, true, "а хэш медиа — остаться целым");
  });

  test("тот же пробел в файле 1.x подпись НЕ ломает", { skip: haveReal ? false : "нет samples/genuine-photo.trustvisor" }, async () => {
    /* Вторая половина пары, и она тут не для симметрии. В 1.x подпись
       считается по восстановленной форме, поэтому форматирование её не
       трогает — раздел 3.3 спецификации. Держим это тестом, чтобы разница
       двух форматов была измеримой, а не описанной: если однажды 1.x начнёт
       отвергать такие файлы, у людей на руках сломаются старые съёмки. */
    const entries = await extract(readFileSync(REAL_PHOTO));
    assert.equal(entries.manifestJwsBytes, undefined, "образец 1.x не должен нести запись подписи");
    const spaced = spaceAfterBrace(entries.manifestJsonBytes!);
    const r = await verifyPackage({
      ...entries,
      manifestJsonBytes: spaced,
      manifestJson: new TextDecoder().decode(spaced),
    });
    assert.equal(r.allPass, true, "формат 1.x обязан терпеть форматирование манифеста");
  });

  test("выбросить запись подписи и выдать 2.0 за 1.x нельзя", async () => {
    /* Различение форматов идёт по НАЛИЧИЮ записи .jws. Значит напрашивается
       обход: убрать запись и заставить проверку пойти по старым правилам.
       Не выходит — в манифесте 2.0 нет поля signature, и реконструкции
       нечего проверять. */
    const entries = await extract(readFileSync(REAL_2_0_PHOTO));
    const r = await verifyPackage({ ...entries, manifestJwsBytes: undefined });
    assert.equal(r.allPass, false, "без записи подписи файл 2.0 проходить не должен");
    assert.equal(r.checks.sig, false, "проверка уходит на путь 1.x и не находит подписи");
    assert.equal(r.checks.hash, true, "медиа при этом цело");
  });
});

describe("Настоящая видеосъёмка формата 2.0", { skip: have20Video ? false : "нет samples/genuine-2.0-video.trustvisor" }, () => {
  test("проходит как ПОДЛИННАЯ, и подписей две", async () => {
    const entries = await extract(readFileSync(REAL_2_0_VIDEO));
    assert.ok(entries.manifestStartJwsBytes, "у видео 2.0 обязана быть подпись манифеста начала");
    assert.ok(entries.manifestEndJwsBytes, "и подпись манифеста конца");
    const r = await verifyPackage(entries);
    assert.equal(r.allPass, true, "настоящее видео 2.0 обязано пройти все проверки");
    assert.equal(r.trustDowngrade, false, "и не должно понижаться в доверии");
  });

  test("без подписи манифеста конца видео не проходит", async () => {
    /* Манифест конца несёт хэш самого видео. Разрешить пакету доехать без
       его подписи значило бы принимать видео, за которое никто не расписался. */
    const entries = await extract(readFileSync(REAL_2_0_VIDEO));
    const r = await verifyPackage({ ...entries, manifestEndJwsBytes: undefined });
    assert.equal(r.allPass, false, "видео без подписи манифеста конца проходить не должно");
    /* Отказ здесь наступает РАНЬШЕ проверки подписи — на разборе состава, и
       причина названа словами. Утверждаем именно её: «не прошло» без причины
       ничего не стережёт. */
    assert.match(String(r.formatError), /обе записи подписи/,
      "причина обязана быть названа, а не сведена к общему отказу");
  });

  test("лишний пробел в манифесте конца ломает подпись", async () => {
    const entries = await extract(readFileSync(REAL_2_0_VIDEO));
    const spaced = spaceAfterBrace(entries.manifestEndJsonBytes!);
    const r = await verifyPackage({
      ...entries,
      manifestEndJsonBytes: spaced,
      manifestEndJson: new TextDecoder().decode(spaced),
    });
    assert.equal(r.allPass, false, "пересборка манифеста конца обязана ломать подпись");
    /* Подписи у видео две, и сломаться обязана ровно одна — та, чей манифест
       трогали. Если падают обе, значит проверка их не различает. */
    assert.equal(r.checks.sigEnd, false, "ломается подпись манифеста конца");
    assert.equal(r.checks.sigStart, true, "подпись манифеста начала остаётся целой");
    assert.equal(r.checks.hash, true, "и видео цело");
  });
});

describe("Порядок разбора: медиа узнаётся раньше архива", () => {
  /* Подпись концевой записи ZIP — четыре байта, и в хвосте настоящего снимка
     они могут оказаться случайно. Пока оглавление разбиралось раньше магии
     медиа, такое фото получало отказ «архив объявлен многотомным» и до
     проверки подписи не доходило вовсе. Найдено сторонним разбором кода
     15 сентября 2026; браузерная копия так себя никогда не вела. */
  function jpegWithTail(tail: Buffer): Buffer {
    const head = Buffer.from([0xff, 0xd8, 0xff, 0xe0, 0x00, 0x10, 0x4a, 0x46,
                              0x49, 0x46, 0x00, 0x01, 0x01, 0x00, 0x00, 0x01]);
    return Buffer.concat([head, Buffer.alloc(4000, 0x5a), tail]);
  }

  async function reason(buf: Buffer): Promise<string> {
    const p = join(tmpdir(), "t-" + randomUUID() + ".bin");
    writeFileSync(p, buf);
    try {
      await extractPackageFromPath(p, "x.jpg");
      return "(разобрался)";
    } catch (e) {
      return (e as Error).message;
    } finally {
      try { unlinkSync(p); } catch { /* уже удалён */ }
    }
  }

  test("случайная подпись концевой записи в хвосте JPEG не мешает", async () => {
    const eocd = Buffer.concat([Buffer.from("PK", "latin1"), Buffer.alloc(18, 0x11)]);
    const ссигнатурой = await reason(jpegWithTail(eocd));
    const обычный = await reason(jpegWithTail(Buffer.alloc(22, 0x11)));
    assert.equal(ссигнатурой, обычный,
      "файл с случайной подписью концевой записи обязан разбираться как обычный JPEG");
    assert.match(обычный, /JPEG/, "ответ обязан говорить про JPEG, а не про архив");
  });
});

describe("Объявленное число записей", () => {
  /* Предел в восемь записей стоял только в разборщике, а обход оглавления шёл
     до него по всему объявленному числу. Замер 15 сентября 2026: архив из
     22 000 пустых записей (1,64 МБ — помещается под потолок оглавления в 1 МБ)
     разбирался 1 337 мс против 234 мс на настоящей съёмке. После отказа по
     объявленному числу — 192 мс, быстрее настоящей. Точка приёма файла
     открытая, и учетверять на ней работу полутора мегабайтами не стоит. */
  test("больше восьми записей отвергается до обхода оглавления", async () => {
    const zip = buildZip(
      [{ name: "manifest.json", data: TINY_MANIFEST }, { name: "photo.png", data: TINY_PNG }],
      9,
    );
    await assert.rejects(() => extract(zip), /объявлено записей/);
  });

  test("настоящий пакет с двумя записями проходит этот заслон", async () => {
    /* Обратная сторона: заслон не должен цеплять честные файлы. Двух записей
       меньше восьми, и разбор обязан дойти до содержимого. */
    const zip = buildZip([{ name: "manifest.json", data: TINY_MANIFEST },
                          { name: "photo.png", data: TINY_PNG }]);
    let сказал = "";
    try { await extract(zip); } catch (e) { сказал = (e as Error).message; }
    assert.ok(!/объявлено записей/.test(сказал),
      "двух записей меньше восьми — заслон не должен срабатывать: " + сказал);
  });
});

describe("Разборщики сертификатов", () => {
  /* Три ручных разборщика DER — derTLV, parseCertMeta, parseAndroidKeystoreExt —
     до 15 сентября 2026 не имели ни одного теста. Проверялись они только
     косвенно, через настоящую съёмку: если цепочка сошлась, значит разобралась.
     Косвенная проверка молчит о границах, а именно на границе и был знаковый
     сдвиг, из-за которого длина 0xFFFFFFFF превращалась в минус единицу. */

  test("derTLV: короткая форма длины", () => {
    const b = Uint8Array.from([0x30, 0x03, 0x02, 0x01, 0x05]);
    const t0 = derTLV(b, 0);
    assert.equal(t0.tag, 0x30);
    assert.equal(t0.valueStart, 2);
    assert.equal(t0.end, 5);
  });

  test("derTLV: длинная форма длины", () => {
    const body = new Uint8Array(300).fill(0x41);
    const b = Uint8Array.from([0x04, 0x82, 0x01, 0x2c, ...body]);
    const t0 = derTLV(b, 0);
    assert.equal(t0.valueStart, 4);
    assert.equal(t0.end, 304);
  });

  test("derTLV: длина 0xFFFFFFFF не становится отрицательной", () => {
    /* Тот самый случай: сдвиг в JavaScript знаковый и 32-битный, и длина
       0xFFFFFFFF давала -1. Срез с концом раньше начала возвращает пустой
       массив, а не ошибку, — разбор молча продолжался на пустоте. */
    const b = Uint8Array.from([0x04, 0x84, 0xff, 0xff, 0xff, 0xff, 0x00]);
    assert.throws(() => derTLV(b, 0), /DER/);
  });

  test("derTLV: элемент за границей данных — отказ", () => {
    assert.throws(() => derTLV(Uint8Array.from([0x30]), 0), /DER/);
    assert.throws(() => derTLV(Uint8Array.from([0x30, 0x7f]), 0), /DER/);
  });
});

describe("Разборщики сертификатов на настоящей цепочке", { skip: haveReal ? false : "нет samples/genuine-photo.trustvisor" }, () => {
  async function chain(): Promise<string[]> {
    const entries = await extract(readFileSync(REAL_PHOTO));
    const m = JSON.parse(entries.manifestJson!) as Record<string, unknown>;
    return m.attestationChain as string[];
  }
  const der = (b64: string) => Uint8Array.from(Buffer.from(String(b64).replace(/\s+/g, ""), "base64"));

  test("parseCertMeta читает серийный номер, срок и признак центра", async () => {
    const ch = await chain();
    assert.ok(ch.length >= 2, "в настоящей цепочке больше одного звена");
    const leaf = parseCertMeta(der(ch[0]));
    assert.match(leaf.serialHex, /^[0-9a-f]+$/, "серийный номер шестнадцатеричный, нижним регистром");
    assert.equal(typeof leaf.notBefore, "number");
    assert.equal(typeof leaf.notAfter, "number");
    assert.ok(leaf.notAfter! > leaf.notBefore!, "конец срока позже начала");
    const root = parseCertMeta(der(ch[ch.length - 1]));
    assert.equal(root.isCA, true, "последнее звено — удостоверяющий центр");
  });

  test("parseCertMeta не принимает лишние байты после сертификата", async () => {
    const ch = await chain();
    const d = der(ch[0]);
    const withTail = new Uint8Array(d.length + 4);
    withTail.set(d, 0);
    assert.throws(() => parseCertMeta(withTail), /лишние байты/);
  });

  test("parseAndroidKeystoreExt читает расширение из листа", async () => {
    const ch = await chain();
    const ext = parseAndroidKeystoreExt(der(ch[0]));
    assert.ok(ext, "расширение аттестации обязано читаться");
    assert.equal(typeof ext!.challenge, "string");
    assert.ok(ext!.kmSecName, "уровень защищённости назван");
  });

  test("checkOid и checkRootOfTrust на настоящей цепочке проходят", async () => {
    const ch = await chain();
    assert.equal(checkOid(true, ch).state, "pass");
    assert.equal(checkRootOfTrust(true, ch).state, "pass");
  });

  test("без аттестации обе проверки пропускаются, а не падают", () => {
    assert.equal(checkOid(false, undefined).state, "skip");
    assert.equal(checkRootOfTrust(false, undefined).state, "skip");
    assert.equal(checkOid(true, []).state, "skip");
  });
});

describe("Журнал датчиков", () => {
  test("честный журнал читается, потоки и значения на месте", () => {
    const log = makeSensors();
    const parsed = parseSensorLog(log);
    assert.ok(parsed, "честный журнал обязан читаться");
    assert.equal(parsed!.length, 2);
    assert.equal(parsed![0].kind, 1);
    assert.equal(parsed![0].axes, 3);
    assert.equal(parsed![0].count, 3);
    assert.equal(parsed![0].values.length, 9);
    assert.equal(parsed![1].kind, 4);
    assert.equal(parsed![1].axes, 1);
    assert.equal(parsed![1].values.length, 2);
  });

  /* Байты, которые пишет ПРИЛОЖЕНИЕ. Снято с его собственного набора
     тестов; сам он закрыт и в этот репозиторий не входит.

     Здесь они намеренно НЕ пересобираются makeSensors: смысл вектора ровно в
     том, что байты пришли с другой стороны — другой язык, другая реализация
     той же раскладки из раздела 1.7 спецификации. Пока их нет, два
     кодировщика могут разойтись молча, и оба набора тестов останутся
     зелёными: так у нас и было до 15 сентября 2026.

     Те же строки лежат в наборе тестов приложения, и их равенство сверяет
     отдельная проверка на нашей стороне. Если правите — правьте обе. */
  const PHONE_VECTORS: Array<{
    name: string;
    hex: string;
    streams: Array<{ kind: number; axes: number; hz: number; count: number; rawCount: number; values: number[] }>;
  }> = [
    { name: "движение, два отсчёта", hex: "545653454e533031010000000103000a00000002000000020000000c0064ff380f500065ff390f51", streams: [{ kind: 1, axes: 3, hz: 10, count: 2, rawCount: 2, values: [100, -200, 3920, 101, -199, 3921] }] },
    { name: "освещённость, одна ось и своя частота", hex: "545653454e5330310100000004010002000000030000000300000006164816490000", streams: [{ kind: 4, axes: 1, hz: 2, count: 3, rawCount: 3, values: [5704, 5705, 0] }] },
    { name: "два потока: сначала оба заголовка, потом обе нагрузки", hex: "545653454e533031020000000103000a000000010000000100000006040100020000000100000001000000020001000200030007", streams: [{ kind: 1, axes: 3, hz: 10, count: 1, rawCount: 1, values: [1, 2, 3] }, { kind: 4, axes: 1, hz: 2, count: 1, rawCount: 1, values: [7] }] },
    { name: "отрицательные значения дополнительным кодом", hex: "545653454e533031010000000203000a000000010000000100000006ffff80007fff", streams: [{ kind: 2, axes: 3, hz: 10, count: 1, rawCount: 1, values: [-1, -32768, 32767] }] },
  ];

  test("байты, записанные телефоном, читаются проверяльщиком", () => {
    for (const v of PHONE_VECTORS) {
      const bytes = Uint8Array.from((v.hex.match(/../g) ?? []).map((h) => parseInt(h, 16)));
      const parsed = parseSensorLog(bytes);
      assert.ok(parsed, v.name + ": журнал телефона обязан читаться");
      assert.equal(parsed!.length, v.streams.length, v.name + ": число потоков");
      v.streams.forEach((want, i) => {
        const got = parsed![i];
        assert.equal(got.kind, want.kind, v.name + ": вид потока " + i);
        assert.equal(got.axes, want.axes, v.name + ": оси " + i);
        assert.equal(got.hz, want.hz, v.name + ": частота " + i);
        assert.equal(got.count, want.count, v.name + ": число отсчётов " + i);
        assert.equal(got.rawCount, want.rawCount, v.name + ": rawCount " + i);
        assert.deepEqual(Array.from(got.values), want.values, v.name + ": значения " + i);
      });
    }
  });

  test("один поток — законный журнал: телефон без гироскопа не подделка", () => {
    const parsed = parseSensorLog(makeSensors({ streams: [{ kind: 1, count: 5 }] }));
    assert.ok(parsed);
    assert.equal(parsed!.length, 1);
  });

  test("раскладка, которая не сходится, не читается", () => {
    const cases: Array<[string, Uint8Array]> = [
      ["чужая магия", makeSensors({ magic: "TVSENS02" })],
      ["ноль потоков", makeSensors({ streamsByte: 0 })],
      ["потоков больше четырёх", makeSensors({ streamsByte: 5 })],
      ["заявлено больше потоков, чем есть", makeSensors({ streamsByte: 3 })],
      ["резерв не нулевой", makeSensors({ reserved: [0, 1, 0] })],
      ["два потока одного вида", makeSensors({ streams: [{ kind: 1, count: 1 }, { kind: 1, count: 1 }] })],
      ["неизвестный вид", makeSensors({ streams: [{ kind: 7, axes: 3, count: 1 }] })],
      ["у освещённости три оси", makeSensors({ streams: [{ kind: 4, axes: 3, count: 1 }] })],
      ["у движения одна ось", makeSensors({ streams: [{ kind: 1, axes: 1, count: 1 }] })],
      ["частота ноль", makeSensors({ streams: [{ kind: 1, hz: 0, count: 1 }] })],
      ["частота за пределом", makeSensors({ streams: [{ kind: 1, hz: 5000, count: 1 }] })],
      ["длина не сходится со счётчиком", makeSensors({ streams: [{ kind: 1, count: 2, byteLen: 10 }] })],
      ["хвост после последнего потока", makeSensors({ tail: 16 })],
      ["нагрузка обрезана", makeSensors({ cutPayload: 2 })],
      ["пусто", new Uint8Array(0)],
      ["короче заголовка", new Uint8Array(11)],
    ];
    for (const [label, log] of cases) {
      assert.equal(parseSensorLog(log), null, "должно было не прочитаться: " + label);
    }
  });

  test("хвост после журнала не проходит: карман закрыт, как в блоках подписи", () => {
    /* Отдельным тестом, а не строкой в списке выше: ровно этот карман
       («не меньше нужного» вместо «ровно») уже приезжал в настоящей съёмке
       с 1120 дописанными байтами и давал ПОДЛИННО. */
    const honest = makeSensors();
    const withTail = makeSensors({ tail: 1024 });
    assert.ok(parseSensorLog(honest));
    assert.equal(parseSensorLog(withTail), null);
  });

  test("манифест объявил журнал — хэш обязан сойтись", async () => {
    const log = makeSensors();
    const man = { sensorLogSha256: sha256hex(log) };
    const ok = await checkSensorLog(man, log);
    assert.equal(ok.state, "pass");

    const spoiled = makeSensors();
    spoiled[spoiled.byteLength - 1] ^= 0xff;
    const bad = await checkSensorLog(man, spoiled);
    assert.equal(bad.state, "fail", "подменённый журнал обязан валить проверку");
  });

  test("манифест объявил журнал, а записи нет — отказ", async () => {
    const r = await checkSensorLog({ sensorLogSha256: sha256hex(makeSensors()) }, undefined);
    assert.equal(r.state, "fail");
  });

  test("запись есть, а манифест о ней молчит — пакет отвергается", async () => {
    /* Вторая половина правила, без которой журнал был бы карманом: к
       честному файлу дописывают sensors.bin, подпись цела, и произвольные
       байты едут внутри пакета с вердиктом ПОДЛИННО. */
    await assert.rejects(() => checkSensorLog({}, makeSensors()), /sensors\.bin/);
  });

  test("ни поля, ни записи — проверка пропускается, вердикт не трогается", async () => {
    const r = await checkSensorLog({}, undefined);
    assert.equal(r.state, "skip");
  });

  test("поле испорчено типом — отказ, а не исключение наружу", async () => {
    const r = await checkSensorLog({ sensorLogSha256: 123 }, makeSensors());
    assert.equal(r.state, "fail");
  });

  test("хэш сошёлся, а раскладка нет — предупреждение, но не ИЗМЕНЁН", async () => {
    /* Байты те самые, что подписал телефон, значит подделки не было.
       Показать нечего — но хоронить этим целое доказательство нельзя. */
    const broken = makeSensors({ tail: 8 });
    const r = await checkSensorLog({ sensorLogSha256: sha256hex(broken) }, broken);
    assert.equal(r.state, "warn");
    assert.equal(downgradeReasonsOf({ sensorLog: r }).length, 0,
      "нечитаемый журнал не должен менять вердикт");
  });

  test("обрезанный по объёму журнал — это pass, и об этом сказано", async () => {
    const log = makeSensors();
    const r = await checkSensorLog(
      { sensorLogSha256: sha256hex(log), sensorLogTruncated: true }, log);
    assert.equal(r.state, "pass");
    assert.equal(r.truncated, true);
    assert.match(String(r.msg), /по объёму/);
  });
});
