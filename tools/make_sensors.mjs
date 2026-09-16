// SPDX-License-Identifier: Apache-2.0
/* Собрать пакет формата 2.0 С ЖУРНАЛОМ ДАТЧИКОВ из настоящей съёмки.
 *
 *     node tools/make_sensors.mjs <настоящий .trustvisor> <куда.trustvisor> [случай]
 *
 * Правило «манифест решает, можно ли записи быть» проверяется только
 * на собранном файле: модульный тест видит функцию, а не пакет, и не ловит
 * ни допуск по имени записи, ни предел размера по оглавлению, ни то, как
 * ведут себя на этом файле ОБА проверяльщика.
 *
 * ЧЕГО ЭТОТ СБОРЩИК НЕ МОЖЕТ — ограничение замысла, а не стенда. Настоящую
 * подпись делает ключ внутри чипа телефона, вынуть его нельзя. Здесь берётся
 * контрольный ключ, создаваемый на месте, и `publicKey` заменяется на него.
 * Поэтому подпись у такого пакета сходится (это и проверяем), а привязка
 * ключа к цепочке аттестации — нет. Вердикт ПОДЛИННО с журналом доказуем
 * только настоящей съёмкой новым приложением.
 *
 * Случаи (третий аргумент) отличаются от честного файла ровно одним
 * изменением — иначе непонятно, что именно поймал заслон.
 */
import { readFileSync, writeFileSync } from "node:fs";
import { generateKeyPairSync, sign, createHash } from "node:crypto";
import { execFileSync } from "node:child_process";

const [src, dst, caseName = "clean"] = process.argv.slice(2);
if (!src || !dst) {
  console.error("использование: node tools/make_sensors.mjs <из.trustvisor> <в.trustvisor> [случай]");
  process.exit(2);
}

/* ── Журнал по раскладке раздела 1.7 ──────────────────────────────────────
   Значения синтетические, но правдоподобные по порядку величины: полоса
   должна что-то показывать, иначе глазами её не проверить. */
function makeSensorLog({ seconds = 8, kinds = [1, 2, 3, 4], broken = null } = {}) {
  const SPEC = {
    1: { axes: 3, hz: 10, scale: 400 },
    2: { axes: 3, hz: 10, scale: 900 },
    3: { axes: 3, hz: 5,  scale: 32  },
    4: { axes: 1, hz: 2,  scale: 1   },
  };
  const heads = kinds.map((k) => {
    const s = SPEC[k];
    const count = Math.max(1, Math.round(seconds * s.hz));
    return { kind: k, axes: s.axes, hz: s.hz, count, rawCount: count, byteLen: count * s.axes * 2, scale: s.scale };
  });
  /* Порчи, которые меняют заголовок потока, а не его нагрузку: так
     испорченный файл отличается от честного ровно одним полем, и понятно,
     какое именно правило поймало отказ. */
  if (broken === "dup_kind" && heads.length > 1) heads[1].kind = heads[0].kind;
  if (broken === "bad_kind") heads[0].kind = 9;
  if (broken === "bad_hz") heads[0].hz = 0;
  if (broken === "bad_axes") {
    /* Длину пересчитываем под новое число осей: иначе первым сработало бы
       правило «длина не сходится со счётчиком», и файл проверял бы не то
       правило, ради которого собран. */
    heads[0].axes = 2;
    heads[0].byteLen = heads[0].count * 2 * 2;
  }
  const payload = heads.reduce((n, h) => n + h.byteLen, 0);
  const headerEnd = 12 + heads.length * 16;
  let total = headerEnd + payload;
  if (broken === "tail") total += 32;

  const out = new Uint8Array(total);
  const dv = new DataView(out.buffer);
  const magic = broken === "magic" ? "TVSENS99" : "TVSENS01";
  for (let i = 0; i < 8; i++) out[i] = magic.charCodeAt(i);
  out[8] = broken === "streams0" ? 0 : (broken === "streams5" ? 5 : heads.length);
  if (broken === "reserved") out[10] = 1;

  heads.forEach((h, i) => {
    const o = 12 + i * 16;
    dv.setUint8(o, h.kind);
    dv.setUint8(o + 1, h.axes);
    dv.setUint16(o + 2, h.hz);
    dv.setUint32(o + 4, h.count);
    dv.setUint32(o + 8, broken === "thin" ? Math.floor(h.count * 0.3) : h.rawCount);
    dv.setUint32(o + 12, broken === "len" && i === 0 ? h.byteLen + 2 : h.byteLen);
  });

  let p = headerEnd;
  for (const h of heads) {
    for (let i = 0; i < h.count; i++) {
      const t = i / h.hz;
      for (let a = 0; a < h.axes; a++) {
        /* Рука человека: медленное покачивание плюс мелкая дрожь. */
        let v;
        if (h.kind === 1) v = (a === 1 ? 9.8 : 0) + Math.sin(t * 1.7 + a) * 1.4 + Math.sin(t * 23) * 0.2;
        else if (h.kind === 2) v = Math.sin(t * 1.1 + a * 2) * 0.35;
        else if (h.kind === 3) v = [18, -6, 42][a] + Math.sin(t * 0.6 + a) * 3;
        else v = Math.log1p(300 + Math.sin(t * 0.4) * 250) * 1000 / 1000;
        let q = h.kind === 4 ? Math.round(1000 * Math.log1p(300 + Math.sin(t * 0.4) * 250))
                             : Math.round(v * h.scale);
        q = Math.max(-32768, Math.min(32767, q));
        dv.setInt16(p, q);
        p += 2;
      }
    }
  }
  return Buffer.from(out.buffer, 0, out.byteLength);
}

const CASES = {
  clean:      { log: () => makeSensorLog(), field: "match" },
  truncated:  { log: () => makeSensorLog(), field: "match", truncFlag: true },
  no_field:   { log: () => makeSensorLog(), field: "none" },
  no_entry:   { log: () => null,            field: "fake" },
  bad_hash:   { log: () => makeSensorLog(), field: "fake" },
  bad_layout: { log: () => makeSensorLog({ broken: "tail" }), field: "match" },
  bad_magic:  { log: () => makeSensorLog({ broken: "magic" }), field: "match" },
  bad_len:    { log: () => makeSensorLog({ broken: "len" }),   field: "match" },
  streams0:   { log: () => makeSensorLog({ broken: "streams0" }), field: "match" },
  reserved:   { log: () => makeSensorLog({ broken: "reserved" }), field: "match" },
  thin:       { log: () => makeSensorLog({ broken: "thin" }), field: "match" },
  one_stream: { log: () => makeSensorLog({ kinds: [1] }), field: "match" },
  dup_kind:   { log: () => makeSensorLog({ broken: "dup_kind" }), field: "match" },
  bad_kind:   { log: () => makeSensorLog({ broken: "bad_kind" }), field: "match" },
  bad_axes:   { log: () => makeSensorLog({ broken: "bad_axes" }), field: "match" },
  bad_hz:     { log: () => makeSensorLog({ broken: "bad_hz" }),   field: "match" },
  streams5:   { log: () => makeSensorLog({ broken: "streams5" }), field: "match" },
  short:      { log: () => Buffer.from("TVSENS0"), field: "match" },
  oversize:   { log: () => makeSensorLog({ seconds: 9000 }), field: "match" },
  in_start:   { log: () => makeSensorLog(), field: "start" },
  /* Сжимаемая запись. Ровно этого случая в корпусе не было, и из-за него
     полгода жило расхождение: сервер режет запись по степени сжатия (20×),
     а браузер смотрел её только у медиа. Миллион нулей сжимается в тысячу
     байт — 1015×. Размер при этом ровно на потолке, чтобы сработала именно
     степень, а не объём. */
  zip_ratio:  { log: () => Buffer.alloc(1024 * 1024), field: "match" },
};

const spec = CASES[caseName];
if (!spec) {
  console.error("неизвестный случай: " + caseName + "; есть " + Object.keys(CASES).join(", "));
  process.exit(2);
}

/* Разбор и сборка ZIP — через Python, как в make_v2.mjs: вторая реализация
   ZIP в проекте нам не нужна ни под каким видом. */
/* Берём и манифесты, и записи подписи: у источника формата 2.0 цепочка
   аттестации лежит в защищённом заголовке `.jws` (в этом и была реформа), а
   в манифесте её уже нет. Без неё пересобранный пакет получал бы заголовок
   без x5c, разбор такую запись отвергает, и «подпись не сошлась» означало бы
   дефект стенда, а не находку. */
const READ_PY = String.raw`
import base64, io, json, sys, zipfile
z = zipfile.ZipFile(sys.argv[1])
out = {n: base64.b64encode(z.read(n)).decode()
       for n in z.namelist() if n.endswith(".json") or n.endswith(".jws")}
print(json.dumps(out))
`;

const WRITE_PY = String.raw`
import base64, io, json, sys, zipfile
src, dst, payload = sys.argv[1], sys.argv[2], sys.argv[3]
spec = json.loads(io.open(payload, encoding="utf-8").read())
zin = zipfile.ZipFile(src)
with zipfile.ZipFile(dst, "w", zipfile.ZIP_DEFLATED) as zout:
    for info in zin.infolist():
        name = info.filename
        if name.endswith(".jws") or name == "sensors.bin":
            continue
        if name in spec["manifests"]:
            zout.writestr(name, base64.b64decode(spec["manifests"][name]))
        else:
            zout.writestr(name, zin.read(name))
    for name, b64 in spec["jws"].items():
        zout.writestr(name, base64.b64decode(b64))
    if spec.get("sensors"):
        zout.writestr("sensors.bin", base64.b64decode(spec["sensors"]))
print("записей:", len(zipfile.ZipFile(dst).namelist()))
`;

const raw = JSON.parse(execFileSync("python", ["-c", READ_PY, src], { encoding: "utf8" }));
const { privateKey, publicKey } = generateKeyPairSync("ec", { namedCurve: "prime256v1" });
const spki = publicKey.export({ type: "spki", format: "der" }).toString("base64");
const b64u = (b) => Buffer.from(b).toString("base64url");

const log = spec.log();
const realHex = log ? createHash("sha256").update(log).digest("hex") : null;
const FAKE_HEX = "0".repeat(64);

/* Куда класть поле. Манифест НАЧАЛА подписывается до конца съёмки, журнала
   тогда ещё нет, — поэтому поле живёт в манифесте конца (видео) или в
   манифесте фото. Случай `in_start` кладёт его не туда нарочно: проверяльщик
   обязан не заметить и отказать по «записи нет в манифесте». */
function fieldTarget(name) {
  if (spec.field === "none") return false;
  if (spec.field === "start") return name === "manifest_start.json";
  return name === "manifest_end.json" || name === "manifest.json";
}

/* Цепочка: из манифеста (источник 1.x) либо из заголовка любой записи
   подписи (источник 2.0). */
let chain = null;
for (const [name, b64] of Object.entries(raw)) {
  if (!name.endsWith(".jws")) continue;
  const rec = Buffer.from(b64, "base64").toString("ascii");
  const prot = rec.slice(0, rec.indexOf(".."));
  try {
    const hdr = JSON.parse(Buffer.from(prot, "base64url").toString("utf8"));
    if (Array.isArray(hdr.x5c) && hdr.x5c.length) { chain = hdr.x5c; break; }
  } catch { /* не разобралось — попробуем следующую */ }
}

const manifests = {}, jws = {};
for (const [name, b64] of Object.entries(raw)) {
  if (!name.endsWith(".json")) continue;
  const m = JSON.parse(Buffer.from(b64, "base64").toString("utf8"));
  chain = chain ?? m.attestationChain;
  delete m.signature; delete m.signatureAlgorithm; delete m.attestationChain;
  m.publicKey = spki;
  m.manifestVersion = "2.0";
  if (fieldTarget(name)) {
    m.sensorLogSha256 = spec.field === "fake" ? FAKE_HEX : realHex;
    if (spec.truncFlag) m.sensorLogTruncated = true;
  }
  const bytes = Buffer.from(JSON.stringify(m, null, 2), "utf8");
  manifests[name] = bytes.toString("base64");

  const header = { alg: "ES256", b64: false, crit: ["b64"],
                   typ: "application/trustvisor-manifest+json", x5c: chain };
  const prot = b64u(Buffer.from(JSON.stringify(header), "utf8"));
  const input = Buffer.concat([Buffer.from(prot, "ascii"), Buffer.from("."), bytes]);
  const sig = sign("sha256", input, { key: privateKey, dsaEncoding: "ieee-p1363" });
  jws[name + ".jws"] = Buffer.from(prot + ".." + b64u(sig), "utf8").toString("base64");
}

const tmp = dst + ".spec.json";
writeFileSync(tmp, JSON.stringify({
  manifests, jws, sensors: log ? log.toString("base64") : null,
}), "utf8");
console.log(execFileSync("python", ["-c", WRITE_PY, src, dst, tmp], { encoding: "utf8" }).trim());
console.log("случай:", caseName, log ? "· журнал " + log.length + " Б" : "· журнала нет");
