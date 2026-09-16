// SPDX-License-Identifier: Apache-2.0
/* Эталонные векторы для перехода на JWS.
 *
 *     node tools/jws_vectors.mjs [файл вывода.json]
 *
 * Реформа переносит подпись из манифеста в отдельную запись формата
 * JWS (RFC 7515) с отсоединённой нагрузкой (RFC 7797). Это значит, что в
 * приложении появляется новый криптографический код, а прогнать его можно
 * только на телефоне. Самое опасное место — два тихих преобразования:
 *
 *   1) подпись. Java отдаёт ECDSA в виде DER (SEQUENCE из двух INTEGER),
 *      а JWS требует 64 байта: R и S по 32, без разделителей. Здесь ошибаются
 *      все и одинаково — на ведущем нулевом байте, который DER добавляет,
 *      когда старший бит числа выставлен, и на коротком R или S, который надо
 *      дополнить нулями СЛЕВА, а не справа;
 *
 *   2) подписываемые байты. Подписывается не манифест, а склейка
 *      base64url(заголовок) + "." + байты манифеста. Перепутать легко,
 *      заметить трудно: подпись просто не сойдётся, и будет непонятно, где.
 *
 * Оба преобразования детерминированы — в отличие от самой подписи ECDSA,
 * которая случайна и побайтово несравнима. Поэтому их можно закрыть
 * векторами: приложение считает своё, сверяет с эталоном, расходится — видно
 * сразу и на стенде, а не на телефоне.
 *
 * Зависимостей нет: только node:crypto. Наш проверяльщик тоже останется без
 * зависимостей — разобрать плоский JWS это JSON.parse, base64url и склейка.
 */
import { createHash, generateKeyPairSync, sign, verify, webcrypto } from "node:crypto";
import { writeFileSync } from "node:fs";

const OUT = process.argv[2] ?? "tools/jws_vectors.json";

const hex = (b) => Buffer.from(b).toString("hex");
const b64u = (b) => Buffer.from(b).toString("base64url");

/* ── 1. DER → R‖S ─────────────────────────────────────────────────────────
   Та же логика, что в derToP1363 ядра, но записанная отдельно и нарочно
   просто: это эталон для переписывания на Kotlin, а не боевой разбор.
   Боевой обязан быть строгим к длинам — см. verify-core.ts:114. */
function derToRS(der) {
  let p = 0;
  if (der[p++] !== 0x30) throw new Error("ожидался SEQUENCE");
  let seqLen = der[p++];
  if (seqLen & 0x80) {
    const nb = seqLen & 0x7f;
    seqLen = 0;
    for (let i = 0; i < nb; i++) seqLen = seqLen * 256 + der[p++];
  }
  if (p + seqLen !== der.length) throw new Error("длина SEQUENCE не сходится");
  const readInt = () => {
    if (der[p++] !== 0x02) throw new Error("ожидался INTEGER");
    const len = der[p++];
    if (len & 0x80) throw new Error("длинная форма длины у INTEGER недопустима для P-256");
    let v = der.subarray(p, p + len);
    p += len;
    /* DER пишет числа со знаком: если старший бит выставлен, впереди
       добавляется 0x00. Его надо снять. */
    while (v.length > 1 && v[0] === 0x00) v = v.subarray(1);
    if (v.length > 32) throw new Error("число длиннее 32 байт — это не P-256");
    /* Дополняем слева. Дополнить справа — самая частая ошибка: подпись
       станет неверной, но структурно правильной, и отладка уйдёт не туда. */
    const out = new Uint8Array(32);
    out.set(v, 32 - v.length);
    return out;
  };
  const r = readInt();
  const s = readInt();
  if (p !== der.length) throw new Error("после S остались байты");
  const rs = new Uint8Array(64);
  rs.set(r, 0);
  rs.set(s, 32);
  return rs;
}

/* ── 2. Набор подписей, включая краевые ───────────────────────────────────
   Краевые случаи не выдумываются, а вылавливаются: подписываем, пока не
   попадутся все четыре сочетания «короткое/длинное R» на «короткое/длинное
   S». Вероятность короткого около 1/256, поэтому попыток нужно несколько
   тысяч, и это единственный честный способ получить настоящие векторы. */
const { privateKey, publicKey } = generateKeyPairSync("ec", { namedCurve: "prime256v1" });

const MSG = Buffer.from("TrustVisor JWS vector", "utf8");
const wanted = new Map();
const labelOf = (rs) => (rs[0] === 0 ? "R короткое" : "R полное")
  + ", " + (rs[32] === 0 ? "S короткое" : "S полное");

for (let i = 0; i < 200000 && wanted.size < 4; i++) {
  const msg = Buffer.concat([MSG, Buffer.from(String(i))]);
  const der = sign("sha256", msg, { key: privateKey, dsaEncoding: "der" });
  const rs = derToRS(der);
  const key = labelOf(rs);
  if (wanted.has(key)) continue;
  /* Сверка не побайтовая, и это важно. ECDSA случайна: два вызова подписи на
     одном сообщении дают разные байты. Сравнивать преобразованную подпись с
     заново запрошенной бессмысленно — я на этом сам споткнулся при первом
     прогоне, все четыре случая показали расхождение при верном коде.
     Правильная сверка: проверить, что преобразованная подпись сходится. */
  const ok1363 = verify("sha256", msg, { key: publicKey, dsaEncoding: "ieee-p1363" }, rs);
  wanted.set(key, {
    случай: key,
    сообщение_hex: hex(msg),
    der_hex: hex(der),
    rs_hex: hex(rs),
    преобразованная_подпись: ok1363 ? "сходится" : "НЕ СХОДИТСЯ",
  });
}

/* ── 2б. Синтетические векторы: то же самое, но без ключа ─────────────────
   Векторы выше собраны настоящим ключом, а ключ у каждого прогона свой —
   значит и векторы каждый раз новые. Как данные для теста в приложении это
   плохо: тест должен опираться на неподвижное.

   Поэтому здесь R и S задаются руками, DER собирается вокруг них, и ответ
   известен заранее. Ключа нет, подписи нет, проверять нечего — проверяется
   ровно преобразование, и оно детерминировано. Такие векторы можно вписать
   в тест на Kotlin прямо числами. */
function derOf(r, s) {
  const intOf = (v) => {
    let i = 0;
    while (i < v.length - 1 && v[i] === 0) i++;      // снять ведущие нули
    let body = v.subarray(i);
    if (body[0] & 0x80) body = Buffer.concat([Buffer.from([0]), body]);  // знак
    return Buffer.concat([Buffer.from([0x02, body.length]), body]);
  };
  const body = Buffer.concat([intOf(r), intOf(s)]);
  return Buffer.concat([Buffer.from([0x30, body.length]), body]);
}
const b32 = (fill) => Buffer.alloc(32, fill);
const withFirst = (fill, first) => { const b = b32(fill); b[0] = first; return b; };

const synthetic = [
  ["R и S обычные, старший бит снят", withFirst(0x11, 0x7f), withFirst(0x22, 0x7f)],
  ["у обоих выставлен старший бит — DER добавит 0x00", withFirst(0x33, 0xff), withFirst(0x44, 0xff)],
  ["R короткое на байт — дополняем слева", withFirst(0x55, 0x00), withFirst(0x66, 0x7f)],
  ["S короткое на байт", withFirst(0x77, 0x7f), withFirst(0x88, 0x00)],
  ["R равно единице — в DER всего один байт", withFirst(0x00, 0x00).fill(0, 0, 31), b32(0x01)],
  ["S равно нулю — вырожденный, но разобраться обязан", b32(0x02), Buffer.alloc(32, 0)],
].map(([что, r, s]) => {
  const rr = Buffer.from(r), ss = Buffer.from(s);
  if (что.startsWith("R равно единице")) rr.fill(0), (rr[31] = 1);
  const der = derOf(rr, ss);
  return {
    что,
    r_hex: hex(rr),
    s_hex: hex(ss),
    der_hex: hex(der),
    ожидаемые_64_байта: hex(Buffer.concat([rr, ss])),
    наш_разбор_совпал: hex(derToRS(der)) === hex(Buffer.concat([rr, ss])) ? "да" : "НЕТ",
  };
});

/* ── 3. Подписываемые байты ───────────────────────────────────────────────
   Здесь случайности нет вообще: заголовок и манифест заданы, склейка
   однозначна. Это и есть главный вектор для приложения. */
const header = {
  alg: "ES256",
  b64: false,
  crit: ["b64"],
  typ: "application/trustvisor-manifest+json",
  x5c: ["<сюда идёт цепочка аттестации, base64 от DER, как в attestationChain>"],
};
/* Заголовок сериализуется компактно и ровно один раз: подписывается именно
   та строка, что попадёт в файл. Пересобирать её при проверке нельзя —
   порядок членов не гарантирован. */
const protectedJson = JSON.stringify(header);
const protectedB64 = b64u(Buffer.from(protectedJson, "utf8"));

const manifestBytes = Buffer.from(
  '{\n  "manifestVersion": "2.0",\n  "sessionId": "пример"\n}', "utf8");

const signingInput = Buffer.concat([
  Buffer.from(protectedB64, "ascii"),
  Buffer.from(".", "ascii"),
  manifestBytes,
]);

const derSig = sign("sha256", signingInput, { key: privateKey, dsaEncoding: "der" });
const rsSig = derToRS(derSig);

/* Проверяем вектор целиком тем же способом, каким его будет проверять
   браузер: Web Crypto, ECDSA P-256, плоская подпись. */
const wcKey = await webcrypto.subtle.importKey(
  "spki", publicKey.export({ type: "spki", format: "der" }),
  { name: "ECDSA", namedCurve: "P-256" }, false, ["verify"]);
const ok = await webcrypto.subtle.verify(
  { name: "ECDSA", hash: { name: "SHA-256" } }, wcKey, rsSig, signingInput);

const vectors = {
  пояснение: "Эталоны для перехода на JWS. Подпись ECDSA случайна и побайтово "
    + "несравнима; сравнивать надо преобразования, они детерминированы.",
  преобразование_der_в_rs_настоящим_ключом: [...wanted.values()],
  преобразование_der_в_rs_синтетика: synthetic,
  подписываемые_байты: {
    заголовок_json: protectedJson,
    заголовок_base64url: protectedB64,
    манифест_hex: hex(manifestBytes),
    склейка_hex: hex(signingInput),
    склейка_sha256: createHash("sha256").update(signingInput).digest("hex"),
    пояснение: "Приложение обязано получить ровно эту склейку. Сверять по "
      + "sha256: совпал — склейка верна, не совпал — искать здесь, а не в подписи.",
  },
  пример_записи_jws: {
    protected: protectedB64,
    signature: b64u(rsSig),
    проверка_web_crypto: ok ? "подпись сходится" : "ПОДПИСЬ НЕ СОШЛАСЬ",
    оговорка: "Ключ здесь одноразовый, цепочка x5c подставная. Вектор "
      + "проверяет разбор конверта, а не доверие к цепочке.",
  },
};

writeFileSync(OUT, JSON.stringify(vectors, null, 2), "utf8");

console.log("краевых случаев подписи собрано: " + wanted.size + " из 4");
for (const v of wanted.values()) {
  console.log("  " + v.случай.padEnd(28) + " преобразованная подпись: " + v.преобразованная_подпись);
}
console.log("склейка подписываемых байт, sha256: "
  + vectors.подписываемые_байты.склейка_sha256.slice(0, 16) + "…");
console.log("проверка примера через Web Crypto: "
  + vectors.пример_записи_jws.проверка_web_crypto);
for (const v of synthetic) console.log("  " + v.что.padEnd(48) + " разбор совпал: " + v.наш_разбор_совпал);
console.log("записано: " + OUT);
