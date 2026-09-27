// SPDX-License-Identifier: Apache-2.0
// Ядро проверки подписанных файлов TrustVisor.
//
// Тот же код работает и в браузере, и на сервере: браузерная проверка и
// серверная обязаны давать один и тот же вердикт на одном и том же файле.
// Расхождение между двумя проверяльщиками — главный класс ошибок в задаче
// такого рода, поэтому обе стороны меняются только вместе, а совпадение
// вердиктов проверяется перебором испорченных файлов (см. tools/).
//
// Файл намеренно не зависит ни от DOM, ни от сети: проверка обязана
// работать без обращения к кому бы то ни было, включая нас.
//
// Три слова, которые встречаются в комментариях ниже и не объясняются на
// месте. «Браузерная копия» — вторая
// реализация этой же проверки, она живёт на странице проверки файла и в этот
// репозиторий не входит. «Полка» — хранилище съёмок в кабинете клиента: файл
// туда попадает, только если проверка сочла его подлинным. «Портал» — сервер,
// который эту проверку выполняет.
import type { webcrypto } from "node:crypto";
import { GOOGLE_ROOT_FINGERPRINTS_HARDCODED, OEM_ROOT_FINGERPRINTS, TRUSTVISOR_ATTESTATION_PUBLIC_KEY_B64, TRUSTVISOR_ATTESTATION_PUBLIC_KEY_NEXT_B64, TRUSTVISOR_ATTESTATION_OLD_KEY_LAST_EXP_MS, TRUSTVISOR_WEB_SIGNING_KEYS } from "./trusted-roots.js";
import { REVOKED_SERIALS, REVOKED_SNAPSHOT_DATE } from "./revoked-keys.js";
import { PackageRejectedError } from "./errors.js";
export { PackageRejectedError } from "./errors.js";

// В tsconfig намеренно нет библиотеки "DOM": этот файл не должен зависеть от
// document и window — ради этого он и вынесен отдельно. Поэтому два глобальных
// имени ниже приходится объявить руками: в браузере они есть сами по себе, а
// здесь работает Web Crypto из Node. Объявления описывают только их форму для
// проверки типов, на работу они не влияют.
type CryptoKey = webcrypto.CryptoKey;
type BufferSource = ArrayBufferView | ArrayBuffer;

export type CheckState = "pass" | "warn" | "fail" | "skip" | "na" | "ok";

export interface NamedCheck {
  state: CheckState;
  msg?: string;
  [key: string]: unknown;
}

/** Что может лежать в `VerifyResult.checks` — см. пояснение у поля. */
export type CheckValue = boolean | string | NamedCheck;

export interface VerifyResult {
  isPhoto: boolean;
  fileName: string;
  /** Почему разбор формата 2.0 не состоялся: манифест не отвечает требованиям
   *  раздела 2.0.6, запись подписи повреждена, в манифесте поля формата 1.x.
   *  Прежде этот текст пропадал, и человек читал «запись могла быть изменена»
   *  там, где правда была «манифест не отвечает формату». */
  formatError?: string | null;
  /** Результаты проверок по именам. Значение трёх видов, и это не небрежность:
   *  булево там, где ответ двоичный (подпись сошлась или нет), строка у хэша
   *  медиа (его показывают), и `NamedCheck` там, где кроме состояния нужен
   *  текст для человека. Раньше здесь стояло `unknown`, и в самой
   *  ответственной функции тип не проверял ничего. */
  checks: Record<string, CheckValue>;
  allPass: boolean;
  trustDowngrade: boolean;
  downgradeReasons: string[];
  /* Момент съёмки: по серверным часам, если есть привязка (checkServerAnchor),
     иначе по часам телефона; momentSource говорит, чему верить. */
  momentMs?: number | null;
  momentSource?: "anchor" | "token" | "device";
  offlineMs?: number | null;
  deviceClockShiftMs?: number | null;
  locationMock?: boolean;
  meta: unknown;
  /* Байты медиа для показа. У видео, отпечаток которого посчитан при
     чтении (PackageEntries.videoDigest), буфер пуст: байты остались в
     файле, и показывающая сторона берёт их оттуда. */
  mediaBuffer: ArrayBuffer;
  mediaType: string;
  mediaName: string;
  /* Байты журнала датчиков — для показа. Ядро отдаёт их как есть и никаких
     выводов из них не делает; разбор раскладки живёт на показывающей
     стороне. Отсутствует, когда журнала в пакете нет. */
  sensorLogBytes?: Uint8Array;
}

export interface PackageEntries {
  fileName: string;
  manifestJson?: string; // photo path
  photoBuffer?: ArrayBuffer;
  manifestStartJson?: string; // video path
  manifestEndJson?: string;
  videoBuffer?: ArrayBuffer;
  /* Отпечаток видео, посчитанный разборщиком по ходу чтения (ядро 1.4.0).

     Видео бывает до гигабайта, и держать его в памяти ради одного хэша
     незачем: ядро смотрит на байты видео только чтобы посчитать SHA-256.
     Разборщик прогоняет байты через хэш, пока читает файл, и отдаёт сюда
     итог и число байт.

     Заполнять это поле вправе ТОЛЬКО тот, кто сам прочитал байты видео.
     Взять его из пакета или из манифеста — значит сверить манифест сам с
     собой. Если переданы и буфер, и отпечаток, верим буферу: его хэш ядро
     считает само. */
  videoDigest?: { sha256Hex: string; size: number };
  /* СЫРЫЕ байты манифестов — именно они идут в проверку подписи.

     Строки выше остаются для JSON.parse и для показа полей в отчёте, но
     доверять им при проверке подписи нельзя: они получены нестрогим
     Buffer.toString("utf-8"), который молча заменяет невалидный байт на
     U+FFFD. Из-за этого сервер подтверждал подпись на файле, который браузер
     (строгий TextDecoder) объявлял изменённым — воспроизведено на
     настоящем demo.trustvisor. */
  manifestJsonBytes?: Uint8Array;
  manifestStartJsonBytes?: Uint8Array;
  manifestEndJsonBytes?: Uint8Array;
  /* Формат 2.0: содержимое записей `<манифест>.jws`. Их НАЛИЧИЕ и решает,
     по каким правилам проверять пакет, — см. раздел 2.0.7 спецификации.
     Отсутствуют у файлов формата 1.x, и это нормальный путь, а не ошибка. */
  manifestJwsBytes?: Uint8Array;
  manifestStartJwsBytes?: Uint8Array;
  manifestEndJwsBytes?: Uint8Array;
  /* Формат 2.0, необязательная запись `sensors.bin`: показания датчиков за
     время съёмки. Ядро её НЕ истолковывает — сверяет хэш и отдаёт байты
     показывающей стороне. Вывод «похоже на настоящую съёмку» из журнала не
     делается ни здесь, ни где-либо ещё: это вопрос к эксперту, а не к
     программе. Раздел 1.7 спецификации. */
  sensorLogBytes?: Uint8Array;
}

/* Текст манифеста и подписываемые байты обязаны происходить из одного
   источника, иначе в отчёт попадут поля, которых подпись не покрывала.
   Байты — главные; строка выводится из них. Показ декодируется НЕстрого
   (испорченный файл всё равно должен что-то показать), строгость живёт в
   проверке подписи. */
function manifestPair(
  bytes: Uint8Array | undefined,
  text: string | undefined,
): { bytes?: Uint8Array; text?: string } {
  /* ignoreBOM обязателен. Без него TextDecoder молча срезает метку порядка
     байт в начале, и манифест с дописанной меткой начинает разбираться как
     обычный. Прежний Buffer.toString её не срезал, и JSZip в браузере не
     срезает — то есть сервер стал бы принимать файл, который сайт отвергает.
     Ровно это и произошло при переводе проверки на сырые байты. */
  if (bytes) return { bytes, text: new TextDecoder("utf-8", { ignoreBOM: true }).decode(bytes) };
  if (text != null) return { bytes: new TextEncoder().encode(text), text };
  return {};
}

function base64ToBytes(b64: string): Uint8Array {
  const bin = atob(b64);
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}

function bufToHex(buf: ArrayBuffer | Uint8Array): string {
  return Array.from(new Uint8Array(buf as ArrayBuffer))
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("");
}

async function importSpkiKey(b64: string): Promise<CryptoKey> {
  return crypto.subtle.importKey("spki", base64ToBytes(b64) as BufferSource, { name: "ECDSA", namedCurve: "P-256" }, false, ["verify"]);
}

function derToP1363(der: Uint8Array): Uint8Array {
  let p = 0;
  if (der[p++] !== 0x30) throw new Error("DER: ожидался SEQUENCE (0x30)");
  /* Длину внешнего SEQUENCE раньше читали и не использовали. Из-за этого
     подпись можно было перекодировать — сменить форму длины, объявить её
     больше и дописать хвост, — а вердикт не менялся. Теперь она обязана
     точно покрывать r и s и заканчиваться на конце данных. */
  let seqLen = der[p++];
  if (seqLen & 0x80) {
    const nb = seqLen & 0x7f;
    if (nb === 0 || nb > 4) throw new Error("DER: недопустимая форма длины подписи");
    if (p + nb > der.length) throw new Error("DER: длина подписи обрывается за границей данных");
    seqLen = 0;
    for (let i = 0; i < nb; i++) seqLen = seqLen * 256 + der[p++];
  }
  const seqEnd = p + seqLen;
  if (!Number.isSafeInteger(seqEnd) || seqEnd !== der.length)
    throw new Error("DER: длина подписи не совпадает с размером данных");
  function readInt(): Uint8Array {
    if (der[p++] !== 0x02) throw new Error("DER: ожидался INTEGER (0x02)");
    let len = der[p++];
    if (len & 0x80) {
      const nb = len & 0x7f;
      // Та же дисциплина, что в derTLV: длина считается умножением, потому что
      // сдвиг знаковый и 32-битный, и проверяется на выход за границы.
      if (nb === 0 || nb > 4) throw new Error("DER: недопустимая форма длины в подписи");
      if (p + nb > der.length) throw new Error("DER: длина подписи обрывается за границей данных");
      len = 0;
      for (let i = 0; i < nb; i++) len = len * 256 + der[p++];
    }
    if (!Number.isSafeInteger(len) || len < 0 || p + len > der.length)
      throw new Error("DER: некорректная длина в подписи");
    const val = der.slice(p, p + len);
    p += len;
    return val[0] === 0x00 ? val.slice(1) : val;
  }
  const r = readInt(),
    s = readInt();
  if (p !== seqEnd) throw new Error("DER: в подписи остались лишние байты");
  const out = new Uint8Array(64);
  out.set(r, 32 - r.length);
  out.set(s, 64 - s.length);
  return out;
}


/* ── Формат 2.0: подпись отдельной записью, JWS ───────────────────────────

   Раскладка и правила — раздел 2.0 спецификации. Здесь только то, что важно
   помнить, читая код.

   Запись `.jws` ничем не подписана, поэтому её содержимое задано ПОБАЙТНО, а
   не описано списком разрешённого. Разница не стилистическая: список
   запрещает то, что мы придумали, а пересборка разрешает только то, что мы
   породили. Первая редакция проекта закрывала запись шестью запретами, и
   шесть обходов из шести её прошли — экранирование имени члена, пробел
   внутри строкового литерала, дубликат ключа, метка BOM. Все они существуют
   потому, что JSON описывает РАЗОБРАННЫЙ объект, а карман живёт в сырых
   байтах.

   Поэтому здесь нет JSON вообще: компактная сериализация JWS с
   отсоединённой нагрузкой (RFC 7515 + RFC 7797), то есть одна строка ASCII
   `заголовок..подпись`. Нечего экранировать, негде поставить пробел, нечему
   повториться. */
const JWS_SIG_CHARS = 86;
/* 86 символов base64url несут 516 бит, подпись — 512. Лишние четыре бита
   обязаны быть нулями: иначе 16 разных записей дают одну и ту же подпись.
   Нулевым младшим битам соответствуют ровно эти четыре символа. Замерено. */
const JWS_SIG_TAIL = new Set(["A", "Q", "g", "w"]);
const JWS_HEADER_KEYS = ["alg", "b64", "crit", "typ", "x5c"];
/* Второй допустимый набор — подпись сервера для съёмки из браузера. Именно
   НАБОР, а не «x5c необязателен»: пакет обязан быть либо тем, либо другим, и
   смешать их нельзя. Заголовок целиком под подписью. */
const JWS_HEADER_KEYS_KID = ["alg", "b64", "crit", "kid", "typ"];
const JWS_TYP = "application/trustvisor-manifest+json";

export interface DetachedJws {
  protectedB64: string;
  signature: Uint8Array;
  /* Пусто у браузерной съёмки: цепочки аттестации там нет и быть не может. */
  x5c: string[];
  /* Заполнено только у подписи сервера. Взаимоисключающе с x5c: набор полей
     заголовка проверяется целиком, третьего варианта нет. */
  kid?: string;
}

/* Строгий разбор base64url. Отдельной функцией и намеренно: base64ToBytes
   выше опирается на atob, а тот символы `-` и `_` отвергает. Наивное
   `replace` здесь — как раз то место, где рождаются щели с набивкой `=` и
   с чужим алфавитом `+/`, поэтому алфавит проверяется ДО перевода. */
function base64UrlToBytes(s: string): Uint8Array {
  for (let i = 0; i < s.length; i++) {
    const c = s.charCodeAt(i);
    const ok = (c >= 0x41 && c <= 0x5a) || (c >= 0x61 && c <= 0x7a)
      || (c >= 0x30 && c <= 0x39) || c === 0x2d || c === 0x5f;
    if (!ok) throw new Error("В подписи посторонний символ — ожидается только base64url");
  }
  if (s.length % 4 === 1) throw new Error("Длина base64url невозможна");
  const std = s.replace(/-/g, "+").replace(/_/g, "/")
    + "=".repeat((4 - (s.length % 4)) % 4);
  return base64ToBytes(std);
}

/** Разобрать запись `.jws`. Бросает, если она отличается от предписанной. */
export function parseDetachedJws(bytes: Uint8Array): DetachedJws {
  for (let i = 0; i < bytes.length; i++) {
    if (bytes[i] > 0x7f) throw new Error("Запись подписи содержит не-ASCII байт");
  }
  /* Циклом, а не раскрытием аргументов: предел раскрытия зависит от движка
     и от оставшейся глубины стека. Замер в Node 24 — около 124 000 при потолке
     записи 65 536, то есть запас меньше двукратного, а у других движков он
     исторически бывал ровно на нашем потолке. Браузерная копия и так собирает
     строку циклом; расходиться им здесь нельзя. */
  let text = "";
  for (let i = 0; i < bytes.length; i++) text += String.fromCharCode(bytes[i]);
  const at = text.indexOf("..");
  if (at <= 0) throw new Error("Запись подписи не похожа на компактный JWS");
  const protectedB64 = text.slice(0, at);
  const sigB64 = text.slice(at + 2);
  if (!/^[A-Za-z0-9_-]+$/.test(protectedB64) || !/^[A-Za-z0-9_-]+$/.test(sigB64)) {
    throw new Error("В записи подписи посторонние символы");
  }
  if (sigB64.length !== JWS_SIG_CHARS) {
    throw new Error("Подпись не 64 байта");
  }
  if (!JWS_SIG_TAIL.has(sigB64[sigB64.length - 1])) {
    throw new Error("Подпись записана неканонически — последние четыре бита не нулевые");
  }
  const header = JSON.parse(new TextDecoder("utf-8", { fatal: true })
    .decode(base64UrlToBytes(protectedB64))) as Record<string, unknown>;
  if (header === null || typeof header !== "object" || Array.isArray(header)) {
    throw new Error("Заголовок подписи не объект");
  }
  /* Отвергаем незнакомые члены заголовка — и это НЕ защита от кармана:
     заголовок целиком под подписью, положить туда что-то может только
     владелец ключа. Это политика принадлежности формату, а не проверка
     подлинности; см. раздел 2.0.8 спецификации. Отсюда и текст ошибки:
     «не наш пакет», а не «изменён». */
  const keys = Object.keys(header).sort();
  const withX5c = keys.join(",") === JWS_HEADER_KEYS.join(",");
  const withKid = keys.join(",") === JWS_HEADER_KEYS_KID.join(",");
  if (!withX5c && !withKid) {
    throw new Error("Заголовок подписи содержит не тот набор полей — это не пакет TrustVisor");
  }
  /* `alg` сверяется ДО того, как по нему что-либо выбирается: иначе
     классическая подмена алгоритма. `b64` обязан быть false — при true
     подписывались бы другие байты. `crit` требует RFC 7797, чтобы чужая
     реализация, не знающая про `b64`, отвергла файл, а не проверила его
     неправильно. */
  if (header.alg !== "ES256") throw new Error("Алгоритм подписи не ES256");
  if (header.b64 !== false) throw new Error("Нагрузка объявлена закодированной — ожидается b64:false");
  if (!Array.isArray(header.crit) || header.crit.length !== 1 || header.crit[0] !== "b64") {
    throw new Error("Поле crit обязано быть [\"b64\"]");
  }
  if (header.typ !== JWS_TYP) throw new Error("Тип подписи не наш");
  if (withKid) {
    const kid = header.kid;
    if (typeof kid !== "string" || !kid.length || kid.length > 64 || !/^[A-Za-z0-9._-]+$/.test(kid)) {
      throw new Error("Имя ключа подписи (kid) пусто или недопустимо");
    }
    /* Неизвестный kid отвергаем ЗДЕСЬ, а не молчаливой неудачей подписи:
       иначе «мы не знаем такого ключа» и «подпись не сошлась» слились бы в
       один вердикт ИЗМЕНЁН, и разобраться было бы нечем. */
    if (!Object.prototype.hasOwnProperty.call(TRUSTVISOR_WEB_SIGNING_KEYS, kid)) {
      throw new Error("Подпись сделана неизвестным нам ключом: " + kid);
    }
    return { protectedB64, signature: base64UrlToBytes(sigB64), x5c: [], kid };
  }
  const x5c = header.x5c;
  if (!Array.isArray(x5c) || x5c.length === 0
      || x5c.some((c) => typeof c !== "string" || c.length === 0)) {
    throw new Error("Цепочка аттестации в подписи пуста или испорчена");
  }
  return { protectedB64, signature: base64UrlToBytes(sigB64), x5c: x5c as string[] };
}

/**
 * Проверить отсоединённую подпись над сырыми байтами манифеста.
 *
 * Подписывается НЕ манифест сам по себе, а склейка
 * `ASCII(заголовок) · "." · байты манифеста` — так требует RFC 7797. Это
 * связывает заголовок с манифестом: подменить `alg` или цепочку `x5c`, не
 * сломав подпись, нельзя.
 *
 * Заголовок берётся КАК ЕСТЬ, строкой из записи. Пересобирать его из
 * разобранного объекта нельзя: порядок членов в JSON не гарантирован, и
 * пересборка дала бы другие байты.
 */
export async function verifyDetachedJws(
  jws: DetachedJws, manifestBytes: Uint8Array, pubKey: CryptoKey,
): Promise<boolean> {
  const head = new TextEncoder().encode(jws.protectedB64 + ".");
  const input = new Uint8Array(head.length + manifestBytes.length);
  input.set(head, 0);
  input.set(manifestBytes, head.length);
  return crypto.subtle.verify(
    { name: "ECDSA", hash: { name: "SHA-256" } }, pubKey,
    jws.signature as BufferSource, input as BufferSource);
}

/* Поля, которых в манифесте формата 2.0 быть НЕ должно. На их отсутствии
   стоит различение форматов: новый файл без записи `.jws` не пройдёт по
   старому правилу, потому что старое требует `signature` внутри манифеста.
   Если разрешить им сосуществовать, различение рассыплется. */
const V1_ONLY_FIELDS = ["signature", "signatureAlgorithm", "attestationChain"];

/** Два правила раздела 2.0.6: строгий UTF-8 и никаких повторов имён полей.
 *
 *  Судьёй работает `compactSignedPayloadFromRaw`: оба правила уже живут в ней,
 *  и она возвращает null ровно на их нарушении. Своей копии правил тут нет
 *  нарочно — два набора правил на одну спецификацию и есть то, из-за чего
 *  проверяльщики расходятся.
 *
 *  Прежде обе проверки работали только на пути 1.x, и манифест 2.0 с двумя
 *  одинаковыми именами полей проходил: разборщик брал последнее. */
export function assertManifestWellFormed(rawBytes: Uint8Array | undefined, label: string): void {
  if (!rawBytes) return;
  if (compactSignedPayloadFromRaw(rawBytes) === null) {
    throw new Error(
      label + ": манифест не отвечает разделу 2.0.6 — байты не являются действительным " +
      "UTF-8 при строгом декодировании либо имя поля верхнего уровня встречается дважды",
    );
  }
}

export function assertNoV1Fields(manifest: Record<string, unknown>): void {
  for (const f of V1_ONLY_FIELDS) {
    if (Object.prototype.hasOwnProperty.call(manifest, f)) {
      throw new Error("В манифесте формата 2.0 осталось поле " + f);
    }
  }
}

/* ── Восстановление подписанной формы манифеста из сырого текста ──────────
   Должно вести себя идентично браузерной копии:
   расхождение означало бы, что полка принимает файл, который сайт объявляет
   изменённым, или наоборот.

   Приложение подписывает json.toString() — компактный JSON без полей подписи,
   а на диск пишет отформатированный вариант, дописывая ПОСЛЕ подписания три
   поля: signature, signatureAlgorithm и attestationChain. Поэтому здесь
   убирается форматирование (числовые литералы и содержимое строк не
   трогаются: Java печатает 10.0, разбор и обратная сборка дали бы 10) и
   выбрасываются ровно эти три поля.
   Побочный эффект, ради которого всё и делалось: любое ЛИШНЕЕ поле,
   дописанное в файл, попадает в проверяемый payload и ломает подпись. */
const _CH_BACKSLASH = 92, _CH_QUOTE = 34, _CH_SPACE = 32, _CH_NL = 10, _CH_CR = 13, _CH_TAB = 9;

function _skipString(t: string, i: number): number {
  i++;
  while (i < t.length) {
    const c = t.charCodeAt(i);
    if (c === _CH_BACKSLASH) { i += 2; continue; }
    if (c === _CH_QUOTE) return i + 1;
    i++;
  }
  return -1;
}

function _skipValue(t: string, i: number): number {
  const c = t[i];
  if (t.charCodeAt(i) === _CH_QUOTE) return _skipString(t, i);
  if (c === "{" || c === "[") {
    const open = c, close = (c === "{") ? "}" : "]";
    let depth = 0;
    while (i < t.length) {
      if (t.charCodeAt(i) === _CH_QUOTE) { i = _skipString(t, i); if (i < 0) return -1; continue; }
      const ch = t[i];
      if (ch === open) depth++;
      else if (ch === close) { depth--; if (depth === 0) return i + 1; }
      i++;
    }
    return -1;
  }
  while (i < t.length && t[i] !== "," && t[i] !== "}" && t[i] !== "]") i++;
  return i;
}

function compactSignedPayloadFromRaw(rawBytes: Uint8Array | undefined | null): Uint8Array | null {
  if (!rawBytes || !rawBytes.length) return null;
  /* Декодируем СТРОГО и сами, а не полагаемся на уже готовую строку.

     Buffer.toString("utf-8") заменяет невалидный байт на U+FFFD молча, и тогда
     подделка с байтом 0xFF внутри неподписываемого поля даёт байт-в-байт тот же
     payload, что у оригинала. Браузер здесь всегда декодировал строго —
     расхождение шло отсюда. */
  let t: string;
  try {
    /* ignoreBOM — по той же причине, что и при показе: метку в начале не
       срезаем, иначе подписанная форма восстановится там, где не должна. */
    t = new TextDecoder("utf-8", { fatal: true, ignoreBOM: true }).decode(rawBytes);
  } catch {
    return null;
  }
  if (!t.length) return null;
  let flat = "", i = 0;
  while (i < t.length) {
    const code = t.charCodeAt(i);
    if (code === _CH_QUOTE) {
      const e = _skipString(t, i);
      if (e < 0) return null;
      flat += t.slice(i, e);
      i = e;
      continue;
    }
    if (code === _CH_SPACE || code === _CH_NL || code === _CH_CR || code === _CH_TAB) { i++; continue; }
    flat += t[i];
    i++;
  }
  if (flat[0] !== "{") return null;
  /* Служебные поля отбрасываются по СЫРЫМ байтам имени, а не по разобранному.
     Раньше сравнивался результат JSON.parse, и "signature" — та же буква
     «s», записанная экранированно, — считался тем же ключом: поле выпадало из
     подписанных байтов и при этом оставалось в разобранном объекте. Через него
     в файл с вердиктом ПОДЛИННО проходило до мегабайта неподписанных данных.
     Воспроизведено на настоящей съёмке 9 сентября 2026.

     Set, а не объект: у объекта ключи вроде constructor или toString находятся
     в прототипе, и такое поле молча выпадало бы из подписи. */
  const DROP = new Set(['"signature"', '"signatureAlgorithm"', '"attestationChain"']);
  const ALG_FIELD = /^"[A-Za-z0-9/._+-]{1,64}"$/;
  /* Повторяющееся имя поля — отказ. JSON с двумя одинаковыми ключами
     неоднозначен: разборщики расходятся в том, какой из них побеждает, а
     служебное поле, названное дважды, выпадало из подписи ОБА раза — и первое
     из них становилось карманом для произвольных байтов в файле с вердиктом
     ПОДЛИННО. Сравниваем разобранные имена: "signature" и та же строка в
     экранированном виде — это одно имя. Найдено 9 сентября 2026. */
  const seen = new Set<string>();
  let out = "{", first = true, j = 1;
  while (j < flat.length && flat[j] !== "}") {
    if (flat.charCodeAt(j) !== _CH_QUOTE) return null;
    const ks = j;
    j = _skipString(flat, j);
    if (j < 0) return null;
    const rawKey = flat.slice(ks, j);
    /* Разбираем ради двух вещей: отказать на неразбираемом ключе и поймать
       повтор. Что считать служебным полем, решают сырые байты ниже. */
    let decodedKey: unknown;
    try { decodedKey = JSON.parse(rawKey); } catch { return null; }
    if (typeof decodedKey !== "string" || seen.has(decodedKey)) return null;
    seen.add(decodedKey);
    if (flat[j] !== ":") return null;
    j++;
    const vs = j;
    j = _skipValue(flat, j);
    if (j < 0) return null;
    /* Карман в служебном поле. Три поля выброшены из подписи, значит их
       содержимое ею не покрыто, и границу задаёт только употребление. У
       `signature` мусор ломает проверку подписи, у `attestationChain` — разбор
       цепочки; проверено, оба дают ИЗМЕНЁН. У `signatureAlgorithm` границы не
       было никакой: к настоящей съёмке приклеивался мегабайт произвольных
       байтов, и вердикт оставался ПОДЛИННО. Найдено сторонним разбором 15
       сентября 2026, воспроизведено на samples/genuine-photo.trustvisor.
       Настоящее значение — SHA256withECDSA, пятнадцать знаков; в 77 манифестах
       настоящих съёмок другого не встречается. */
    if (rawKey === '"signatureAlgorithm"' && !ALG_FIELD.test(flat.slice(vs, j))) return null;
    if (!DROP.has(rawKey)) { if (!first) out += ","; out += flat.slice(ks, j); first = false; }
    if (flat[j] === ",") j++;
  }
  out += "}";
  return new TextEncoder().encode(out);
}

/* Подпись манифеста формата 1.x: только по сырым байтам, отката на
   реконструкцию нет. Отката не стало потому, что сборка payload по списку
   полей игнорирует неизвестные имена: манифест, который разбирается как JSON,
   но не проходит строгое декодирование UTF-8, проносил через неё дописанное
   поле. Настоящие файлы всегда дают непустой raw — проверено на 19 настоящих
   пакетах и на наборе стенда сверки.

   Порядок полей формата 1.x описан в спецификации, разделы 3.4–3.6. */
async function verifyManifestSig(
  which: string,
  manifest: Record<string, unknown>,
  pubKey: CryptoKey,
  rawBytes?: Uint8Array,
): Promise<boolean> {
  if (!manifest.signature) throw new Error("В манифесте " + which + " нет поля подписи");
  const sig = derToP1363(base64ToBytes(manifest.signature as string)) as BufferSource;
  const raw = compactSignedPayloadFromRaw(rawBytes);
  if (!raw) return false;
  return crypto.subtle.verify({ name: "ECDSA", hash: { name: "SHA-256" } }, pubKey, sig, raw as BufferSource);
}

export interface SensorStream {
  kind: number;
  axes: number;
  hz: number;
  count: number;
  rawCount: number;
  values: Int16Array;
}

/* Строгий разбор раскладки журнала (раздел 1.7 спецификации).

   Зачем вообще разбирать то, чего мы не истолковываем. Затем же, зачем
   сужен допустимый ZIP: два проверяльщика на разных библиотеках трижды
   расходились на пограничных файлах. Журнал даёт ту же поверхность — один
   нарисовал бы полосу по мусору, другой отказался бы, и один файл получил
   бы два разных ответа. Здесь раскладка проверяется по единственному
   описанию, и нечитаемый журнал одинаково не рисуется с обеих сторон.

   Разбор — не истолкование. Мы убеждаемся, что байты складываются в
   описанную структуру, и не делаем никаких выводов о самом движении.

   Возвращает null, если раскладка не сходится. Это НЕ «изменён»: хэш к
   этому моменту уже сошёлся, то есть байты те самые, что подписал телефон.
   Нечитаемый журнал означает лишь, что показать нечего. */
export function parseSensorLog(bytes: Uint8Array): SensorStream[] | null {
  const MAGIC = "TVSENS01";
  if (bytes.byteLength < 12) return null;
  for (let i = 0; i < 8; i++) {
    if (bytes[i] !== MAGIC.charCodeAt(i)) return null;
  }
  const streams = bytes[8];
  if (streams < 1 || streams > 4) return null;
  // Резерв обязан быть нулевым: три байта «на будущее» — это карман на три
  // байта, а карманы мы закрываем везде одинаково.
  if (bytes[9] !== 0 || bytes[10] !== 0 || bytes[11] !== 0) return null;

  const view = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
  const headerEnd = 12 + streams * 16;
  if (bytes.byteLength < headerEnd) return null;

  const heads: SensorStream[] = [];
  const seenKinds = new Set<number>();
  let payload = 0;
  for (let s = 0; s < streams; s++) {
    const o = 12 + s * 16;
    const kind = view.getUint8(o);
    const axes = view.getUint8(o + 1);
    const hz = view.getUint16(o + 2);
    const count = view.getUint32(o + 4);
    const rawCount = view.getUint32(o + 8);
    const byteLen = view.getUint32(o + 12);
    if (kind < 1 || kind > 4) return null;
    // Два потока одного вида — это два разных ответа на вопрос «а как
    // двигался телефон»; который из них показывать, решать было бы нам.
    if (seenKinds.has(kind)) return null;
    seenKinds.add(kind);
    const wantAxes = kind === 4 ? 1 : 3;
    if (axes !== wantAxes) return null;
    if (hz < 1 || hz > 1000) return null;
    if (byteLen !== count * axes * 2) return null;
    payload += byteLen;
    heads.push({ kind, axes, hz, count, rawCount, values: new Int16Array(0) });
  }
  /* Длина обязана сойтись РОВНО, как у блоков подписи в медиа (раздел 1.6):
     «не меньше» оставило бы в конце журнала карман для произвольных байтов
     внутри файла с вердиктом ПОДЛИННО. */
  if (headerEnd + payload !== bytes.byteLength) return null;

  let p = headerEnd;
  for (const h of heads) {
    const n = h.count * h.axes;
    const v = new Int16Array(n);
    for (let i = 0; i < n; i++) v[i] = view.getInt16(p + i * 2);
    h.values = v;
    p += n * 2;
  }
  return heads;
}

/* Журнал датчиков: связь «манифест ⟺ запись», обе стороны.

   Зачем проверять ОТСУТСТВИЕ. Без второй половины правила журнал стал бы
   карманом: к честному файлу дописывается `sensors.bin`, манифест о ней
   молчит, подпись цела — и произвольные байты едут внутри пакета с
   вердиктом ПОДЛИННО. Тот же карман мы уже закрывали в блоках подписи медиа
   (раздел 1.6 спецификации), здесь он закрыт сразу.

   Зачем вызывать ПОСЛЕ проверки подписи. Правило опирается на поле
   манифеста; если бы оно применялось до криптографии, нападающему хватило
   бы стереть поле, чтобы разрешить себе любой журнал. После проверки
   стереть поле нельзя — подпись уже не сойдётся.

   Несовпадение хэша — это `fail`, то есть ИЗМЕНЁН, как у `photoSha256`.
   Исключения здесь быть не может: правило «всё, что покрыто подписью,
   сходится» с дырой перестаёт быть правилом. */
export async function checkSensorLog(
  manifest: Record<string, unknown>,
  bytes: Uint8Array | undefined,
): Promise<NamedCheck> {
  const declared: unknown = manifest.sensorLogSha256;
  if (declared === undefined) {
    if (bytes) {
      /* Именно PackageRejectedError, а не обычный Error: маршруты портала ловят
         только его. С обычным пакет получал общее «не удалось проверить», а
         оператор читал «файл битый, попросите оригинал» вместо настоящей
         причины. Раздел 1.5 спецификации требует называть причину. */
      throw new PackageRejectedError(
        "Пакет содержит журнал датчиков sensors.bin, которого нет в подписанном манифесте. " +
        "Подписан только заявленный набор — остальное к доказательству отношения не имеет",
      );
    }
    return { state: "skip", msg: "Журнал датчиков не велся" };
  }
  if (typeof declared !== "string") {
    return { state: "fail", msg: "Поле журнала датчиков в манифесте испорчено" };
  }
  if (!bytes) {
    return { state: "fail", msg: "Манифест объявляет журнал датчиков, но записи sensors.bin в пакете нет" };
  }
  const actual = await sha256Bytes(toPlainArrayBuffer(bytes));
  if (actual !== declared.toLowerCase()) {
    return { state: "fail", msg: "Журнал датчиков — НЕСООТВЕТСТВИЕ хэша" };
  }
  /* Хэш сошёлся — байты те самые. Осталось убедиться, что они складываются
     в описанную раскладку: нечитаемый журнал показывать нечем, и обе
     стороны обязаны отказаться от показа одинаково.

     Это `warn`, а не `fail`: доказательство цело, испорчена только
     необязательная добавка. В `downgradeReasonsOf` имя `sensorLog` не
     значится, поэтому вердикт не меняется вовсе — так и задумано. */
  if (!parseSensorLog(bytes)) {
    return { state: "warn", msg: "Журнал датчиков цел по хэшу, но его раскладка не читается — показывать нечего" };
  }
  const cut = manifest.sensorLogTruncated === true;
  return {
    state: "pass",
    truncated: cut,
    msg: cut
      ? "Журнал датчиков цел; покрывает начало съёмки — дальше остановлен по объёму"
      : "Журнал датчиков цел",
  };
}

/* Байты журнала приходят подмассивом чужого буфера, и `bytes.buffer` у
   такого подмассива — весь исходный буфер целиком. Хэш от него не имел бы
   отношения к журналу. Поэтому копия по границам подмассива. */
function toPlainArrayBuffer(bytes: Uint8Array): ArrayBuffer {
  return bytes.buffer.slice(bytes.byteOffset, bytes.byteOffset + bytes.byteLength) as ArrayBuffer;
}

async function sha256Bytes(arrayBuffer: ArrayBuffer): Promise<string> {
  return bufToHex(await crypto.subtle.digest("SHA-256", arrayBuffer));
}

/* Разбор одного элемента DER (тег-длина-значение).
 *
 * Прежняя версия считала длину так: len = (len << 8) | buf[p++]. Оператор <<
 * в JavaScript работает с 32-битным ЗНАКОВЫМ числом, поэтому длина
 * 0xFFFFFFFF превращалась в -1, а 0x7FFFFFFF — в два гигабайта. Ни то ни
 * другое не отвергалось.
 *
 * Отрицательная длина опаснее, чем кажется: slice(начало, конец) при конце
 * меньше начала отдаёт ПУСТОЙ массив, а не ошибку. Дальше по коду пустые
 * байты издателя и субъекта сравнивались между собой и признавались
 * совпадающими — то есть структурная проверка цепочки проходила вхолостую,
 * ничего на самом деле не сравнив.
 *
 * Теперь любая ненормальная длина — это отказ разбора, а не тихо пустой
 * результат. Все проверки ниже по коду обязаны иметь дело либо с настоящими
 * байтами, либо с ошибкой.
 */
export function derTLV(buf: Uint8Array, offset: number): { tag: number; valueStart: number; end: number } {
  let p = offset;
  if (p < 0 || p + 2 > buf.length) throw new Error("DER: элемент выходит за границы данных");
  const tag = buf[p++];
  let len = buf[p++];
  if (len & 0x80) {
    const nb = len & 0x7f;
    /* Неопределённая длина (nb === 0) в DER запрещена; больше 4 байт длины
       означало бы элемент свыше 4 ГБ — в наших данных такого быть не может. */
    if (nb === 0 || nb > 4) throw new Error("DER: недопустимая форма длины");
    if (p + nb > buf.length) throw new Error("DER: длина обрывается за границей данных");
    len = 0;
    /* Умножение вместо сдвига: сдвиг в JavaScript знаковый и 32-битный,
       именно он и превращал 0xFFFFFFFF в -1. */
    for (let i = 0; i < nb; i++) len = len * 256 + buf[p++];
  }
  if (!Number.isSafeInteger(len) || len < 0) throw new Error("DER: некорректная длина");
  const end = p + len;
  if (end > buf.length) throw new Error("DER: значение выходит за границы данных");
  return { tag, valueStart: p, end };
}

function parseCertForVerify(der: Uint8Array): { tbsBytes: Uint8Array; sigAlgOid: number[]; sigBytes: Uint8Array; spkiBytes: Uint8Array } {
  let p = 0;
  const cert = derTLV(der, p);
  // Сертификат обязан быть SEQUENCE. Внешний тег не покрыт ни одной подписью,
  // поэтому без этой проверки его подмена проходила незамеченной.
  if (cert.tag !== 0x30) throw new Error("DER: сертификат не является SEQUENCE");
  /* Разбор обязан израсходовать сертификат целиком. Иначе после
     закрывающего SEQUENCE можно дописать что угодно: подпись покрывает
     только TBS, отпечатком проверяется лишь последнее звено цепочки, а
     остальные принимали хвост молча. Проверено 9 сентября 2026: 24 байта
     текста после SEQUENCE у любого звена, кроме корня, давали ПОДЛИННО. */
  if (cert.end !== der.length) throw new Error("DER: после сертификата остались лишние байты");
  p = cert.valueStart;
  const tbsStart = p;
  const tbs = derTLV(der, p);
  p = tbs.end;
  const tbsBytes = der.slice(tbsStart, tbs.end);
  const sigAlg = derTLV(der, p);
  const oidTlv = derTLV(der, sigAlg.valueStart);
  const sigAlgOid = Array.from(der.slice(oidTlv.valueStart, oidTlv.end));
  p = sigAlg.end;
  const sigBits = derTLV(der, p);
  /* Разбор обязан израсходовать сертификат ИЗНУТРИ тоже.

     9 сентября закрыли хвост ПОСЛЕ внешнего SEQUENCE. Внутри него, после
     BIT STRING подписи, не проверялось ничего: подпись покрывает только
     TBS, отпечатком сверяется лишь последнее звено цепочки, а в формате
     1.x цепочка вообще не входит в подписанные байты. Замер: 13 200 байт
     произвольного текста, дописанных внутрь трёх звеньев из четырёх,
     давали вердикт ПОДЛИННО. */
  if (sigBits.end !== cert.end) throw new Error("DER: внутри сертификата остались лишние байты");
  const sigBytes = der.slice(sigBits.valueStart + 1, sigBits.end);
  let tp = tbs.valueStart;
  if (der[tp] === 0xa0) {
    const t = derTLV(der, tp);
    tp = t.end;
  }
  for (let i = 0; i < 5; i++) {
    const t = derTLV(der, tp);
    tp = t.end;
  }
  const spkiStart = tp;
  const spki = derTLV(der, tp);
  const spkiBytes = der.slice(spkiStart, spki.end);
  return { tbsBytes, sigAlgOid, sigBytes, spkiBytes };
}

// Разбор расширения Android Keystore (OID 1.3.6.1.4.1.11129.2.1.17)
const _AKS_OID = [0x2b, 0x06, 0x01, 0x04, 0x01, 0xd6, 0x79, 0x02, 0x01, 0x11];
function _derInt(buf: Uint8Array, tlv: { valueStart: number; end: number }): number {
  let v = 0;
  for (let i = tlv.valueStart; i < tlv.end; i++) v = v * 256 + (buf[i] & 0xff);
  return v;
}

// derTLV выше читает тег одним байтом — этого хватает для всех структурных
// тегов X.509, которые здесь разбираются. Но в списке разрешений Android
// Keystore (softwareEnforced и teeEnforced внутри KeyDescription) номера тегов
// часто больше тридцати: у ROOT_OF_TRUST он равен 704, а такой номер DER
// умеет записать только многобайтовой формой. Разбор вынесен в отдельную
// функцию, а не добавлен в derTLV: новый и реже используемый путь не должен
// иметь возможности изменить поведение там, где разбор уже работает верно.
function _tlvHighTag(buf: Uint8Array, offset: number): { tagNumber: number; valueStart: number; end: number } {
  let p = offset;
  if (p < 0 || p + 2 > buf.length) throw new Error("DER: элемент выходит за границы данных");
  const first = buf[p++];
  let tagNumber: number;
  if ((first & 0x1f) !== 0x1f) {
    tagNumber = first & 0x1f;
  } else {
    // Умножение вместо сдвига — по той же причине, что в derTLV. Ограничение
    // на длину номера тега страхует от бесконечного чтения продолжений.
    tagNumber = 0;
    let guard = 0;
    while (p < buf.length && buf[p] & 0x80) {
      tagNumber = tagNumber * 128 + (buf[p] & 0x7f);
      p++;
      if (++guard > 5) throw new Error("DER: слишком длинный номер тега");
    }
    if (p >= buf.length) throw new Error("DER: номер тега обрывается за границей данных");
    tagNumber = tagNumber * 128 + (buf[p] & 0x7f);
    p++;
  }
  if (p >= buf.length) throw new Error("DER: длина отсутствует");
  let len = buf[p++];
  if (len & 0x80) {
    const nb = len & 0x7f;
    if (nb === 0 || nb > 4) throw new Error("DER: недопустимая форма длины");
    if (p + nb > buf.length) throw new Error("DER: длина обрывается за границей данных");
    len = 0;
    for (let i = 0; i < nb; i++) len = len * 256 + buf[p++];
  }
  const end = p + len;
  if (!Number.isSafeInteger(len) || len < 0 || end > buf.length)
    throw new Error("DER: значение выходит за границы данных");
  return { tagNumber, valueStart: p, end };
}

const ROOT_OF_TRUST_TAG = 704; // KM_TAG_ROOT_OF_TRUST
const VERIFIED_BOOT_STATE_NAMES: Record<number, string> = {
  0: "Verified", 1: "SelfSigned", 2: "Unverified", 3: "Failed",
};
export interface RootOfTrust {
  deviceLocked: boolean;
  verifiedBootState: number;
  verifiedBootStateName: string;
}
// Идёт по списку разрешений teeEnforced и ищет ROOT_OF_TRUST. Он есть не у
// всех: устройство должно быть достаточно новым и сообщать состояние загрузки
// на аппаратном уровне. Поэтому его отсутствие само по себе не подозрительно —
// checkRootOfTrust в этом случае пропускает проверку. Остальные записи
// перешагиваются по их собственной длине и не разбираются вовсе: понимать
// каждый тег списка не требуется, нужен только этот.
function _findRootOfTrust(buf: Uint8Array, seqValueStart: number, seqValueEnd: number): RootOfTrust | null {
  let p = seqValueStart;
  while (p < seqValueEnd) {
    const entry = _tlvHighTag(buf, p);
    if (entry.tagNumber === ROOT_OF_TRUST_TAG) {
      // Значение записи — обёртка ровно вокруг одного элемента: структуры
      // RootOfTrust (ключ verified boot, признак блокировки загрузчика,
      // состояние verified boot и далее). Её внешний тег — обычный SEQUENCE,
      // так что здесь достаточно однобайтового derTLV.
      const rotSeq = derTLV(buf, entry.valueStart);
      let rp = rotSeq.valueStart;
      const vbk = derTLV(buf, rp);
      rp = vbk.end;
      const dl = derTLV(buf, rp);
      const deviceLocked = buf[dl.valueStart] !== 0x00;
      rp = dl.end;
      const vbs = derTLV(buf, rp);
      const verifiedBootState = buf[vbs.valueStart];
      return {
        deviceLocked, verifiedBootState,
        verifiedBootStateName: VERIFIED_BOOT_STATE_NAMES[verifiedBootState] ?? String(verifiedBootState),
      };
    }
    p = entry.end;
  }
  return null;
}

/* ── Привязка ключа к НАШЕМУ приложению (порт с браузерного верификатора) ──
   Аппаратная аттестация доказывает «ключ рождён в защищённом чипе», но не
   доказывает, каким приложением. Без этой проверки ключ, созданный чужим
   приложением на обычном стоковом телефоне, давал здесь вердикт «подлинно»,
   и подделка попадала на полку как настоящая съёмка — при том, что публичный
   верификатор на сайте её уже отвергал. Расхождение двух верификаторов
   недопустимо: полка не должна принимать то, что сайт объявляет подделкой. */
const TV_PACKAGE_NAME = "ru.trustvisor.app";
const ATTESTATION_APP_ID_TAG = 709;
const KEY_ORIGIN_TAG = 702;
/* Google Play переподписывает приложение своим ключом, поэтому у сборки из
   магазина отпечаток другой, чем у APK, собранного нами напрямую. */
const TV_SIGNING_DIGESTS = [
  "b175ead1e2223c37072746a4ffbc43836c1e743d3c81020bb6128f1e83183152", // ключ загрузки (APK напрямую)
  "2ef778b9d6c032c9701fbdbc3029c02c3618c463e48cd45f37661b562f23f9ac", // ключ подписи Google Play
];

interface AttestationAppId {
  packages: string[];
  digests: string[];
}

function _findTag(buf: Uint8Array, start: number, end: number, tagNumber: number): { valueStart: number; end: number } | null {
  let p = start;
  while (p < end) {
    const entry = _tlvHighTag(buf, p);
    if (entry.tagNumber === tagNumber) return { valueStart: entry.valueStart, end: entry.end };
    p = entry.end;
  }
  return null;
}

/* AttestationApplicationId ::= SEQUENCE {
     package_infos     SET OF SEQUENCE { package_name OCTET STRING, version INTEGER },
     signature_digests SET OF OCTET STRING } */
function _parseAppId(buf: Uint8Array, valueStart: number): AttestationAppId | null {
  try {
    const octet = derTLV(buf, valueStart);
    const blob = buf.slice(octet.valueStart, octet.end);
    const seq = derTLV(blob, 0);
    const pkgSet = derTLV(blob, seq.valueStart);
    const packages: string[] = [];
    let q = pkgSet.valueStart;
    while (q < pkgSet.end) {
      const info = derTLV(blob, q);
      const nameT = derTLV(blob, info.valueStart);
      packages.push(new TextDecoder().decode(blob.slice(nameT.valueStart, nameT.end)));
      q = info.end;
    }
    const digSet = derTLV(blob, pkgSet.end);
    const digests: string[] = [];
    let r = digSet.valueStart;
    while (r < digSet.end) {
      const d = derTLV(blob, r);
      digests.push(bufToHex(blob.slice(d.valueStart, d.end)));
      r = d.end;
    }
    return { packages, digests };
  } catch {
    return null;
  }
}

interface KeyDescription {
  attestationVersion: number;
  attestationSecLevel: number;
  keymasterVersion: number;
  keymasterSecLevel: number;
  challenge: string;
  attSecName: string;
  kmSecName: string;
  rootOfTrust: RootOfTrust | null;
  appId: AttestationAppId | null;
  keyOrigin: number | null;
}
function _parseKeyDesc(buf: Uint8Array): KeyDescription {
  const SEQ = derTLV(buf, 0);
  let p = SEQ.valueStart;
  const avT = derTLV(buf, p);
  p = avT.end;
  const attestationVersion = _derInt(buf, avT);
  const asT = derTLV(buf, p);
  p = asT.end;
  const attestationSecLevel = buf[asT.valueStart];
  const kvT = derTLV(buf, p);
  p = kvT.end;
  const keymasterVersion = _derInt(buf, kvT);
  const ksT = derTLV(buf, p);
  p = ksT.end;
  const keymasterSecLevel = buf[ksT.valueStart];
  const chT = derTLV(buf, p);
  p = chT.end;
  const challenge = new TextDecoder().decode(buf.slice(chT.valueStart, chT.end));
  const SL: Record<number, string> = { 0: "Software", 1: "TrustedEnvironment (TEE)", 2: "StrongBox" };
  // Сначала uniqueId, затем softwareEnforced. Ни то ни другое здесь не нужно:
  // оба перешагиваются по собственной длине, чтобы добраться до teeEnforced —
  // там и лежит ROOT_OF_TRUST ключа, созданного в чипе.
  let rootOfTrust: RootOfTrust | null = null;
  let appId: AttestationAppId | null = null;
  let keyOrigin: number | null = null;
  try {
    const uidT = derTLV(buf, p);
    p = uidT.end;
    const swT = derTLV(buf, p);
    p = swT.end;
    const teeT = derTLV(buf, p);
    /* Порядок полей и поведение catch ОБЯЗАНЫ совпадать с браузерным
       копией. Здесь они расходились:
       сервер разбирал appId первым, а при ошибке обнулял только rootOfTrust —
       значит appId выживал. Браузер разбирал rootOfTrust первым и при ошибке
       обнулял всё. Пока derTLV не бросал ошибок, разницы не было; после
       укрепления разбора она появилась, и на одном файле сервер говорил бы
       ПОДЛИННО, а сайт НЕ АТТЕСТОВАНО.

       Выровнено по браузеру: при непонятном разборе верификатор закрывается
       целиком, а не досказывает по уцелевшим полям.

       Идентификатор приложения лежит в softwareEnforced (тег 709),
       происхождение ключа — в teeEnforced (тег 702, 0 = создан в чипе).

       Разница между двумя разделами существенна, и мы говорим о ней прямо.
       `teeEnforced` заполняет сам чип. `softwareEnforced` заполняет
       операционная система — значит на телефоне с полученными правами
       суперпользователя утверждение «подписано приложением TrustVisor»
       подделывается. Дырой это не становится: состояние загрузчика приходит
       из teeEnforced, и такой телефон ловится по нему (checkRootOfTrust). Но
       читателю надо знать, какое из двух утверждений крепче. */
    rootOfTrust = _findRootOfTrust(buf, teeT.valueStart, teeT.end);
    const appT = _findTag(buf, swT.valueStart, swT.end, ATTESTATION_APP_ID_TAG);
    if (appT) appId = _parseAppId(buf, appT.valueStart);
    const orgT = _findTag(buf, teeT.valueStart, teeT.end, KEY_ORIGIN_TAG);
    if (orgT) { const oi = derTLV(buf, orgT.valueStart); keyOrigin = buf[oi.valueStart]; }
  } catch {
    rootOfTrust = null;
    appId = null;
    keyOrigin = null;
  }
  return {
    appId,
    keyOrigin,
    attestationVersion, attestationSecLevel, keymasterVersion, keymasterSecLevel, challenge, rootOfTrust,
    attSecName: SL[attestationSecLevel] || String(attestationSecLevel),
    kmSecName: SL[keymasterSecLevel] || String(keymasterSecLevel),
  };
}
export function parseAndroidKeystoreExt(leafDer: Uint8Array): KeyDescription | null {
  try {
    const cert = derTLV(leafDer, 0);
    /* И здесь до конца: разбор расширения аттестации не должен принимать
       сертификат, который два других разборщика уже отвергнут. */
    if (cert.end !== leafDer.length) return null;
    const tbs = derTLV(leafDer, cert.valueStart);
    let tp = tbs.valueStart;
    if (leafDer[tp] === 0xa0) {
      const t = derTLV(leafDer, tp);
      tp = t.end;
    }
    for (let i = 0; i < 6; i++) {
      const t = derTLV(leafDer, tp);
      tp = t.end;
    }
    if (leafDer[tp] === 0x81) {
      const t = derTLV(leafDer, tp);
      tp = t.end;
    }
    if (leafDer[tp] === 0x82) {
      const t = derTLV(leafDer, tp);
      tp = t.end;
    }
    if (tp >= tbs.end || leafDer[tp] !== 0xa3) return null;
    const extsOut = derTLV(leafDer, tp);
    const extsSEQ = derTLV(leafDer, extsOut.valueStart);
    let ep = extsSEQ.valueStart;
    while (ep < extsSEQ.end) {
      const ext = derTLV(leafDer, ep);
      let fp = ext.valueStart;
      const oidTlv = derTLV(leafDer, fp);
      if (oidTlv.tag !== 0x06) {
        ep = ext.end;
        continue;
      }
      const oid = Array.from(leafDer.slice(oidTlv.valueStart, oidTlv.end));
      fp = oidTlv.end;
      if (oid.length === _AKS_OID.length && _AKS_OID.every((b, i) => b === oid[i])) {
        if (leafDer[fp] === 0x01) {
          const t = derTLV(leafDer, fp);
          fp = t.end;
        }
        const extnVal = derTLV(leafDer, fp);
        return _parseKeyDesc(leafDer.slice(extnVal.valueStart, extnVal.end));
      }
      ep = ext.end;
    }
    return null;
  } catch {
    return null;
  }
}

function parseCurveFromSpki(spkiBytes: Uint8Array): { curve: string; componentLen: number } {
  const outer = derTLV(spkiBytes, 0);
  const algId = derTLV(spkiBytes, outer.valueStart);
  const algOid = derTLV(spkiBytes, algId.valueStart);
  const curveT = derTLV(spkiBytes, algOid.end);
  const oid = Array.from(spkiBytes.slice(curveT.valueStart, curveT.end));
  const eq = (ref: number[]) => oid.length === ref.length && ref.every((b, i) => b === oid[i]);
  if (eq([0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07])) return { curve: "P-256", componentLen: 32 };
  if (eq([0x2b, 0x81, 0x04, 0x00, 0x22])) return { curve: "P-384", componentLen: 48 };
  if (eq([0x2b, 0x81, 0x04, 0x00, 0x23])) return { curve: "P-521", componentLen: 66 };
  throw new Error("Аттестация: неизвестный OID эллиптической кривой " + oid.map((b) => b.toString(16).padStart(2, "0")).join(":"));
}

async function importCertPublicKey(spkiBytes: Uint8Array, sigAlgOid: number[]): Promise<{ key: CryptoKey; componentLen: number }> {
  const isRSA = sigAlgOid[0] === 0x2a && sigAlgOid[1] === 0x86 && sigAlgOid[2] === 0x48 && sigAlgOid[3] === 0x86 && sigAlgOid[4] === 0xf7 && sigAlgOid[5] === 0x0d && sigAlgOid[6] === 0x01 && sigAlgOid[7] === 0x01;
  const isEC = sigAlgOid[0] === 0x2a && sigAlgOid[1] === 0x86 && sigAlgOid[2] === 0x48 && sigAlgOid[3] === 0xce && sigAlgOid[4] === 0x3d;
  if (isRSA) {
    const hash = sigAlgOid[8] === 0x0c ? "SHA-384" : "SHA-256";
    const key = await crypto.subtle.importKey("spki", spkiBytes as BufferSource, { name: "RSASSA-PKCS1-v1_5", hash }, false, ["verify"]);
    return { key, componentLen: 0 };
  }
  if (isEC) {
    const { curve, componentLen } = parseCurveFromSpki(spkiBytes);
    const key = await crypto.subtle.importKey("spki", spkiBytes as BufferSource, { name: "ECDSA", namedCurve: curve }, false, ["verify"]);
    return { key, componentLen };
  }
  throw new Error("Аттестация: неподдерживаемый OID алгоритма подписи " + sigAlgOid.map((b) => b.toString(16).padStart(2, "0")).join(":"));
}

function certDerToP1363(der: Uint8Array, componentLen: number): Uint8Array {
  let p = 0;
  if (der[p++] !== 0x30) throw new Error("Подпись сертификата: ожидался SEQUENCE");
  /* Длину внешнего SEQUENCE раньше читали и не использовали. Из-за этого
     подпись можно было перекодировать — сменить форму длины, объявить её
     больше и дописать хвост, — а вердикт не менялся. Теперь она обязана
     точно покрывать r и s и заканчиваться на конце данных. */
  let seqLen = der[p++];
  if (seqLen & 0x80) {
    const nb = seqLen & 0x7f;
    if (nb === 0 || nb > 4) throw new Error("Подпись сертификата: недопустимая форма длины");
    if (p + nb > der.length) throw new Error("Подпись сертификата: длина обрывается за границей данных");
    seqLen = 0;
    for (let i = 0; i < nb; i++) seqLen = seqLen * 256 + der[p++];
  }
  const seqEnd = p + seqLen;
  if (!Number.isSafeInteger(seqEnd) || seqEnd !== der.length)
    throw new Error("Подпись сертификата: длина не совпадает с размером данных");
  function readInt(): Uint8Array {
    if (der[p++] !== 0x02) throw new Error("Подпись сертификата: ожидался INTEGER");
    /* Длина здесь короткой формы по определению: r и s кривой P-256
       не длиннее 33 байт. Всё остальное — не наша подпись. */
    const len = der[p++];
    if (len & 0x80) throw new Error("Подпись сертификата: недопустимая форма длины");
    if (p + len > seqEnd) throw new Error("Подпись сертификата: число выходит за границы");
    const val = der.slice(p, p + len);
    p += len;
    return val[0] === 0x00 ? val.slice(1) : val;
  }
  const r = readInt(),
    s = readInt();
  if (p !== seqEnd) throw new Error("DER: в подписи остались лишние байты");
  const out = new Uint8Array(componentLen * 2);
  const rTrim = r.length > componentLen ? r.slice(r.length - componentLen) : r;
  const sTrim = s.length > componentLen ? s.slice(s.length - componentLen) : s;
  out.set(rTrim, componentLen - rTrim.length);
  out.set(sTrim, componentLen * 2 - sTrim.length);
  return out;
}

async function verifyCertLink(certBytes: Uint8Array, parentCertBytes: Uint8Array): Promise<boolean> {
  const child = parseCertForVerify(certBytes);
  const parent = parseCertForVerify(parentCertBytes);
  const { key, componentLen } = await importCertPublicKey(parent.spkiBytes, child.sigAlgOid);
  const isRSA = child.sigAlgOid[0] === 0x2a && child.sigAlgOid[7] === 0x01;
  if (isRSA) return crypto.subtle.verify({ name: "RSASSA-PKCS1-v1_5" }, key, child.sigBytes as BufferSource, child.tbsBytes as BufferSource);
  const p1363 = certDerToP1363(child.sigBytes, componentLen);
  const ecLast = child.sigAlgOid[child.sigAlgOid.length - 1];
  const hash = ecLast === 0x04 ? "SHA-512" : ecLast === 0x03 ? "SHA-384" : "SHA-256";
  return crypto.subtle.verify({ name: "ECDSA", hash }, key, p1363 as BufferSource, child.tbsBytes as BufferSource);
}

/* ── Структурная проверка цепочки аттестации (порт с браузерного верификатора) ──
   Без неё проверялись ТОЛЬКО подписи звеньев, а этого мало: сертификат обычного
   телефона (CA:FALSE) можно было использовать как промежуточный. То есть взять
   любой Android, настоящим ключом из чипа подписать самодельный «сертификат» с
   любыми заявлениями (StrongBox, заблокированный загрузчик, свой публичный
   ключ), приложить настоящий хвост цепочки Google — и получить на полке
   вердикт «подлинная съёмка». Дальше подделки штампуются офлайн без телефона.
   Браузерный верификатор это закрыл; здесь тот же код. */

interface CertMeta {
  /* Серийный номер в том виде, в каком его ключует список отзыва Google:
     шестнадцатерично, нижний регистр, без ведущих нулей. */
  serialHex: string | null;
  issuerBytes: Uint8Array;
  subjectBytes: Uint8Array;
  isCA: boolean;
  keyCertSign: boolean | null;
  notBefore: number | null;
  notAfter: number | null;
}

function _bytesEq(a: Uint8Array | null, b: Uint8Array | null): boolean {
  /* Пустое НЕ равно пустому. Здесь этой функцией сверяют издателя одного
     сертификата с субъектом следующего; если оба разобрались в пустоту (а
     это случалось при кривой длине DER), «совпадение» означало бы, что
     проверка прошла, ничего не сравнив. Пустой издатель или субъект — сам
     по себе повод не доверять цепочке. */
  if (!a || !b || a.length === 0 || b.length === 0 || a.length !== b.length) return false;
  for (let i = 0; i < a.length; i++) if (a[i] !== b[i]) return false;
  return true;
}

/** UTCTime (YYMMDDHHMMSSZ) и GeneralizedTime (YYYYMMDDHHMMSSZ) → мс epoch */
function _derTime(buf: Uint8Array, t: { valueStart: number; end: number }): number | null {
  const str = new TextDecoder().decode(buf.slice(t.valueStart, t.end));
  const m =
    str.match(/^(\d{2})(\d{2})(\d{2})(\d{2})(\d{2})(\d{2})?Z$/) ||
    str.match(/^(\d{4})(\d{2})(\d{2})(\d{2})(\d{2})(\d{2})?Z$/);
  if (!m) return null;
  let y = parseInt(m[1], 10);
  if (m[1].length === 2) y = y >= 50 ? 1900 + y : 2000 + y;
  return Date.UTC(y, parseInt(m[2], 10) - 1, parseInt(m[3], 10), parseInt(m[4], 10), parseInt(m[5], 10), parseInt(m[6] || "0", 10));
}

export function parseCertMeta(der: Uint8Array): CertMeta {
  const cert = derTLV(der, 0);
  /* Тот же счёт до конца, что и в parseCertForVerify: разбор структуры
     цепочки обязан быть не мягче разбора для проверки подписи. */
  if (cert.end !== der.length) throw new Error("DER: после сертификата остались лишние байты");
  const tbs = derTLV(der, cert.valueStart);
  let tp = tbs.valueStart;
  if (der[tp] === 0xa0) { const t = derTLV(der, tp); tp = t.end; }        /* version */
  let serialHex: string | null = null;
  {
    /* Серийный номер — целое со старшим байтом первым; ведущий 0x00 ставится
       только чтобы число осталось положительным, и в ключе списка его нет. */
    const t = derTLV(der, tp);
    let s = "";
    for (let k = t.valueStart; k < t.end; k++) s += (der[k] < 16 ? "0" : "") + der[k].toString(16);
    s = s.replace(/^0+/, "");
    serialHex = s.length ? s : "0";
    tp = t.end;
  }
  { const t = derTLV(der, tp); tp = t.end; }                              /* signature alg */
  const issStart = tp; { const t = derTLV(der, tp); tp = t.end; }
  const issuerBytes = der.slice(issStart, tp);
  let notBefore: number | null = null, notAfter: number | null = null;
  {
    const v = derTLV(der, tp);
    try {
      const nb = derTLV(der, v.valueStart); notBefore = _derTime(der, nb);
      const na = derTLV(der, nb.end); notAfter = _derTime(der, na);
    } catch { notBefore = null; notAfter = null; }
    tp = v.end;
  }
  const subStart = tp; { const t = derTLV(der, tp); tp = t.end; }
  const subjectBytes = der.slice(subStart, tp);
  { const t = derTLV(der, tp); tp = t.end; }                              /* SPKI */
  let isCA = false, keyCertSign: boolean | null = null;
  while (tp < tbs.end) {
    const t = derTLV(der, tp);
    if (der[tp] === 0xa3) {                                               /* [3] extensions */
      const extSeq = derTLV(der, t.valueStart);
      let ep = extSeq.valueStart;
      while (ep < extSeq.end) {
        const ext = derTLV(der, ep);
        const oid = derTLV(der, ext.valueStart);
        const o = der.slice(oid.valueStart, oid.end);
        let q = oid.end;
        if (der[q] === 0x01) { const c = derTLV(der, q); q = c.end; }      /* critical */
        const val = derTLV(der, q);
        if (o.length === 3 && o[0] === 0x55 && o[1] === 0x1d && o[2] === 0x13) {   /* basicConstraints */
          const bc = derTLV(der, val.valueStart);
          if (bc.valueStart < bc.end && der[bc.valueStart] === 0x01) {
            const b = derTLV(der, bc.valueStart);
            isCA = der[b.valueStart] !== 0x00;
          }
        }
        if (o.length === 3 && o[0] === 0x55 && o[1] === 0x1d && o[2] === 0x0f) {   /* keyUsage */
          const bits = derTLV(der, val.valueStart);
          keyCertSign = !!(der[bits.valueStart + 1] & 0x04);
        }
        ep = ext.end;
      }
    }
    tp = t.end;
  }
  return { serialHex, issuerBytes, subjectBytes, isCA, keyCertSign, notBefore, notAfter };
}

export async function verifyAttestationChain(chainB64: string[]): Promise<boolean> {
  if (!chainB64 || chainB64.length < 2) throw new Error("Цепочка аттестации слишком коротка: нужно не меньше двух сертификатов");
  const certs = chainB64.map((b64) => base64ToBytes(b64.replace(/\s+/g, "")));
  for (let i = 0; i < certs.length - 1; i++) {
    const ok = await verifyCertLink(certs[i], certs[i + 1]);
    if (!ok) throw new Error("Звено цепочки аттестации " + i + "→" + (i + 1) + ": подпись не сходится");
  }
  const chainFps = await Promise.all(certs.map(async (der) => bufToHex(await crypto.subtle.digest("SHA-256", der as BufferSource))));
  const allKnownRoots = [...GOOGLE_ROOT_FINGERPRINTS_HARDCODED, ...OEM_ROOT_FINGERPRINTS];
  /* Структурные требования к цепочке. Без них подпись звена ничего не значит:
     сертификат обычного телефона (CA:FALSE) мог выступать промежуточным. */
  const metas = certs.map(parseCertMeta);
  for (let i = 1; i < certs.length; i++) {
    if (!metas[i].isCA)
      throw new Error("Цепочка аттестации: сертификат " + i + " подписывает другой сертификат, но не является удостоверяющим (basicConstraints CA:FALSE)");
    if (metas[i].keyCertSign === false)
      throw new Error("Цепочка аттестации: сертификату " + i + " не разрешено подписывать сертификаты (keyUsage без keyCertSign)");
  }
  for (let i = 0; i < certs.length - 1; i++) {
    if (!_bytesEq(metas[i].issuerBytes, metas[i + 1].subjectBytes))
      throw new Error("Цепочка аттестации: издатель сертификата " + i + " не совпадает с субъектом сертификата " + (i + 1));
  }
  /* Якорь доверия обязан быть ПОСЛЕДНИМ звеном, а не «где-то в цепочке». */
  const lastFp = chainFps[chainFps.length - 1];
  if (!allKnownRoots.some((k) => k === lastFp))
    throw new Error("Цепочка аттестации: последний сертификат цепочки не является известным корнем аттестации");
  return true;
}

// Раньше эта проверка судила и о самом разовом вызове: пропускала два
// известных значения, на всё остальное давала предупреждение. Обнаружилось
// на первой же настоящей съёмке нового образца: выданный сервером вызов —
// это и есть «всё остальное», поэтому доверие понижалось у каждой честной
// съёмки и не восстанавливалось никогда, даже когда проверка свежести вызова
// ниже честно отвечала «в порядке».
//
// Теперь о самом вызове судит только она — и может по-настоящему сверить
// подпись сервера. Здешнее сравнение строк такой защиты не давало никогда:
// значение вызова публично по своей природе.
//
// Эта проверка отвечает ровно на один вопрос — где живёт ключ. Утверждение
// более узкое, но зато честное.
/** Координаты из EXIF снимка, если они там есть. */
export interface ExifGps {
  latitude: number;
  longitude: number;
}

/* Скупой разбор GPS из EXIF в JPEG. Нужны ровно четыре тега, поэтому своё, а
   не библиотека: проверяльщик работает офлайн и живёт в двух копиях, одна из
   которых переносится руками.

   Любая неожиданность — возвращаем null («EXIF нет»), а не бросаем: эта
   проверка приводит довод, и ронять из-за неё разбор целого файла нельзя. */
export function parseExifGps(bytes: Uint8Array): ExifGps | null {
  try {
    if (bytes.length < 4 || bytes[0] !== 0xff || bytes[1] !== 0xd8) return null;  // не JPEG
    /* Ищем сегмент APP1 с меткой "Exif\0\0". Идём по сегментам, а не поиском
       подстроки: подстрока нашлась бы и внутри пикселей. */
    let p = 2;
    let tiff = -1;
    while (p + 4 <= bytes.length) {
      if (bytes[p] !== 0xff) return null;
      const marker = bytes[p + 1];
      if (marker === 0xda || marker === 0xd9) break;            // начались данные
      const len = (bytes[p + 2] << 8) | bytes[p + 3];
      if (len < 2 || p + 2 + len > bytes.length) return null;
      if (marker === 0xe1 && len >= 8
          && bytes[p + 4] === 0x45 && bytes[p + 5] === 0x78
          && bytes[p + 6] === 0x69 && bytes[p + 7] === 0x66) {
        tiff = p + 10;
        break;
      }
      p += 2 + len;
    }
    if (tiff < 0 || tiff + 8 > bytes.length) return null;

    const le = bytes[tiff] === 0x49 && bytes[tiff + 1] === 0x49;   // "II" или "MM"
    const u16 = (o: number) => le ? bytes[o] | (bytes[o + 1] << 8)
                                  : (bytes[o] << 8) | bytes[o + 1];
    const u32 = (o: number) => (le
      ? (bytes[o] | (bytes[o + 1] << 8) | (bytes[o + 2] << 16) | (bytes[o + 3] << 24))
      : ((bytes[o] << 24) | (bytes[o + 1] << 16) | (bytes[o + 2] << 8) | bytes[o + 3])) >>> 0;
    if (u16(tiff + 2) !== 0x002a) return null;

    /* IFD0 → указатель на GPS-подкаталог (тег 0x8825). */
    const ifd0 = tiff + u32(tiff + 4);
    if (ifd0 + 2 > bytes.length) return null;
    let gpsIfd = -1;
    const n0 = u16(ifd0);
    for (let i = 0; i < n0; i++) {
      const e = ifd0 + 2 + i * 12;
      if (e + 12 > bytes.length) return null;
      if (u16(e) === 0x8825) { gpsIfd = tiff + u32(e + 8); break; }
    }
    if (gpsIfd < 0 || gpsIfd + 2 > bytes.length) return null;

    /* В GPS-подкаталоге берём широту, долготу и их полушария. */
    const rational3 = (off: number): number | null => {
      let v = 0;
      for (let k = 0; k < 3; k++) {
        const num = u32(off + k * 8), den = u32(off + k * 8 + 4);
        if (!den) return null;
        v += (num / den) / Math.pow(60, k);
      }
      return v;
    };
    let lat: number | null = null, lon: number | null = null;
    let latRef = "", lonRef = "";
    const n = u16(gpsIfd);
    for (let i = 0; i < n; i++) {
      const e = gpsIfd + 2 + i * 12;
      if (e + 12 > bytes.length) return null;
      const tag = u16(e), count = u32(e + 4);
      if (tag === 1 || tag === 3) {
        /* Полушарие — одна буква, лежит прямо в поле значения. */
        const c = String.fromCharCode(bytes[e + 8]);
        if (tag === 1) latRef = c; else lonRef = c;
      } else if ((tag === 2 || tag === 4) && count === 3) {
        const off = tiff + u32(e + 8);
        if (off + 24 > bytes.length) return null;
        const v = rational3(off);
        if (v === null) return null;
        if (tag === 2) lat = v; else lon = v;
      }
    }
    if (lat === null || lon === null) return null;
    if (latRef === "S") lat = -lat;
    if (lonRef === "W") lon = -lon;
    if (!Number.isFinite(lat) || !Number.isFinite(lon)) return null;
    if (Math.abs(lat) > 90 || Math.abs(lon) > 180) return null;
    return { latitude: lat, longitude: lon };
  } catch {
    return null;
  }
}

/* Расстояние между двумя точками, метры. Формула гаверсинуса: на наших
   расстояниях плоская прикидка тоже сошлась бы, но у полюсов врала бы. */
function metersBetween(aLat: number, aLon: number, bLat: number, bLon: number): number {
  const R = 6371000, rad = Math.PI / 180;
  const dLat = (bLat - aLat) * rad, dLon = (bLon - aLon) * rad;
  const s = Math.sin(dLat / 2) ** 2
    + Math.cos(aLat * rad) * Math.cos(bLat * rad) * Math.sin(dLon / 2) ** 2;
  return 2 * R * Math.asin(Math.min(1, Math.sqrt(s)));
}

/* Двести метров. EXIF хранит координаты округлёнными до долей секунды, а
   манифест несёт полное число, поэтому расхождение в сантиметры неизбежно.
   Допуск НЕ про точность фикса — он про согласованность двух записей об одном
   событии. */
const EXIF_GPS_TOLERANCE_M = 200;

/**
 * Совпадают ли координаты в EXIF с подписанными.
 *
 * Довод, а не запрет: подменить EXIF после съёмки нельзя — подпись покрывает
 * весь файл. Поэтому расхождение означает не подделку, а нашу собственную
 * ошибку при записи копии в EXIF. Показывается замечанием; вердикт не трогает —
 * наказывать клиента за наш промах нельзя. Верны координаты из подписанного
 * описания: их записал проверенный путь приложения, и их показывает отчёт.
 */
export function checkExifGps(
  photoBytes: Uint8Array | undefined,
  manifest: Record<string, unknown>,
): NamedCheck {
  if (!photoBytes) return { state: "skip", msg: "EXIF: кадра нет" };
  const exif = parseExifGps(photoBytes);
  if (!exif) {
    return { state: "skip", msg: "В снимке нет координат EXIF — так снимали до сентября 2026" };
  }
  const mLat = manifest.latitude, mLon = manifest.longitude;
  if (typeof mLat !== "number" || typeof mLon !== "number") {
    return {
      state: "warn",
      msg: "В снимке есть координаты EXIF, но в подписанном манифесте места нет",
    };
  }
  const d = metersBetween(mLat, mLon, exif.latitude, exif.longitude);
  if (d <= EXIF_GPS_TOLERANCE_M) {
    return {
      state: "pass",
      exifLat: exif.latitude,
      exifLon: exif.longitude,
      msg: "Координаты в EXIF снимка совпадают с подписанными — и само совпадение под подписью",
    };
  }
  return {
    state: "warn",
    exifLat: exif.latitude,
    exifLon: exif.longitude,
    msg: "Координаты в EXIF снимка расходятся с подписанными на "
      + (d >= 1000 ? Math.round(d / 100) / 10 + " км" : Math.round(d) + " м"),
  };
}

export function checkOid(attOk: boolean, attChain: string[] | undefined, refTsMs?: number | null): NamedCheck {
  if (!attOk || !attChain || !attChain.length) return { state: "skip", msg: "OID — аттестация отсутствует или не прошла" };
  let ext: KeyDescription | null = null;
  try {
    ext = parseAndroidKeystoreExt(base64ToBytes(attChain[0]));
  } catch {
    /* дальше сработает ветка «расширение не разобралось» */
  }
  if (!ext) return { state: "warn", msg: "OID-расширение аттестации (1.3.6.1.4.1.11129.2.1.17) не найдено в leaf-сертификате" };
  const hwOk = ext.keymasterSecLevel >= 1;
  if (!hwOk) return { state: "warn", msg: `OID: ключ в программном хранилище (${ext.kmSecName})` };

  /* Чип настоящий. Теперь — чей это ключ. */
  if (!ext.appId || !ext.appId.packages.length)
    return { state: "warn", msg: `Ключ в ${ext.kmSecName}, но приложение-владелец в аттестации не указано` };
  if (ext.appId.packages.indexOf(TV_PACKAGE_NAME) < 0)
    return { state: "fail", msg: `Ключ аттестован настоящим чипом, но принадлежит другому приложению: ${ext.appId.packages.join(", ")}` };
  const known = ext.appId.digests.some((d) => TV_SIGNING_DIGESTS.indexOf(String(d).toLowerCase()) >= 0);
  if (!known)
    return { state: "warn", msg: `Ключ в ${ext.kmSecName}, приложение то самое, но сертификат подписи нам неизвестен` };
  if (ext.keyOrigin !== null && ext.keyOrigin !== 0)
    return { state: "warn", msg: `Ключ в ${ext.kmSecName}, но импортирован, а не создан в чипе` };

  /* Действовали ли сертификаты цепочки НА МОМЕНТ СЪЁМКИ.

     Сверяем со временем съёмки, а не с «сейчас»: файл, снятый при
     действующих сертификатах, обязан остаться подлинным и через десять лет.

     Мягко — предупреждение, а не отказ: истёкший сертификат сам по себе
     подделкой не является. Отзыв ключа проверяется отдельно —
     checkAttestationRevoked, раздел 4.7 спецификации: обещание «проверка
     работает без сети» сохранено снимком списка с датой, а сервер сверяется
     с живым списком.

     Эта проверка была только в браузерной копии (там у checkOid есть третий
     параметром). На сервере notBefore/notAfter вычислялись, но ни с чем не
     сравнивались, и честная съёмка вне окна действия получала НЕ АТТЕСТОВАНО
     на сайте и ПОДЛИННО на полке. Расходиться им нельзя. */
  try {
    if (refTsMs != null && isFinite(refTsMs)) {
      const certs = attChain.map((b64) => base64ToBytes(String(b64).replace(/\s+/g, "")));
      /* Последнее звено — якорь доверия, и его срок НЕ проверяем.

         Google перевыпустил свой корень аттестации, сохранив тот же серийный
         номер: старый действовал 2016 — 24.05.2026, новый 2022 — 2042. Поэтому
         Google прямо рекомендует доверять цепочке к этому корню независимо от
         срока действия. Устройство со старым корнем иначе получало бы
         «сертификат истёк» и вердикт НЕ АТТЕСТОВАНО на честной съёмке.

         Подтверждать якорь датой и незачем: его подлинность мы устанавливаем
         сильнее — сверкой отпечатка SHA-256 с зашитым списком (см.
         verifyAttestationChain). Так же поступает и сам стандарт X.509:
         срок действия trust anchor не проверяется, потому что проверять его
         некому — он подписан сам собой. */
      for (let i = 0; i < certs.length - 1; i++) {
        const cm = parseCertMeta(certs[i]);
        /* Дата, которую не удалось прочитать, — не повод промолчать. RFC 5280
           допускает два вида записи времени, и оба здесь понимаются; на трёх
           настоящих цепочках все двенадцать сертификатов даты отдают. Значит
           непрочитанная дата означает негодную, а не незнакомый формат. */
        if (cm.notBefore == null || cm.notAfter == null)
          return { state: "warn", msg: `Ключ в ${ext.kmSecName}, но у сертификата ${i} не читается срок действия` };
        if (cm.notBefore != null && refTsMs < cm.notBefore)
          return { state: "warn", msg: `Ключ в ${ext.kmSecName}, но сертификат ${i} на момент съёмки ещё не действовал` };
        if (cm.notAfter != null && refTsMs > cm.notAfter)
          return { state: "warn", msg: `Ключ в ${ext.kmSecName}, но сертификат ${i} на момент съёмки уже истёк` };
      }
    }
  } catch {
    /* разбор срока не удался — не понижаем вердикт из-за этого */
  }
  return { state: "pass", msg: `Ключ в ${ext.kmSecName} · подписано приложением TrustVisor` };
}

// Третье, отдельное утверждение о цепочке аттестации — не о том, где живёт
// ключ, и не о происхождении разового вызова, а о состоянии самого
// устройства.
//
// Разница существенная: телефон с полученными правами суперпользователя или
// разблокированным загрузчиком спокойно создаёт настоящий аппаратный ключ и
// получает настоящий свежий вызов. Две другие проверки такого телефона не
// видят вовсе. Разбор когда-то останавливался, не дойдя до этого поля, — и
// взломанное устройство проходило наравне с целым.
//
// Отсутствие поля само по себе не подозрительно: старые версии Android и
// часть производителей его не передают. Подозрительно только явно
// объявленное «загрузчик открыт». Поэтому при отсутствии — «нет данных», а
// не «предупреждение».
/* Отзыв ключа аттестации — четвёртое утверждение о цепочке, и оно сильнее
   трёх остальных: Root of Trust, уровень защиты ключа и принадлежность
   приложению читаются ИЗ ТОЙ ЖЕ цепочки. Обладатель отозванного ключа
   сочиняет их все разом, не притрагиваясь к телефону.

   Проверяем ВСЕ звенья, как велит документация Google, а не только лист:
   скомпрометирован может быть промежуточный ключ производителя.

   Снимок списка — с датой, и дата уходит в текст: человек должен знать, на
   какое число мы отвечаем. Сервер сверяется с живым списком отдельно. */
/* Одно и то же число Google публикует в списке отзыва ДВУМЯ видами: новые
   ключи шестнадцатеричным, старые — десятичным. На 18.09.2026 из 1753 записей
   977 десятичные (19–20 цифр), и сверка одной лишь hex-формой не находила ни
   одну из них: отозванный ключ проходил как подлинный.

   Список при этом нормализовать НЕЛЬЗЯ: строка из одних цифр неоднозначна —
   «12345678» бывает и десятичной записью, и шестнадцатеричной, — и перегнав
   её, мы сломали бы те записи, что были настоящим hex. Поэтому нормализуем
   запрос: отдаём обе формы и ищем любую. Совпадений только прибавляется,
   прежние не теряются. */
export function serialLookupForms(serialHex: string): string[] {
  const forms = [serialHex];
  try {
    const dec = BigInt("0x" + serialHex).toString(10);
    if (dec !== serialHex) forms.push(dec);
  } catch {
    /* серийник не разобрался как число — остаётся одна hex-форма */
  }
  return forms;
}

export function checkAttestationRevoked(
  attOk: boolean,
  attChain: string[] | undefined,
  /* Список передаётся параметром, а не берётся из модуля намертво. Это не
     украшение: заслон обязан уметь подложить свой список, иначе проверить его
     работу можно только пересборкой снимка, и её никто делать не станет —
     значит проверка жила бы непроверенной. */
  /* Значения по умолчанию срабатывают и когда довод передан как undefined —
     именно так приходит `opts?.revoked` при вызове без настроек. */
  revoked: ReadonlySet<string> = REVOKED_SERIALS,
  snapshotDate: string = REVOKED_SNAPSHOT_DATE,
): NamedCheck {
  if (!attOk || !attChain || !attChain.length)
    return { state: "skip", msg: "Отзыв ключа — аттестация отсутствует или не прошла" };
  const hit: string[] = [];
  let seen = 0;
  for (const b64 of attChain) {
    let meta: CertMeta | null = null;
    try {
      meta = parseCertMeta(base64ToBytes(String(b64).replace(/\s+/g, "")));
    } catch {
      continue; /* звено не разобралось — об этом говорят другие проверки */
    }
    if (!meta.serialHex) continue;
    seen++;
    /* Показываем всегда hex — это каноническая запись серийника сертификата,
       даже когда совпала десятичная форма из списка. */
    if (serialLookupForms(meta.serialHex).some((f) => revoked.has(f)))
      hit.push(meta.serialHex);
  }
  if (!seen) return { state: "skip", msg: "Отзыв ключа: серийные номера цепочки не разобрались" };
  if (hit.length)
    return {
      state: "warn",
      msg: `Ключ аттестации отозван Google — серийный номер ${hit[0]}. Список отзыва на ${snapshotDate}`,
    };
  return { state: "pass", msg: `В списке отзыва Google не значится (список на ${snapshotDate})` };
}

export function checkRootOfTrust(attOk: boolean, attChain: string[] | undefined): NamedCheck {
  if (!attOk || !attChain || !attChain.length) return { state: "skip", msg: "Root of trust — аттестация отсутствует или не прошла" };
  let ext: KeyDescription | null = null;
  try {
    ext = parseAndroidKeystoreExt(base64ToBytes(attChain[0]));
  } catch {
    /* дальше сработает ветка «расширение не разобралось» */
  }
  if (!ext || !ext.rootOfTrust) return { state: "skip", msg: "Root of trust: поле отсутствует в аттестации этого устройства" };
  const { deviceLocked, verifiedBootState, verifiedBootStateName } = ext.rootOfTrust;
  if (deviceLocked && verifiedBootState === 0)
    return { state: "pass", msg: `Загрузчик заблокирован, verified boot: ${verifiedBootStateName}` };
  return {
    state: "warn",
    msg: `Возможен root или разлоченный загрузчик — deviceLocked=${deviceLocked}, verified boot: ${verifiedBootStateName}`,
  };
}

// checkOid выше отвечает за уровень защиты ключа и принадлежность
// приложению. За сам разовый вызов отвечает только эта функция: она
// подтверждает, что вызов выдан нашим сервером, — сверяет подпись, которую
// сервер поставил над ним своим закрытым ключом. Такую подпись нельзя
// сочинить: ключ никуда не уезжает, а простую строку клиент мог бы передать
// в Keystore и сам. Функция оставлена отдельной, а не влита в checkOid:
// это другое утверждение — о происхождении и свежести, а не об уровне
// защиты, — и исходов у него три (устаревшая схема, свежий, истёкший),
// плюс отдельный случай подделки.
/* Срок токена подтверждения момента. Сервер выдаёт токен на срок компании
   (по умолчанию CHALLENGE_TTL_MS, 12 часов; до перехода — час; длина записана
   в самом токене, см. challengeTtlMs). Момент выдачи в токен не записан,
   поэтому «не раньше» считается из срока и длины токена. Если съёмка позже
   срока, но привязка к серверному времени цела (checkServerAnchor), момент
   подтверждён ею и вердикт не понижается — см. withAnchorWitness. Прежнее
   правило «спутниковый свидетель» снято: спутниковый сигнал подделывается с
   земли, привязка — нет; спутниковое время осталось сверкой в checkGpsTime. */
export const CHALLENGE_TTL_MS = 12 * 60 * 60 * 1000;
export const CHALLENGE_TTL_LEGACY_MS = 60 * 60 * 1000;
/* Момент выкладки 12-часового срока, мс UTC. 0 — все токены считаются
   12-часовыми: «не раньше» для старых часовых токенов выходит шире, чем могло
   бы, но не ложным. */
export const CHALLENGE_TTL_SWITCH_MS = 1788591494707; /* момент выкладки 12-часового срока: 2026-09-05 */
const LEGACY_CHALLENGES = new Set(["trustvisor-v1", "trustvision-v1"]);

export const FRESHNESS_EARLY_SLACK_MS = 60 * 1000;
export async function checkAttestationChallengeFreshness(
  attOk: boolean,
  attChain: string[] | undefined,
  manifest: Record<string, unknown>,
  referenceTsMs: number | null
): Promise<NamedCheck> {
  if (!attOk || !attChain || !attChain.length) return { state: "skip", msg: "Аттестация отсутствует — проверка свежести challenge невозможна" };
  let ext: KeyDescription | null = null;
  try {
    ext = parseAndroidKeystoreExt(base64ToBytes(attChain[0]));
  } catch {
    /* этот случай уже описан в checkOid */
  }
  if (!ext) return { state: "skip", msg: "OID-расширение недоступно — проверка свежести challenge невозможна" };

  if (LEGACY_CHALLENGES.has(ext.challenge)) {
    return { state: "warn", msg: "Ключ создан по устаревшей схеме (публичная строка-challenge, до перехода на серверные токены)" };
  }

  const sigB64 = manifest.attestationChallengeServerSig as string | undefined;
  const expMs = manifest.attestationChallengeExpiresAt as number | undefined;
  if (!sigB64 || expMs == null) {
    return { state: "fail", msg: "Challenge не подтверждён сервером — возможна подделка" };
  }

  let sigOk = false;
  const payload = new TextEncoder().encode(`${ext.challenge}.${expMs}`);
  /* Нынешний ключ — всегда; прежний — только для токенов, выданных до его
     замены (см. TRUSTVISOR_ATTESTATION_OLD_KEY_LAST_EXP_MS). */
  const keysToTry = [TRUSTVISOR_ATTESTATION_PUBLIC_KEY_NEXT_B64];
  if (expMs <= TRUSTVISOR_ATTESTATION_OLD_KEY_LAST_EXP_MS) keysToTry.push(TRUSTVISOR_ATTESTATION_PUBLIC_KEY_B64);
  for (const keyB64 of keysToTry) {
    try {
      const pubKey = await importSpkiKey(keyB64);
      if (await crypto.subtle.verify({ name: "ECDSA", hash: { name: "SHA-256" } }, pubKey, derToP1363(base64ToBytes(sigB64)) as BufferSource, payload as BufferSource)) {
        sigOk = true;
        break;
      }
    } catch {
      /* следующий ключ */
    }
  }
  if (!sigOk) return { state: "fail", msg: "Подпись сервера для challenge не подтверждена — возможна подделка" };

  // Дальше вызов в любом случае подписан сервером. Отдаём сам вызов наружу:
  // те части сервиса, у которых есть сеть, могут проверить, не использован ли
  // он повторно. Здесь это невозможно по устройству — проверка работает без
  // обращений к сети.
  const ttlMs = challengeTtlMs(ext.challenge, expMs);
  const notBeforeMs = expMs - ttlMs;
  const notAfterMs = expMs;
  // Раньше выдачи подтверждения съёмки быть не могло: подтверждение вшито
  // в сертификат ключа этой же съёмки. Дата раньше — часы телефона
  // переведены назад. Симметрично ветке «позже exp» ниже; при живой
  // привязке withAnchorWitness снимает (momentMs ≥ notBeforeMs). Минута
  // допуска — на разницу часов телефона и сервера в момент выдачи.
  if (referenceTsMs != null && referenceTsMs < notBeforeMs - FRESHNESS_EARLY_SLACK_MS) {
    const earlyH = Math.round((notBeforeMs - referenceTsMs) / 360000) / 10;
    return { state: "warn", msg: "Съёмка датирована раньше выдачи подтверждения момента (на " + earlyH + " ч) — часы телефона переведены назад", token: ext.challenge, notBeforeMs, notAfterMs };
  }
  if (referenceTsMs != null && referenceTsMs > expMs) {
    const lateMs = referenceTsMs - expMs;
    const lateH = Math.round(lateMs / 360000) / 10;
    return { state: "warn", msg: "Challenge был подлинным, но истёк к моменту съёмки (устройство было без связи, съёмка на " + lateH + " ч позже срока)", token: ext.challenge, notBeforeMs, notAfterMs };
  }
  return { state: "pass", msg: "Challenge подтверждён сервером и был свежим на момент съёмки", token: ext.challenge, notBeforeMs, notAfterMs };
}

// Эта проверка не зависит от checkTimestamp ниже. Та сверяет время, которое
// манифест сообщает о себе сам, с часами машины, где открыт файл, и съёмку,
// датированную задним числом переводом часов телефона, не поймает.
//
// Расхождение с серверным временем записывает само приложение, попутно с
// обращениями, которые устройство и так делает — за разовым вызовом и за
// разрешением на кадр. Поэтому число показывает, насколько часы УСТРОЙСТВА
// расходились с часами СЕРВЕРА в тот момент, и задним числом его в уже
// подписанном манифесте не поменять.
//
// Доказательством это не является: у устройства, давно не выходившего в сеть,
// запись может быть многодневной давности. Это признак правдоподобия — потому
// предупреждение, а не провал.
const SERVER_CLOCK_WARN_MS = 5 * 60 * 1000;

export function checkServerClockDelta(manifest: Record<string, unknown>): NamedCheck {
  const deltaMs = manifest.serverTimeDeltaMs as number | undefined;
  const checkedAt = manifest.serverTimeCheckedAt as number | undefined;
  if (deltaMs == null || checkedAt == null) {
    return { state: "skip", msg: "Нет сверки с серверным временем (старый манифест или устройство ещё ни разу не выходило в сеть)" };
  }
  const absSec = Math.round(Math.abs(deltaMs) / 1000);
  if (Math.abs(deltaMs) > SERVER_CLOCK_WARN_MS) {
    return { state: "warn", msg: `Часы устройства расходились с сервером на ${absSec}с при последней сверке — возможна манипуляция временем` };
  }
  return { state: "pass", msg: `Часы устройства сверены с сервером (расхождение ${absSec}с)` };
}

/* ── Привязка к серверному времени по счётчику загрузки ──────────────────
   Приложение (с версии 1.4, manifestVersion 1.2) при каждом ответе сервера
   запоминает серверное время и показание счётчика времени с загрузки
   (SystemClock.elapsedRealtime: идёт и во сне, часы и пояс на него не
   влияют, перевести без root нельзя). При съёмке в манифест уходит
   anchorServerMs — серверное время при последней связи — и anchorElapsedMs —
   сколько натикал счётчик с тех пор. Момент съёмки по серверным часам — их
   сумма, с точностью до секунд в сутки, сколько бы телефон ни был без сети.
   anchorState = "reboot": телефон перезагружался без связи, счётчик новый,
   привязки нет — момент ограничен только сроком токена (срок компании).
   Доверие к привязке — то же, что ко всему манифесту: аттестованный чип
   подтверждает, что поля писало настоящее приложение на устройстве с
   проверенной загрузкой. Неправдоподобная привязка — признак вмешательства
   и понижает доверие (причина «anchor»); потеря привязки — нет. */
export const ANCHOR_MAX_ELAPSED_MS = 400 * 24 * 60 * 60 * 1000;
export const ANCHOR_TOKEN_SLACK_MS = 60 * 1000;
export interface AnchorCheck extends NamedCheck { momentMs?: number; offlineMs?: number; inconsistent?: boolean }
function _num(v: unknown): number | null {
  return typeof v === "number" && Number.isFinite(v) ? v : null;
}
export function checkServerAnchor(m: Record<string, unknown>, freshness: NamedCheck | null): AnchorCheck {
  const serverMs = _num(m.anchorServerMs);
  if (serverMs == null) return { state: "skip", msg: "Привязки к серверному времени нет (приложение до 1.4 или устройство ни разу не выходило в сеть)" };
  const elapsedMs = _num(m.anchorElapsedMs);
  if (m.anchorState === "reboot" || elapsedMs == null) {
    return { state: "warn", msg: "Привязка к серверному времени потеряна: телефон перезагружался без связи — момент съёмки ограничен только сроком подтверждения" };
  }
  if (elapsedMs < 0 || elapsedMs > ANCHOR_MAX_ELAPSED_MS) {
    return { state: "warn", msg: "Привязка к серверному времени неправдоподобна (счётчик " + Math.round(elapsedMs / 3600000) + " ч) — возможно вмешательство", inconsistent: true };
  }
  const nb = freshness ? _num(freshness.notBeforeMs) : null;
  if (nb != null && serverMs + ANCHOR_TOKEN_SLACK_MS < nb) {
    return { state: "warn", msg: "Привязка старше подтверждения момента, полученного при той же связи — возможно вмешательство", inconsistent: true };
  }
  const momentMs = serverMs + elapsedMs;
  const offH = Math.round(elapsedMs / 360000) / 10;
  return { state: "pass", msg: "Момент съёмки подтверждён привязкой к серверному времени (последняя связь за " + offH + " ч до съёмки)", momentMs, offlineMs: elapsedMs };
}

/* Привязка снимает понижение за истёкший токен: момент съёмки известен по
   серверным часам, а не по телефонным. Условие momentMs ≥ notBeforeMs —
   съёмка не могла быть раньше выдачи токена, вшитого в её же сертификат. */
export function withAnchorWitness(f: NamedCheck, anchor: AnchorCheck | null): NamedCheck {
  if (!anchor || anchor.state !== "pass" || anchor.momentMs == null) return f;
  const nb = _num(f.notBeforeMs), na = _num(f.notAfterMs);
  if (f.state !== "warn" || nb == null || na == null || anchor.momentMs < nb) return f;
  if (anchor.momentMs <= na) {
    return { ...f, state: "pass", msg: "Challenge был свежим на момент съёмки по серверным часам (часы телефона спешили)", anchorWitness: true };
  }
  const lateH = Math.round((anchor.momentMs - na) / 360000) / 10;
  return { ...f, state: "pass", msg: "Challenge истёк за " + lateH + " ч до съёмки, но момент подтверждён привязкой к серверному времени", anchorWitness: true };
}

/* Часы телефона против момента по серверу. Перевод часов ловится здесь;
   вердикт от него не зависит — момент известен и без часов телефона. */
export const DEVICE_CLOCK_SHIFT_WARN_MS = 2 * 60 * 1000;
/* Больше этого — не дрейф и не рука на часах ради удобства, а дата, которой
   нельзя верить: честный дрейф — секунды в сутки, ручная подстройка — минуты,
   подлог ради спора — часы и дни. Вердикт при этом «Момент не подтверждён»,
   не «Изменён»: подпись и устройство целы, момент известен по серверу и
   показан, противоречит ему только собственная дата файла. */
export const DEVICE_CLOCK_DOWNGRADE_MS = 30 * 60 * 1000;
export function checkDeviceClock(referenceTsMs: number | null, anchor: AnchorCheck, m: Record<string, unknown>): NamedCheck {
  if (anchor.state !== "pass" || anchor.momentMs == null) return { state: "skip", msg: "Без привязки часы телефона сверяются только по записи последней сверки" };
  if (referenceTsMs == null) return { state: "skip", msg: "Нет времени съёмки по часам телефона" };
  const shiftMs = referenceTsMs - anchor.momentMs;
  const autoNote = m.autoTimeEnabled === false ? "; автоматическая установка времени на телефоне выключена" : "";
  if (Math.abs(shiftMs) > DEVICE_CLOCK_SHIFT_WARN_MS) {
    const min = Math.round(Math.abs(shiftMs) / 60000);
    const downgrade = Math.abs(shiftMs) > DEVICE_CLOCK_DOWNGRADE_MS;
    return { state: "warn", msg: "Часы телефона " + (shiftMs > 0 ? "спешат" : "отстают") + " на " + min + " мин относительно сервера" + (downgrade ? " — собственной дате файла верить нельзя, момент съёмки указан по серверу" : " (перевод часов или долгий дрейф); момент съёмки указан по серверу") + autoNote, shiftMs, downgrade };
  }
  return { state: "pass", msg: "Часы телефона совпадают с серверными (±" + Math.round(Math.abs(shiftMs) / 1000) + " с)" + autoNote, shiftMs };
}

/* Приложение подмены местоположения: его фиксы приложение отбрасывает, а
   факт записывает. Координат в файле нет, момент и устройство подтверждены —
   поэтому только отчёт и API, вердикт не понижается. */
export function checkLocationMock(m: Record<string, unknown>): NamedCheck {
  if (m.locationMockSeen === true) return { state: "warn", msg: "Во время съёмки работало приложение подмены местоположения — его данные отброшены, координаты не записаны" };
  const v = parseFloat(String(m.manifestVersion ?? ""));
  if (Number.isFinite(v) && v >= 1.2) return { state: "pass", msg: "Подмены местоположения не замечено" };
  return { state: "skip", msg: "Приложение этой версии подмену местоположения не отмечало" };
}

/* Второе мнение о месте. Подделку спутникового радиосигнала телефон не
   замечает; сотовые вышки и Wi-Fi подделать на порядок сложнее. Приложение
   1.4 пишет сетевой фикс (netLatitude/netLongitude/netAccuracy) рядом со
   спутниковым; расхождение больше суммы точностей и двух километров —
   признак подмены сигнала (причина «location», НЕ АТТЕСТОВАНО). Сравнение
   имеет смысл только со спутниковым фиксом: у fused/network источник тот же.
   Без покрытия второго мнения нет — проверка пропускается, не понижает. */
export const LOCATION_NET_MARGIN_M = 2000;
function _fmtDist(m: number): string { return m >= 1000 ? (Math.round(m / 100) / 10) + " км" : m + " м"; }
export function checkLocationSecondOpinion(m: Record<string, unknown>): NamedCheck {
  const nlat = _num(m.netLatitude), nlon = _num(m.netLongitude), nacc = _num(m.netAccuracy);
  if (nlat == null || nlon == null) return { state: "skip", msg: "Сетевого фикса нет (приложение до 1.4 или нет покрытия) — второго мнения о месте нет" };
  const lat = _num(m.latitude), lon = _num(m.longitude);
  if (lat == null || lon == null || m.locationProvider !== "gps") return { state: "skip", msg: "Спутникового фикса нет — сравнивать сетевой не с чем", netLat: nlat, netLon: nlon, netAcc: nacc };
  const distM = Math.round(haversineKm(lat, lon, nlat, nlon) * 1000);
  const margin = (nacc ?? 2000) + (_num(m.locationAccuracy) ?? 50) + LOCATION_NET_MARGIN_M;
  if (distM > margin) return { state: "warn", msg: "Координаты со спутника и по сотовой сети/Wi-Fi расходятся на " + _fmtDist(distM) + " — возможна подмена сигнала", distM, netLat: nlat, netLon: nlon, netAcc: nacc };
  return { state: "pass", msg: "Место по сотовой сети/Wi-Fi совпадает со спутниковым (расхождение " + _fmtDist(distM) + ")", distM, netLat: nlat, netLon: nlon, netAcc: nacc };
}

/* Портрет спутникового сигнала (пишется приложением с версии 1.4). Передатчик
   поддельных сигналов даёт слишком ровную картину: одинаковая сила с одной
   антенны, часто одно созвездие. Каждый признак сам по себе бывает и у
   честного неба, поэтому понижает доверие только их сочетание (два и больше,
   причина «location»). Уровень усиления и диапазоны — только в отчёт: без
   эталона устройства судить по ним нельзя. Дробные поля приложение пишет
   строками с одним знаком. */
export const GNSS_MIN_SATS = 6;
function _numStr(v: unknown): number | null {
  if (typeof v === "number") return Number.isFinite(v) ? v : null;
  if (typeof v === "string" && v.trim() !== "") { const n = Number(v); return Number.isFinite(n) ? n : null; }
  return null;
}
const GNSS_NAMES: Record<string, string> = { G: "GPS", R: "ГЛОНАСС", E: "Galileo", C: "BeiDou", J: "QZSS", I: "IRNSS", S: "SBAS" };
export function checkGnssPortrait(m: Record<string, unknown>): NamedCheck {
  const used = _numStr(m.gnssUsed);
  if (used == null) return { state: "skip", msg: "Портрета спутникового сигнала нет (приложение до 1.4 или спутниковый запрос не делался)" };
  if (m.locationProvider !== "gps") return { state: "skip", msg: "Фикс не спутниковый — портрет сигнала не оценивается" };
  const consts = String(m.gnssConst ?? "").split(",").filter((c) => c);
  const mean = _numStr(m.gnssCn0Mean), std = _numStr(m.gnssCn0Std), agc = _numStr(m.gnssAgcDb);
  const flags: string[] = [];
  if (used >= GNSS_MIN_SATS && consts.length === 1) flags.push("одно созвездие при " + used + " спутниках");
  if (used >= GNSS_MIN_SATS && std != null && std < 1.5) flags.push("слишком ровный сигнал (разброс " + std + " дБ)");
  if (mean != null && std != null && mean > 45 && std < 3) flags.push("ровный и очень сильный сигнал (" + mean + "±" + std + " дБ-Гц)");
  const portrait = "спутников " + used + (consts.length ? ": " + consts.map((c) => GNSS_NAMES[c] ?? c).join(", ") : "")
    + (mean != null ? "; сигнал " + mean + (std != null ? "±" + std : "") + " дБ-Гц" : "")
    + (m.gnssBands ? "; " + String(m.gnssBands) : "") + (agc != null ? "; усиление " + agc + " дБ" : "");
  if (flags.length >= 2) return { state: "warn", msg: "Портрет спутникового сигнала похож на передатчик: " + flags.join("; ") + " (" + portrait + ")", flags, portrait };
  if (flags.length === 1) return { state: "pass", msg: portrait + " — один признак подмены (" + flags[0] + "), сам по себе не показатель", flags, portrait };
  return { state: "pass", msg: portrait, flags, portrait };
}

function _setMoment(result: VerifyResult, anchor: AnchorCheck, fresh: NamedCheck, deviceTsMs: number | null, clock: NamedCheck, mock: boolean): void {
  if (anchor.state === "pass" && anchor.momentMs != null) {
    result.momentMs = anchor.momentMs; result.momentSource = "anchor"; result.offlineMs = anchor.offlineMs ?? null;
  } else {
    result.momentMs = deviceTsMs; result.momentSource = fresh.notBeforeMs != null ? "token" : "device"; result.offlineMs = null;
  }
  result.deviceClockShiftMs = typeof clock.shiftMs === "number" ? clock.shiftMs : null;
  result.locationMock = mock;
}

// Только для видео: у фотографии длительности нет. Лимит задаёт компания, и
// приложение обязано было само остановить запись по нему. Лимит подписывается
// вместе с манифестом, и поэтому проверяющий может убедиться, что остановка
// действительно произошла: сама по себе остановка на устройстве не доказывает
// ничего — изменённое приложение просто не стало бы её делать.
//
// Пять секунд запаса — на обычную задержку между срабатыванием таймера и
// концом записи, чтобы её не приняли за нарушение лимита.
const DURATION_CAP_GRACE_MS = 5000;

export function checkDurationCap(sm: Record<string, unknown>, em: Record<string, unknown>): NamedCheck {
  const capSec = em.caseMaxDurationSeconds as number | undefined;
  if (capSec == null) return { state: "skip", msg: "Лимит длительности не задан для этого кода" };
  const start = _tsMs(sm.recordingStartedAt);
  const end = _tsMs(em.recordingEndedAt);
  if (start == null || end == null) return { state: "skip", msg: "Нет обеих меток времени для проверки длительности" };
  const actualMs = end - start;
  if (actualMs < 0) return { state: "skip", msg: "Некорректные временные метки — проверка длительности невозможна" };
  const capMs = capSec * 1000;
  if (actualMs > capMs + DURATION_CAP_GRACE_MS) {
    return { state: "warn", msg: `Запись длиннее заявленного лимита компании (${Math.round(actualMs / 1000)}с при лимите ${capSec}с)` };
  }
  return { state: "pass", msg: `Длительность записи в пределах лимита компании (${Math.round(actualMs / 1000)}с из ${capSec}с)` };
}

function _tsMs(v: unknown): number | null {
  if (v == null) return null;
  const n = Number(v);
  return isNaN(n) ? null : n < 1e11 ? n * 1000 : n;
}
// Сверка со временем НА МАШИНЕ ЧИТАТЕЛЯ, а потому только пояснительная: fail
// эта проверка не возвращает и на вердикт не влияет. Часы того, кто открыл
// файл, доказательством не являются — севшая батарейка BIOS или машина из
// старого образа иначе объявляли бы подлинную съёмку подделкой.
// Подмену времени ловят checkServerClockDelta (расхождение часов телефона с
// нашим сервером, записанное в манифест) и
// checkAttestationChallengeFreshness (разовый вызов, подписанный сервером и
// вшитый чипом в сертификат) — оба понижают доверие сами.
export function checkTimestamp(ts: unknown): NamedCheck {
  const t = _tsMs(ts);
  if (t == null) return { state: "skip", msg: "Временная метка отсутствует" };
  const now = Date.now();
  const d = new Date(t).toLocaleDateString("ru-RU");
  if (t > now + 5 * 60 * 1000) return { state: "warn", msg: "Время записи (" + d + ") позже часов этого компьютера — проверьте дату у себя; на вердикт не влияет" };
  if (t < now - 30 * 24 * 60 * 60 * 1000) return { state: "warn", msg: "Запись старше 30 дней (" + d + ")" };
  return { state: "pass", msg: "Временная метка корректна (" + d + ")" };
}

/* Длина срока токена. С 5 сентября 2026 сервер вшивает её в сам токен
   префиксом «h<часы>.» — подпись сервера покрывает токен вместе со сроком,
   поэтому длина приходит подписанной и «не раньше» считается точно при любой
   настройке компании. Токены без префикса — по дате перехода. */
export function challengeTtlMs(challenge: unknown, expMs: number): number {
  const m = /^h(\d{1,2})\./.exec(String(challenge ?? ""));
  if (m) return Number(m[1]) * 60 * 60 * 1000;
  return expMs - CHALLENGE_TTL_MS >= CHALLENGE_TTL_SWITCH_MS ? CHALLENGE_TTL_MS : CHALLENGE_TTL_LEGACY_MS;
}

/* Причины понижения доверия — те же условия, что раньше стояли одним
   выражением в trustDowngrade, но по именам: по ним портал и браузер отличают
   «не подтверждено устройство» от «не подтверждён момент». Понижение только
   по времени = все причины из TIME_DOWNGRADE_REASONS. */
export const TIME_DOWNGRADE_REASONS = ["challengeFreshness", "serverClock", "gpstime", "deviceClock"];
/** Состояние именованной проверки. В `checks` лежит три вида значений, и
 *  спрашивать `.state` у булева нечего — тогда ответ undefined. Сужение, а
 *  не приведение: до 15 сентября 2026 здесь стояло `as NamedCheck`, и тип не
 *  проверял ничего. */
export function stateOf(v: CheckValue | undefined): CheckState | undefined {
  return v && typeof v === "object" ? v.state : undefined;
}

function _st(c: Record<string, CheckValue>, key: string): CheckState | undefined {
  return stateOf(c[key]);
}
export function downgradeReasonsOf(c: Record<string, CheckValue>): string[] {
  const r: string[] = [];
  if (c.attestation === "missing") r.push("attestation");
  if (_st(c, "oid") === "warn") r.push("oid");
  if (_st(c, "rootOfTrust") === "warn") r.push("rootOfTrust");
  /* Понижение, а не отказ: отзыв — утверждение о ключе СЕГОДНЯ, а съёмка была
     тогда. Отказ лишил бы человека возможности вообще открыть файл. */
  if (_st(c, "revoked") === "warn") r.push("revoked");
  if (_st(c, "keybound") === "warn") r.push("keybound");
  if (_st(c, "motion") === "warn") r.push("motion");
  /* exifGps здесь НЕТ намеренно. Подпись покрывает и описание, и EXIF, так что
     расхождение может вызвать только наша ошибка при записи копии, — и за неё
     не должен платить клиент понижением вердикта в своём споре. Расхождение
     видно отдельной строкой проверки. Решение владельца, 23.09.2026. */
  if (_st(c, "challengeFreshness") === "warn") r.push("challengeFreshness");
  if (_st(c, "serverClock") === "warn") r.push("serverClock");
  if (_st(c, "deviceClock") === "warn" && (c.deviceClock as { downgrade?: boolean }).downgrade) r.push("deviceClock");
  if (_st(c, "gpstime") === "warn" || _st(c, "gpstime") === "fail") r.push((c.gpstime as { vsAnchor?: boolean }).vsAnchor ? "location" : "gpstime");
  if (_st(c, "anchor") === "warn" && (c.anchor as { inconsistent?: boolean }).inconsistent) r.push("anchor");
  if (_st(c, "locationNet") === "warn") r.push("location");
  if (_st(c, "gnssPortrait") === "warn") r.push("location");
  if (_st(c, "durationCap") === "warn") r.push("durationCap");
  return r;
}
/** Четыре слова, которыми кончается проверка. Имена, а не русский текст:
 *  показывающая сторона переводит их сама — на странице, в кабинете, в отчёте
 *  формулировки разные. */
export type Verdict = "TRUSTED_CAPTURE" | "TIME_UNCONFIRMED" | "UNVERIFIED_DEVICE" | "TAMPERED";

/** Вердикт по результату проверки.
 *
 *  Правило простое, но до 15 сентября 2026 оно было выписано отдельно в каждом
 *  месте, где вердикт нужен, — в двух здешних инструментах и на сервере. Три
 *  копии одного правила расходятся молча: вердикт у них один на всех, и
 *  расхождение видно не в тесте, а у получателя файла.
 *
 *  Отказ разобрать пакет сюда не попадает: это не вердикт о съёмке, а
 *  сообщение, что перед нами не наш файл. Его бросает `PackageRejectedError`. */
export function verdictOf(result: { allPass: boolean; trustDowngrade: boolean; downgradeReasons?: string[] }): Verdict {
  if (!result.allPass) return "TAMPERED";
  if (!result.trustDowngrade) return "TRUSTED_CAPTURE";
  return isTimeOnlyDowngrade(result) ? "TIME_UNCONFIRMED" : "UNVERIFIED_DEVICE";
}

export function isTimeOnlyDowngrade(result: { downgradeReasons?: string[] }): boolean {
  const r = result.downgradeReasons ?? [];
  return r.length > 0 && r.every((x) => TIME_DOWNGRADE_REASONS.includes(x));
}

/* При целой привязке и спутниковом фиксе время приёмника сверяется с
   серверным моментом, а не с часами телефона: приёмник и сервер независимы
   друг от друга, и расхождение между ними — признак подмены сигнала
   (vsAnchor, причина «location»). Без привязки — прежняя сверка с часами. */
export function checkGpsTime(gpsTs: unknown, sysTs: unknown, anchorMomentMs: number | null = null, provider: unknown = null): NamedCheck {
  const g = _tsMs(gpsTs),
    s = _tsMs(sysTs);
  if (g == null) return { state: "skip", msg: "GPS время недоступно" };
  if (anchorMomentMs != null && provider === "gps") {
    const d = Math.abs(g - anchorMomentMs);
    const min = Math.round(d / 60000);
    if (d > 60 * 60 * 1000) return { state: "fail", msg: "Спутниковое время расходится с серверным на " + min + " мин — возможна подмена сигнала GPS", vsAnchor: true };
    if (d > 5 * 60 * 1000) return { state: "warn", msg: "Спутниковое время расходится с серверным на " + min + " мин", vsAnchor: true };
    return { state: "pass", msg: "Спутниковое время совпадает с серверным (±" + Math.round(d / 1000) + "с)", vsAnchor: true };
  }
  if (s == null) return { state: "skip", msg: "Системное время недоступно" };
  const diff = Math.abs(g - s);
  if (diff > 60 * 60 * 1000) return { state: "fail", msg: "GPS/системное время расходятся на " + Math.round(diff / 60000) + " мин — возможна манипуляция" };
  if (diff > 5 * 60 * 1000) return { state: "warn", msg: "GPS/системное время расходятся на " + Math.round(diff / 60000) + " мин" };
  return { state: "pass", msg: "GPS и системное время совпадают (±" + Math.round(diff / 1000) + "с)" };
}

export async function checkKeyBinding(pubKeyB64: string | undefined, attChain: string[] | undefined): Promise<NamedCheck> {
  if (!pubKeyB64 || !attChain || !attChain.length) return { state: "skip", msg: "Аттестация отсутствует — проверка привязки ключа невозможна" };
  try {
    const leafDer = base64ToBytes(attChain[0]);
    const { spkiBytes } = parseCertForVerify(leafDer);
    const manifestSpki = base64ToBytes(pubKeyB64);
    if (spkiBytes.length !== manifestSpki.length) return { state: "fail", msg: "Ключ манифеста НЕ совпадает с ключом TEE — возможна подделка" };
    for (let i = 0; i < spkiBytes.length; i++)
      if (spkiBytes[i] !== manifestSpki[i]) return { state: "fail", msg: "Ключ манифеста НЕ совпадает с ключом TEE — возможна подделка" };
    return { state: "pass", msg: "Ключ манифеста совпадает с ключом в сертификате TEE" };
  } catch (e) {
    return { state: "warn", msg: "Не удалось проверить привязку ключа: " + (e as Error).message };
  }
}

const CROSS_MAX_PLAUSIBLE_KMH = 1000;

function haversineKm(lat1: number, lng1: number, lat2: number, lng2: number): number {
  const R = 6371;
  const toRad = (d: number) => (d * Math.PI) / 180;
  const dLat = toRad(lat2 - lat1);
  const dLng = toRad(lng2 - lng1);
  const a = Math.sin(dLat / 2) ** 2 + Math.cos(toRad(lat1)) * Math.cos(toRad(lat2)) * Math.sin(dLng / 2) ** 2;
  return R * 2 * Math.atan2(Math.sqrt(a), Math.sqrt(1 - a));
}

function checkWithinFileMotion(em: Record<string, unknown>): NamedCheck & { distKm?: number; hours?: number; speedKmh?: number } {
  if (em.latitude == null || em.longitude == null || em.gpsStartTime == null) return { state: "na" };
  if (em.endLatitude == null || em.endLongitude == null || em.gpsEndTime == null) return { state: "na" };
  const dtMs = Math.abs((em.gpsEndTime as number) - (em.gpsStartTime as number));
  if (dtMs === 0) return { state: "na" };
  const distKm = haversineKm(em.latitude as number, em.longitude as number, em.endLatitude as number, em.endLongitude as number);
  const hours = dtMs / 3600000;
  const speedKmh = distKm / hours;
  return { state: speedKmh > CROSS_MAX_PLAUSIBLE_KMH ? "warn" : "ok", distKm, hours, speedKmh };
}

// Защита от zip-бомбы живёт не здесь, а в zip-extract.ts: степень сжатия
// проверяется до распаковки, по размерам из оглавления самого архива.

/**
 * Проверяет один уже разобранный пакет `.trustvisor`.
 *
 * Безопасность разбора — забота вызывающего: из недоверенной загрузки должны
 * быть извлечены только ожидаемые записи с их именами, с ограничением размера
 * и степени сжатия. Как это делается — в zip-extract.ts.
 */
/** Необязательные настройки проверки.
 *
 *  Пока здесь одно: свежий список отозванных ключей аттестации. Сервер всегда
 *  в сети и обязан сверяться с живым списком; страница проверки работает без
 *  сети и обходится вшитым снимком с датой. Одно ядро обслуживает оба случая,
 *  и разница видна в месте вызова, а не спрятана в состоянии модуля. */
export interface VerifyOptions {
  /** Свежий список серийных номеров (нижний регистр, без ведущих нулей). */
  revoked?: ReadonlySet<string>;
  /** Дата этого списка — уходит в текст проверки, чтобы человек знал, на какое
   *  число мы отвечаем. */
  revokedDate?: string;
}

export async function verifyPackage(entries: PackageEntries, opts?: VerifyOptions): Promise<VerifyResult> {
  const isPhoto = entries.photoBuffer !== undefined;
  const result: VerifyResult = {
    isPhoto,
    fileName: entries.fileName,
    checks: {},
    allPass: true,
    trustDowngrade: false,
    downgradeReasons: [],
    meta: null,
    mediaBuffer: new ArrayBuffer(0),
    mediaType: "",
    mediaName: "",
  };

  if (isPhoto) {
    const photoMan = manifestPair(entries.manifestJsonBytes, entries.manifestJson);
    if (!photoMan.text || !entries.photoBuffer) throw new Error("Пакет не содержит manifest.json или photo.png");
    let manifest: Record<string, unknown>;
    try {
      manifest = JSON.parse(photoMan.text);
    } catch {
      throw new Error("manifest.json — не валидный JSON.");
    }
    result.meta = manifest;
    const pubKeyB64 = manifest.publicKey as string | undefined;
    result.checks.pubkey = !!(pubKeyB64 && pubKeyB64.length > 0);
    if (!result.checks.pubkey) result.allPass = false;
    let pubKey: CryptoKey | null = null;
    if (pubKeyB64) {
      try {
        pubKey = await importSpkiKey(pubKeyB64);
      } catch {
        pubKey = null;
      }
    }
    const photoHex = await sha256Bytes(entries.photoBuffer);
    /* Развилка форматов. Отката НЕТ ни в одну сторону: пакет с записью
       подписи проверяется ТОЛЬКО по правилам 2.0, и несошедшаяся подпись —
       это «изменён», а не «дай попробую по-старому». Иначе достаточно было
       бы испортить запись подписи, чтобы файл поехал по старому пути. */
    let jws: DetachedJws | null = null;
    let jwsError: string | null = null;
    if (entries.manifestJwsBytes) {
      try {
        jws = parseDetachedJws(entries.manifestJwsBytes);
        assertNoV1Fields(manifest);
        assertManifestWellFormed(photoMan.bytes, "manifest.json");
      } catch (e) {
        jwsError = (e as Error).message;
      }
    }
    result.formatError = jwsError;
    /* Подпись сервера: ключ берётся из закреплённого списка, а не из
       манифеста. Манифест обязан объявлять ТОТ ЖЕ ключ — иначе файл говорит о
       себе одно, а подписан другим, и читать его дальше незачем. */
    if (jws && jws.kid) {
      const pinned = TRUSTVISOR_WEB_SIGNING_KEYS[jws.kid];
      if (pubKeyB64 !== pinned) {
        result.checks.pubkey = false;
        result.allPass = false;
        pubKey = null;
      } else {
        try {
          pubKey = await importSpkiKey(pinned);
        } catch {
          pubKey = null;
        }
      }
    }
    let sigOk = false;
    if (pubKey && !jwsError) {
      try {
        sigOk = jws
          ? await verifyDetachedJws(jws, photoMan.bytes!, pubKey)
          : await verifyManifestSig("фотографии", manifest, pubKey, photoMan.bytes);
      } catch {
        sigOk = false;
      }
    }
    result.checks.sig = sigOk;
    if (!sigOk) result.allPass = false;
    /* В формате 2.0 цепочка аттестации живёт в защищённом заголовке подписи
       (`x5c`), а не в манифесте, — и тем самым впервые оказывается ПОД
       подписью. В 1.x она дописывалась после подписания и подписью не
       покрывалась. */
    const attChain = jws ? jws.x5c : (manifest.attestationChain as string[] | undefined);
    let attOk1 = false;
    if (attChain && Array.isArray(attChain) && attChain.length > 0) {
      try {
        attOk1 = await verifyAttestationChain(attChain);
      } catch {
        attOk1 = false;
      }
      result.checks.attestation = attOk1;
      if (!attOk1) result.allPass = false;
    } else {
      result.checks.attestation = "missing";
    }
    result.checks.oid = checkOid(attOk1, attChain, _tsMs(manifest.capturedAt));
    if (stateOf(result.checks.oid) === "fail") result.allPass = false;
    result.checks.rootOfTrust = checkRootOfTrust(attOk1, attChain);
    result.checks.revoked = checkAttestationRevoked(attOk1, attChain, opts?.revoked, opts?.revokedDate);
    const fresh1 = await checkAttestationChallengeFreshness(attOk1, attChain, manifest, _tsMs(manifest.capturedAt));
    const anchor1 = checkServerAnchor(manifest, fresh1);
    result.checks.anchor = anchor1;
    result.checks.challengeFreshness = withAnchorWitness(fresh1, anchor1);
    if (stateOf(result.checks.challengeFreshness) === "fail") result.allPass = false;
    const moment1 = anchor1.state === "pass" && anchor1.momentMs != null ? anchor1.momentMs : null;
    result.checks.gpstime = checkGpsTime(manifest.gpsCapturedAt, manifest.capturedAt, moment1, manifest.locationProvider);
    result.checks.serverClock = moment1 != null ? { state: "skip", msg: "Заменена привязкой к серверному времени" } : checkServerClockDelta(manifest);
    result.checks.deviceClock = checkDeviceClock(_tsMs(manifest.capturedAt), anchor1, manifest);
    result.checks.locationMock = checkLocationMock(manifest);
    result.checks.locationNet = checkLocationSecondOpinion(manifest);
    result.checks.gnssPortrait = checkGnssPortrait(manifest);
    _setMoment(result, anchor1, result.checks.challengeFreshness as NamedCheck, _tsMs(manifest.capturedAt), result.checks.deviceClock as NamedCheck, manifest.locationMockSeen === true);
    /* Тип проверяем, а не предполагаем: поле приходит из JSON, и
       "photoSha256": 123 роняло разбор исключением наружу вместо честного
       вердикта ИЗМЕНЁН. */
    const expectedHash: unknown = manifest.photoSha256;
    if (typeof expectedHash !== "string") {
      result.checks.hash = false;
      result.allPass = false;
    } else {
      result.checks.hash = photoHex === expectedHash.toLowerCase();
      if (!result.checks.hash) result.allPass = false;
    }
    /* Сверка EXIF с подписанным. Довод для того, кто привык смотреть в EXIF:
       он там теперь есть, он совпадает, и за совпадение ручается подпись. */
    result.checks.exifGps = checkExifGps(
      entries.photoBuffer ? new Uint8Array(entries.photoBuffer) : undefined, manifest);
    result.checks.sensorLog = await checkSensorLog(manifest, entries.sensorLogBytes);
    if (stateOf(result.checks.sensorLog) === "fail") result.allPass = false;
    result.sensorLogBytes = entries.sensorLogBytes;
    result.checks.timestamp = checkTimestamp(manifest.capturedAt);
    result.checks.keybound = await checkKeyBinding(pubKeyB64, attChain);
    if (stateOf(result.checks.keybound) === "fail") result.allPass = false;
    result.downgradeReasons = downgradeReasonsOf(result.checks);
    result.trustDowngrade = result.downgradeReasons.length > 0;
    result.mediaBuffer = entries.photoBuffer;
    result.mediaType = "image/png";
    result.mediaName = "photo.png";
  } else {
    const startMan = manifestPair(entries.manifestStartJsonBytes, entries.manifestStartJson);
    const endMan = manifestPair(entries.manifestEndJsonBytes, entries.manifestEndJson);
    if (!startMan.text || !endMan.text || (!entries.videoBuffer && !entries.videoDigest))
      throw new Error("Пакет не содержит manifest_start.json / manifest_end.json / video.mp4");
    let sm: Record<string, unknown>, em: Record<string, unknown>;
    try {
      sm = JSON.parse(startMan.text);
    } catch {
      throw new Error("manifest_start.json — не валидный JSON.");
    }
    try {
      em = JSON.parse(endMan.text);
    } catch {
      throw new Error("manifest_end.json — не валидный JSON.");
    }
    const emVersion = parseFloat(em.manifestVersion as string);
    if (!em.manifestVersion || isNaN(emVersion) || emVersion < 1.1)
      throw new Error(
        "Неподдерживаемый формат пакета (manifestVersion: " +
          (em.manifestVersion != null ? em.manifestVersion : "отсутствует") +
          ")."
      );
    result.meta = { sm, em };
    result.checks.session = !!(sm.sessionId != null && em.sessionId != null && sm.sessionId === em.sessionId && (em.sessionIdCheck == null || em.sessionIdCheck === em.sessionId));
    if (!result.checks.session) result.allPass = false;
    const pubKeyB64 = sm.publicKey as string | undefined;
    result.checks.pubkey = !!(pubKeyB64 != null && em.publicKey != null && pubKeyB64 === em.publicKey);
    if (!result.checks.pubkey) result.allPass = false;
    let pubKey: CryptoKey | null = null;
    if (pubKeyB64) {
      try {
        pubKey = await importSpkiKey(pubKeyB64);
      } catch {
        pubKey = null;
      }
    }
    /* Хэш видео — либо своими силами по буферу, либо готовый от разборщика,
       который считал его, пока читал файл (см. PackageEntries.videoDigest).
       Отпечаток не того вида — не повод верить: он просто не сойдётся. */
    const videoHex = entries.videoBuffer
      ? await sha256Bytes(entries.videoBuffer)
      : /^[0-9a-f]{64}$/.test(entries.videoDigest!.sha256Hex) ? entries.videoDigest!.sha256Hex : "";
    const videoSize = entries.videoBuffer ? entries.videoBuffer.byteLength : entries.videoDigest!.size;
    /* Развилка форматов, как в ветке фото. Для видео ОБЕ подписи
       обязательны: нет одной, не сошлась одна — ИЗМЕНЁН. Разбор пакета к
       этому моменту уже отверг бы пакет с одной записью подписи, но
       полагаться на это одно нельзя: сюда ходят и другие входы. */
    let jwsStart: DetachedJws | null = null;
    let jwsEnd: DetachedJws | null = null;
    let jwsError: string | null = null;
    if (entries.manifestStartJwsBytes || entries.manifestEndJwsBytes) {
      try {
        if (!entries.manifestStartJwsBytes || !entries.manifestEndJwsBytes) {
          throw new Error("У видео обязаны быть обе записи подписи");
        }
        jwsStart = parseDetachedJws(entries.manifestStartJwsBytes);
        jwsEnd = parseDetachedJws(entries.manifestEndJwsBytes);
        assertNoV1Fields(sm);
        assertNoV1Fields(em);
        assertManifestWellFormed(startMan.bytes, "manifest_start.json");
        assertManifestWellFormed(endMan.bytes, "manifest_end.json");
      } catch (e) {
        jwsError = (e as Error).message;
        jwsStart = null;
        jwsEnd = null;
      }
    }
    result.formatError = jwsError;
    let sigStartOk = false;
    if (pubKey && !jwsError) {
      try {
        sigStartOk = jwsStart
          ? await verifyDetachedJws(jwsStart, startMan.bytes!, pubKey)
          : await verifyManifestSig("начала", sm, pubKey, startMan.bytes);
      } catch {
        sigStartOk = false;
      }
    }
    result.checks.sigStart = sigStartOk;
    if (!sigStartOk) result.allPass = false;
    let sigEndOk = false;
    if (pubKey && !jwsError) {
      try {
        sigEndOk = jwsEnd
          ? await verifyDetachedJws(jwsEnd, endMan.bytes!, pubKey)
          : await verifyManifestSig("конца", em, pubKey, endMan.bytes);
      } catch {
        sigEndOk = false;
      }
    }
    result.checks.sigEnd = sigEndOk;
    if (!sigEndOk) result.allPass = false;
    /* Цепочка берётся из заголовка подписи начала: она под подписью, тогда
       как `attestationChain` формата 1.x подписью не покрыт. */
    const attChain = jwsStart ? jwsStart.x5c
      : ((em.attestationChain as string[] | undefined) || (sm.attestationChain as string[] | undefined));
    let attOk2 = false;
    if (attChain && Array.isArray(attChain) && attChain.length > 0) {
      try {
        attOk2 = await verifyAttestationChain(attChain);
      } catch {
        attOk2 = false;
      }
      result.checks.attestation = attOk2;
      if (!attOk2) result.allPass = false;
    } else {
      result.checks.attestation = "missing";
    }
    result.checks.oid = checkOid(attOk2, attChain, _tsMs(sm.recordingStartedAt));
    if (stateOf(result.checks.oid) === "fail") result.allPass = false;
    result.checks.rootOfTrust = checkRootOfTrust(attOk2, attChain);
    result.checks.revoked = checkAttestationRevoked(attOk2, attChain, opts?.revoked, opts?.revokedDate);
    const fresh2 = await checkAttestationChallengeFreshness(attOk2, attChain, em, _tsMs(sm.recordingStartedAt));
    /* Привязка старт-манифеста — момент начала записи (end-манифест несёт
       свою, на момент остановки; для вердикта важен старт). */
    const anchor2 = checkServerAnchor(sm, fresh2);
    result.checks.anchor = anchor2;
    result.checks.challengeFreshness = withAnchorWitness(fresh2, anchor2);
    if (stateOf(result.checks.challengeFreshness) === "fail") result.allPass = false;
    const moment2 = anchor2.state === "pass" && anchor2.momentMs != null ? anchor2.momentMs : null;
    result.checks.gpstime = checkGpsTime(sm.gpsStartTime != null ? sm.gpsStartTime : em.gpsStartTime, sm.recordingStartedAt, moment2, sm.locationProvider != null ? sm.locationProvider : em.locationProvider);
    result.checks.serverClock = moment2 != null ? { state: "skip", msg: "Заменена привязкой к серверному времени" } : checkServerClockDelta(em);
    result.checks.deviceClock = checkDeviceClock(_tsMs(sm.recordingStartedAt), anchor2, sm);
    result.checks.locationMock = checkLocationMock(em.locationMockSeen === true ? em : sm);
    result.checks.locationNet = checkLocationSecondOpinion(em);
    result.checks.gnssPortrait = checkGnssPortrait(em);
    _setMoment(result, anchor2, result.checks.challengeFreshness as NamedCheck, _tsMs(sm.recordingStartedAt), result.checks.deviceClock as NamedCheck, em.locationMockSeen === true || sm.locationMockSeen === true);
    /* Тип проверяем, а не предполагаем — см. ту же правку в ветке фото. */
    const expectedHash: unknown = em.videoSha256;
    if (typeof expectedHash !== "string") {
      result.checks.hash = false;
      result.allPass = false;
    } else if (videoSize === 0 || videoHex === "") {
      result.checks.hash = false;
      result.allPass = false;
    } else {
      result.checks.hash = videoHex === expectedHash.toLowerCase();
      if (!result.checks.hash) result.allPass = false;
    }
    result.checks.sensorLog = await checkSensorLog(em, entries.sensorLogBytes);
    if (stateOf(result.checks.sensorLog) === "fail") result.allPass = false;
    result.sensorLogBytes = entries.sensorLogBytes;
    result.checks.timestamp = checkTimestamp(sm.recordingStartedAt);
    result.checks.keybound = await checkKeyBinding(sm.publicKey as string | undefined, attChain);
    if (stateOf(result.checks.keybound) === "fail") result.allPass = false;
    result.checks.motion = checkWithinFileMotion(em);
    result.checks.durationCap = checkDurationCap(sm, em);
    result.downgradeReasons = downgradeReasonsOf(result.checks);
    result.trustDowngrade = result.downgradeReasons.length > 0;
    result.mediaBuffer = entries.videoBuffer ?? new ArrayBuffer(0);
    result.mediaType = "video/mp4";
    result.mediaName = "video.mp4";
  }
  return result;
}
