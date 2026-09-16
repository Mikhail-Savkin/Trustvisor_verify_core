// SPDX-License-Identifier: Apache-2.0
/* Проверить файл TrustVisor из командной строки.
 *
 *     npm install && npm run build
 *     node tools/verify.mjs путь/к/файлу.trustvisor
 *
 * Принимает и подписанное медиа: .jpg, .png, .mp4 — те же файлы, что отдаёт
 * приложение кнопкой «поделиться как медиа».
 *
 * В сеть не ходит. Всё, что нужно для вердикта, лежит внутри файла и в списке
 * доверенных корней (src/verify-core/trusted-roots.ts).
 *
 * Код возврата: 0 — ПОДЛИННО, 1 — вердикт хуже, 2 — файл не наш или не
 * разобрался. Это позволяет звать проверку из скрипта, а не только глазами.
 */
import { createReadStream, existsSync } from "node:fs";
import { unlink } from "node:fs/promises";
import { basename, join } from "node:path";
import { tmpdir } from "node:os";
import { randomUUID } from "node:crypto";

import { extractPackage, PackageRejectedError } from "../dist/zip-extract.js";
import { verifyPackage, verdictOf } from "../dist/verify-core/verify-core.js";

const src = process.argv[2];
if (!src || !existsSync(src)) {
  console.error("использование: node tools/verify.mjs <файл>");
  console.error("файл может быть .trustvisor, .jpg, .png или .mp4");
  process.exit(2);
}

const tempPath = join(tmpdir(), "trustvisor-verify-" + randomUUID());
let entries;
try {
  entries = await extractPackage(createReadStream(src), basename(src), tempPath);
} catch (e) {
  /* Отказ разобрать — это НЕ вердикт «изменён». Файл не является пакетом
     TrustVisor, и сказать надо именно это: получателю разница важна.

     Сообщения библиотеки разбора наружу не выпускаем первой строкой: они на
     английском и говорят о внутренностях («end of central directory record
     signature not found»). Человеку, который принёс не тот файл, это ничего
     не объясняет — но ниже показываем, для отладки. */
  const ours = e instanceof PackageRejectedError;
  console.error(ours
    ? "Файл не является пакетом TrustVisor: " + e.message
    : "Не удалось прочитать файл: похоже, это не пакет TrustVisor и не подписанное медиа.");
  if (!ours) console.error("Подробность разборщика: " + String(e.message).slice(0, 120));
  process.exit(2);
} finally {
  await unlink(tempPath).catch(() => {});
}

/* Проверка тоже умеет бросать — например, на пустом манифесте. Без этой
   обёртки человек вместо вердикта получал стек Node; поймано первым же
   прогоном набора порчи медиа (tools/fuzz_media.py). */
let result;
try {
  result = await verifyPackage(entries);
} catch (e) {
  console.error("Файл не удалось проверить: " + e.message);
  console.error("Это не вердикт «изменён» — пакет разобрался, но его содержимое "
    + "не годится для проверки.");
  process.exit(2);
}

/* Слово выводит ядро, здесь только перевод на русский: правило вердикта
   обязано жить в одном месте. */
const СЛОВА = {
  TRUSTED_CAPTURE: "ПОДЛИННО",
  TIME_UNCONFIRMED: "МОМЕНТ НЕ ПОДТВЕРЖДЁН",
  UNVERIFIED_DEVICE: "НЕ АТТЕСТОВАНО",
  TAMPERED: "ИЗМЕНЁН",
};
const verdict = СЛОВА[verdictOf(result)];

const meta = result.isPhoto ? result.meta : result.meta.em;
const iso = (ms) => (typeof ms === "number" ? new Date(ms).toISOString() : "—");

console.log("");
console.log("  " + verdict);
if (result.downgradeReasons?.length) {
  console.log("  причины понижения: " + result.downgradeReasons.join(", "));
}
console.log("");
console.log("  что снято      " + (result.isPhoto ? "фотография" : "видео"));
console.log("  устройство     " + (meta.deviceModel ?? "—"));
console.log("  момент съёмки  " + iso(result.momentMs) +
  (result.momentSource ? "   (источник: " + result.momentSource + ")" : ""));
if (typeof result.deviceClockShiftMs === "number") {
  console.log("  часы телефона  сдвиг " + Math.round(result.deviceClockShiftMs / 60000) + " мин");
}
if (typeof meta.latitude === "number") {
  console.log("  координаты     " + meta.latitude + ", " + meta.longitude +
    (meta.locationAccuracy ? "  ±" + Math.round(meta.locationAccuracy) + " м" : ""));
}
console.log("");

/* Показываем ВСЕ проверки, а не только провалившиеся: читателю важно видеть,
   что именно подтверждено, а не только что сломано. */
const ORDER = ["attestation", "oid", "rootOfTrust", "keybound", "challengeFreshness",
               "anchor", "deviceClock", "serverClock", "gpstime", "locationMock",
               "locationNet", "gnssPortrait", "sensorLog", "timestamp"];
const MARK = { pass: "+", warn: "!", skip: ".", fail: "x" };

for (const name of ORDER) {
  const check = result.checks[name];
  if (check === undefined) continue;
  const state = typeof check === "object" ? check.state : (check ? "pass" : "fail");
  const note = typeof check === "object" && check.msg ? "  " + check.msg : "";
  console.log("  [" + (MARK[state] ?? "?") + "] " + name.padEnd(20) + state + note);
}
/* Остальные проверки — простые «да/нет», без пояснения: подпись, хеш, ключ. */
for (const [name, value] of Object.entries(result.checks)) {
  if (ORDER.includes(name) || typeof value === "object") continue;
  console.log("  [" + (value ? "+" : "x") + "] " + name.padEnd(20) + (value ? "pass" : "fail"));
}
console.log("");
console.log("  Проверка не обращалась к сети.");
console.log("");

process.exit(verdict === "ПОДЛИННО" ? 0 : 1);
