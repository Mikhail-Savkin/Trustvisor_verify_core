// SPDX-License-Identifier: Apache-2.0
/* Собрать пакет формата 2.0 из настоящей съёмки формата 1.x.
 *
 *     node tools/make_v2.mjs <настоящий .trustvisor> <куда.trustvisor> [порча]
 *
 * Формат 2.0 переносит подпись в отдельную запись, и проверить этот
 * путь до выпуска приложения больше нечем: настоящих файлов 2.0 не
 * существует.
 *
 * ЧЕГО ЭТОТ СБОРЩИК НЕ МОЖЕТ — и это ограничение замысла, а не стенда.
 * Настоящую подпись делает ключ внутри защищённого чипа телефона, вынуть его
 * нельзя. Поэтому здесь берётся КОНТРОЛЬНЫЙ ключ, создаваемый на месте, и
 * `publicKey` манифеста заменяется на него.
 *
 * Следствие, которое надо держать в голове, читая результат: у такого пакета
 * подпись сходится (это и проверяем), а привязка ключа к цепочке аттестации
 * НЕ сходится — цепочка осталась настоящей, от телефона, и её лист с нашим
 * контрольным ключом не совпадает. Так и должно быть. Вердикт ПОДЛИННО на
 * формате 2.0 доказуем только настоящей съёмкой новым приложением.
 *
 * Порча (необязательный третий аргумент) — имя случая из CASES ниже: тем же
 * сборщиком делается набор для перебора, чтобы испорченные файлы отличались
 * от честного ровно одним изменением.
 */
import { readFileSync, writeFileSync } from "node:fs";
import { generateKeyPairSync, sign } from "node:crypto";
import { execFileSync } from "node:child_process";

const [src, dst, damage] = process.argv.slice(2);
if (!src || !dst) {
  console.error("использование: node tools/make_v2.mjs <из.trustvisor> <в.trustvisor> [порча]");
  process.exit(2);
}

/* Разбор и сборка ZIP — через Python: он уже умеет и то и другое, а вторая
   реализация ZIP в проекте нам не нужна ни под каким видом. */
const PY = String.raw`
import base64, io, json, sys, zipfile
src, dst, payload = sys.argv[1], sys.argv[2], sys.argv[3]
spec = json.loads(io.open(payload, encoding="utf-8").read())
zin = zipfile.ZipFile(src)
with zipfile.ZipFile(dst, "w", zipfile.ZIP_DEFLATED) as zout:
    for info in zin.infolist():
        name = info.filename
        if name in spec["manifests"]:
            zout.writestr(name, base64.b64decode(spec["manifests"][name]))
        else:
            zout.writestr(name, zin.read(name))
    for name, b64 in spec["jws"].items():
        zout.writestr(name, base64.b64decode(b64))
print("записей:", len(zipfile.ZipFile(dst).namelist()))
`;

const buf = readFileSync(src);
/* Читаем манифесты тем же Python — один разборщик на весь инструмент. */
const listed = execFileSync("python", ["-c", String.raw`
import io, json, sys, zipfile, base64
z = zipfile.ZipFile(sys.argv[1])
out = {n: base64.b64encode(z.read(n)).decode() for n in z.namelist() if n.endswith(".json")}
print(json.dumps(out))
`, src], { encoding: "utf8" });
const raw = JSON.parse(listed);

const { privateKey, publicKey } = generateKeyPairSync("ec", { namedCurve: "prime256v1" });
const spki = publicKey.export({ type: "spki", format: "der" }).toString("base64");
const b64u = (b) => Buffer.from(b).toString("base64url");

const CASES = {
  clean: (s) => s,
  jws_space: (s) => s.slice(0, 20) + " " + s.slice(20),
  jws_padding: (s) => s + "=",
  jws_one_dot: (s) => s.replace("..", "."),
  jws_sig_short: (s) => s.slice(0, -1),
  jws_bom: (s) => "﻿" + s,
  jws_empty: () => "",
};
const damageFn = CASES[damage ?? "clean"];
if (!damageFn) {
  console.error("неизвестная порча: " + damage + "; есть " + Object.keys(CASES).join(", "));
  process.exit(2);
}

const manifests = {}, jws = {};
let chain = null;
for (const [name, b64] of Object.entries(raw)) {
  const m = JSON.parse(Buffer.from(b64, "base64").toString("utf8"));
  chain = chain ?? m.attestationChain;
  /* Три поля формата 1.x уходят: на их отсутствии стоит различение форматов. */
  delete m.signature; delete m.signatureAlgorithm; delete m.attestationChain;
  m.publicKey = spki;
  m.manifestVersion = "2.0";
  /* Отступы в два пробела — как пишет приложение. В формате 2.0 это уже
     безразлично для подписи, и ровно в этом смысл реформы. */
  const bytes = Buffer.from(JSON.stringify(m, null, 2), "utf8");
  manifests[name] = bytes.toString("base64");

  const header = {
    alg: "ES256", b64: false, crit: ["b64"],
    typ: "application/trustvisor-manifest+json",
    x5c: chain,
  };
  const prot = b64u(Buffer.from(JSON.stringify(header), "utf8"));
  const input = Buffer.concat([Buffer.from(prot, "ascii"), Buffer.from("."), bytes]);
  const sig = sign("sha256", input, { key: privateKey, dsaEncoding: "ieee-p1363" });
  jws[name + ".jws"] = Buffer.from(damageFn(prot + ".." + b64u(sig)), "utf8").toString("base64");
}

const tmp = dst + ".spec.json";
writeFileSync(tmp, JSON.stringify({ manifests, jws }), "utf8");
console.log(execFileSync("python", ["-c", PY, src, dst, tmp], { encoding: "utf8" }).trim());
console.log("порча:", damage ?? "нет (честный файл)");
console.log("контрольный ключ одноразовый: привязка к цепочке НЕ сойдётся, так и задумано");
