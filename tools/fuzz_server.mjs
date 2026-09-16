/* Прогон набора перебора через СЕРВЕРНЫЙ верификатор.
   Запускается из корня проекта, рядом с собранным ядром проверки.
   Печатает JSON: имя случая → вердикт. */
import { readdirSync, createReadStream, unlinkSync } from 'node:fs';
import { join } from 'node:path';
import { extractPackage, PackageRejectedError } from '../dist/zip-extract.js';
import { verifyPackage, verdictOf } from '../dist/verify-core/verify-core.js';

/* По умолчанию — туда, куда пишет fuzz_gen.py. */
const DIR = process.argv[2] || 'tools/corpus';
const out = {};

for (const f of readdirSync(DIR).filter((n) => n.endsWith('.trustvisor')).sort()) {
  const name = f.replace(/\.trustvisor$/, '');
  const src = join(DIR, f);
  const tmp = src + '.tmp';
  try {
    const entries = await extractPackage(createReadStream(src), f, tmp);
    const r = await verifyPackage(entries);
    /* Три вердикта, а не два: понижение только по времени — это «МОМЕНТ НЕ
       ПОДТВЕРЖДЁН», и сливать его с «НЕ АТТЕСТОВАНО» значит терять разницу,
       ради которой оба и заведены. */
    /* Слово выводит ядро: правило вердикта живёт в одном месте.
       Здесь только имена набора — с подчёркиванием, чтобы вердикт из двух
       слов не разъезжался в выводе. */
    out[name] = { TRUSTED_CAPTURE: 'ПОДЛИННО', TIME_UNCONFIRMED: 'МОМЕНТ_НЕ_ПОДТВЕРЖДЁН',
                  UNVERIFIED_DEVICE: 'НЕ_АТТЕСТОВАНО', TAMPERED: 'ИЗМЕНЁН' }[verdictOf(r)];
  } catch (e) {
    /* И отказ разборщика, и любая другая ошибка для сравнения одинаковы:
       файл не принят. Тексты сообщений специально НЕ сравниваем — известно,
       что часть из них у двух сторон отличается формулировкой при одинаковом
       вердикте, и это не расхождение. */
    out[name] = 'ОТКАЗ';
    if (!(e instanceof PackageRejectedError) && !/JSON|формат|Пакет|манифест|Оглавление|архив/i.test(String(e.message))) {
      /* Отказ уже записан выше; здесь только помечаем непривычную причину,
         чтобы её было видно в выводе. */
      out['__note_' + name] = String(e.message).slice(0, 120);
    }
  } finally {
    try { unlinkSync(tmp); } catch {}
  }
}

console.log(JSON.stringify(out));
