/* Приговор набору перебора: какие случаи могут остаться подлинными.

   fuzz_server.mjs печатает вердикты и только. Смотреть глазами на 301 строку
   бессмысленно: разницу в одну строку человек не замечает, а именно она и
   означает, что порча начала проходить. Здесь эти вердикты сверяются с
   правилом.

   Правило несимметрично, и это нарочно:

     * `000_clean` обязан быть ПОДЛИННО. Это не порча, а исходный файл: если
       он не проходит, сломана проверка живых съёмок, а не заслон.
     * `descriptor_signed` и `descriptor_bare` обязаны быть ПОДЛИННО. Это две
       раскладки, которыми пишет само приложение; обе честные.
     * Остальные могут дать ПОДЛИННО, только если названы ниже. Любой
       неназванный случай с вердиктом ПОДЛИННО — поломка.

   Почему «вправе», а не «обязаны»: перечисленные ниже — пересборки, которые
   ничего не меняют по существу (пробелы в JSON, порядок записей, хранение
   без сжатия). В формате 1.x они проходят, потому что подпись считается по
   восстановленной форме. В формате 2.0 подписаны сырые байты манифеста, и те
   же пересборки дают ИЗМЕНЁН. Требовать от них ПОДЛИННО значило бы объявить
   поломкой то, что проверка стала строже.

   Прогон целиком:

       python tools/fuzz_gen.py samples/genuine-photo.trustvisor
       node   tools/fuzz_server.mjs tools/corpus > /tmp/verdicts.json
       node   tools/fuzz_check.mjs /tmp/verdicts.json

   Код возврата 1, если правило нарушено. */
import { readFileSync } from 'node:fs';

const MUST_PASS = ['000_clean', 'descriptor_signed', 'descriptor_bare'];

/* Пересборки без изменения существа. Каждая — отдельная строка, потому что
   обобщать тут нечего: это перечень того, что мы считаем тем же
   самым файлом. */
const MAY_PASS = new Set([
  'names_reversed_order',   // записи архива в другом порядке
  'stored_all',             // архив без сжатия
  'text_crlf',              // перевод строки CRLF
  'text_tabs',              // отступ табуляцией
  'text_leading_space',
  'text_leading_newline',
  'text_trailing_space',
  'text_trailing_newline',
]);

const file = process.argv[2];
if (!file) {
  console.error('использование: node tools/fuzz_check.mjs <вывод fuzz_server.mjs>');
  process.exit(2);
}

const verdicts = JSON.parse(readFileSync(file, 'utf8'));
const cases = Object.keys(verdicts).filter((k) => !k.startsWith('__note_'));
if (cases.length < 100) {
  console.error(`случаев всего ${cases.length} — набор не собрался, сверять нечего`);
  process.exit(1);
}

const broken = [];
for (const name of MUST_PASS) {
  if (!(name in verdicts)) broken.push(`${name}: случая нет в наборе`);
  else if (verdicts[name] !== 'ПОДЛИННО') broken.push(`${name}: ${verdicts[name]}, а обязан быть ПОДЛИННО`);
}
const leaked = cases.filter(
  (n) => verdicts[n] === 'ПОДЛИННО' && !MUST_PASS.includes(n) && !MAY_PASS.has(n),
);
for (const n of leaked) broken.push(`${n}: ПОДЛИННО, хотя это порча`);

if (broken.length) {
  console.error('НАБОР ПЕРЕБОРА НЕ СХОДИТСЯ:');
  for (const b of broken) console.error('  ' + b);
  process.exit(1);
}

const passed = cases.filter((n) => verdicts[n] === 'ПОДЛИННО');
console.log(`случаев ${cases.length}, подлинными остались ${passed.length} — все названы в правиле`);
