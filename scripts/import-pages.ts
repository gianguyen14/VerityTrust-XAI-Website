/**
 * Chuyển trang HTML thô (JSONL {url, label, html}) sang định dạng huấn luyện của scripts/train-content-model.ts
 * ({url, label, owner, html: HtmlEvidence}), dùng đúng hàm analyzeHtml mà máy chủ dùng khi quét.
 *
 *   npx tsx scripts/import-pages.ts --in .cache/phreshphish/train.jsonl --out .cache/training/phreshphish-train.jsonl
 *
 * - Loại mọi tên miền thuộc các tập đánh giá trong eval/datasets (để số đo không bị "lộ đề")
 * - Bỏ trang gần như rỗng và trang chặn bot
 * - Có thể nối thêm file đã có: --append-to .cache/training/real-pages-v6.jsonl
 * - --exclude-owners train.jsonl: bỏ tên miền đã có trong tập huấn luyện (dùng khi tạo tập kiểm tra)
 */
import fs from 'node:fs';
import path from 'node:path';
import readline from 'node:readline';
import { analyzeHtml } from '../server/evidence.ts';
import { getDomainParts } from '../server/domainRules.ts';

const args = process.argv.slice(2);
const arg = (name: string, def: string) => {
  const i = args.indexOf(`--${name}`);
  return i >= 0 && args[i + 1] ? args[i + 1] : def;
};
const IN = arg('in', '');
const OUT = arg('out', '');
const APPEND_TO = arg('append-to', '');
const EXCLUDE_OWNERS = arg('exclude-owners', '');
if (!IN || !OUT) {
  console.error('Cần --in và --out');
  process.exit(1);
}

const ownerOf = (url: string) => {
  try {
    return getDomainParts(new URL(url).hostname).ownerDomain;
  } catch {
    return null;
  }
};

const evalOwners = new Set<string>();
const datasets = path.join(import.meta.dirname, '../eval/datasets');
for (const f of fs.readdirSync(datasets)) {
  const text = fs.readFileSync(path.join(datasets, f), 'utf8');
  const urls = f.endsWith('.json')
    ? Object.values(JSON.parse(text)).flat().filter((v): v is string => typeof v === 'string')
    : text.split('\n').map(l => l.trim()).filter(l => l && !l.startsWith('#'));
  for (const u of urls) {
    const o = ownerOf(/^https?:\/\//.test(u) ? u : `https://${u}`);
    if (o) evalOwners.add(o);
  }
}

if (EXCLUDE_OWNERS) {
  for (const line of fs.readFileSync(EXCLUDE_OWNERS, 'utf8').split('\n')) if (line) evalOwners.add(JSON.parse(line).owner);
}

fs.mkdirSync(path.dirname(path.resolve(OUT)), { recursive: true });
const out = fs.createWriteStream(OUT);
if (APPEND_TO) out.write(fs.readFileSync(APPEND_TO, 'utf8'));
const counts = { kept: [0, 0], evalOverlap: 0, empty: 0 };
const rl = readline.createInterface({ input: fs.createReadStream(IN) });
for await (const line of rl) {
  if (!line) continue;
  const r = JSON.parse(line);
  const owner = ownerOf(r.url);
  if (!owner) continue;
  if (evalOwners.has(owner)) {
    counts.evalOverlap++;
    continue;
  }
  const html = analyzeHtml(r.html, r.url, owner);
  if (html.botChallenge || html.textLength + html.title.length < 30) {
    counts.empty++;
    continue;
  }
  out.write(JSON.stringify({ url: r.url, label: r.label, owner, html }) + '\n');
  counts.kept[r.label]++;
}
out.end();
console.log(`Giữ ${counts.kept[0]} hợp pháp + ${counts.kept[1]} lừa đảo; bỏ ${counts.evalOverlap} trùng tên miền tập đánh giá${EXCLUDE_OWNERS ? '/tập train' : ''}, ${counts.empty} trang rỗng/chặn bot -> ${OUT}`);
