/**
 * Thu thập HTML trang THẬT để huấn luyện mô hình nội dung (scripts/train-content-model.ts --real ...).
 *
 *   npx tsx scripts/collect-pages.ts [--phishing 4000] [--legit 4000] [--concurrency 24] [--out .cache/training/real-pages.jsonl]
 *     [--phishing-file urls.txt]  (thay nguồn mặc định bằng danh sách URL/tên miền nguy hiểm, giữ nguyên thứ tự)
 *     [--legit-file urls.txt]     (tương tự cho phía hợp pháp)
 *
 * - Lừa đảo: URL từ Phishing.Database (phishing-links-ACTIVE) + OpenPhish
 * - Hợp pháp: tên miền từ Tranco/Majestic (ưu tiên ~30% tên miền .vn), lấy trang chủ
 * - Chỉ tải HTML qua safeFetch (chặn IP nội bộ, 6s, 1MB), KHÔNG chạy JavaScript, không tra RDAP/TLS
 * - Lọc nhiễu nhãn: bỏ trang lỗi, chặn bot, gần như rỗng, trang đã bị gỡ/đỗ tên miền/hosting bị khoá
 * - Tối đa 2 trang mỗi tên miền chủ sở hữu; loại mọi URL/tên miền thuộc các tập đánh giá
 * - Ghi nối tiếp dạng JSONL, chạy lại sẽ bỏ qua URL đã thu thập
 */
import fs from 'node:fs';
import path from 'node:path';
import JSZip from 'jszip';
import { safeFetch } from '../server/netSafety.ts';
import { analyzeHtml } from '../server/evidence.ts';
import { getDomainParts } from '../server/domainRules.ts';

const args = process.argv.slice(2);
const arg = (name: string, def: string) => {
  const i = args.indexOf(`--${name}`);
  return i >= 0 && args[i + 1] ? args[i + 1] : def;
};
const PHISHING_TARGET = parseInt(arg('phishing', '4000'), 10);
const LEGIT_TARGET = parseInt(arg('legit', '4000'), 10);
const CONCURRENCY = parseInt(arg('concurrency', '24'), 10);
const OUT = path.resolve(arg('out', '.cache/training/real-pages.jsonl'));
const CACHE = path.resolve('.cache/training');

const HEADERS = {
  'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36',
  'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
  'Accept-Language': 'vi-VN,vi;q=0.9,en-US;q=0.8,en;q=0.7',
};

// Trang không còn nội dung gốc: dùng làm mẫu sẽ dạy sai mô hình
const DEAD_PAGE = /suspended|has been (?:disabled|removed|deactivated|blocked)|account (?:suspended|disabled)|domain (?:is )?for sale|buy this domain|parked|coming soon|under construction|404|not found|403|forbidden|access denied|bad gateway|service unavailable|site not found|deceptive site|phishing (?:warning|alert)|this site can.?t be reached|default (?:web )?page|it works!|welcome to nginx|index of \//i;

const CLOAKED_PAGE = /^(?:yahoo|google|bing|yandex|tìm kiếm - microsoft bing|index of|welcome to nginx|it works|apache|404|403|fatal error|redirecting|please wait|loading|verify you are human|just a moment|site is created|success!|website takedown|domain information|about this domain|caddy works|my blog|hello world)/i;

let seed = 4242;
const rand = () => {
  seed ^= seed << 13; seed ^= seed >>> 17; seed ^= seed << 5;
  return ((seed >>> 0) % 1_000_000) / 1_000_000;
};
const shuffle = <T>(a: T[]) => {
  for (let i = a.length - 1; i > 0; i--) {
    const j = Math.floor(rand() * (i + 1));
    [a[i], a[j]] = [a[j], a[i]];
  }
  return a;
};

async function cached(url: string, file: string): Promise<Buffer> {
  const full = path.join(CACHE, file);
  if (fs.existsSync(full)) return fs.readFileSync(full);
  const res = await fetch(url, { signal: AbortSignal.timeout(300_000) });
  if (!res.ok) throw new Error(`HTTP ${res.status} ${url}`);
  const buf = Buffer.from(await res.arrayBuffer());
  fs.mkdirSync(CACHE, { recursive: true });
  fs.writeFileSync(full, buf);
  return buf;
}

function ownerOf(url: string): string | null {
  try {
    return getDomainParts(new URL(url).hostname).ownerDomain;
  } catch {
    return null;
  }
}

// ---------------------------------------------------------------- loại trừ tập đánh giá
const excludedUrls = new Set<string>();
const excludedOwners = new Set<string>();
const exclude = (u: string) => {
  const url = /^https?:\/\//.test(u) ? u : `https://${u}`;
  excludedUrls.add(url);
  const o = ownerOf(url);
  if (o) excludedOwners.add(o);
};
const evalDir = path.join(import.meta.dirname, '..', 'eval', 'datasets');
for (const f of fs.readdirSync(evalDir)) {
  const content = fs.readFileSync(path.join(evalDir, f), 'utf8');
  if (f.endsWith('.json')) {
    const ds = JSON.parse(content);
    [...(ds.safe || []), ...(ds.dangerous || [])].forEach(exclude);
  } else {
    content.split('\n').map(l => l.trim()).filter(Boolean).forEach(exclude);
  }
}
const evalCache = path.resolve('.cache/eval-pages.json');
if (fs.existsSync(evalCache)) Object.keys(JSON.parse(fs.readFileSync(evalCache, 'utf8'))).forEach(exclude);
for (const i of args.flatMap((a, k) => (a === '--exclude' ? [args[k + 1]] : []))) {
  fs.readFileSync(i, 'utf8').split('\n').map(l => l.trim()).filter(Boolean).forEach(exclude);
}

// ---------------------------------------------------------------- ứng viên
const PDB = 'https://raw.githubusercontent.com/Phishing-Database/Phishing.Database/master';
// OpenPhish (cập nhật liên tục, phần lớn còn sống) đứng trước; Phishing.Database (rất lớn nhưng đa số URL đã chết) xét sau.
// OpenPhish luôn tải mới, không dùng bản lưu đệm.
const openphishText = await (await fetch('https://raw.githubusercontent.com/openphish/public_feed/refs/heads/main/feed.txt', { signal: AbortSignal.timeout(60_000) })).text();
const pdbText = (await cached(`${PDB}/phishing-links-ACTIVE.txt`, 'phishing-links-ACTIVE.txt')).toString('utf8');
const phishText = `${openphishText}\n${pdbText}`;
const urlsOf = (text: string) => [...new Set(text.split('\n').map(l => l.trim()).filter(l => /^https?:\/\//.test(l)))]
  .filter(u => !excludedUrls.has(u) && !excludedOwners.has(ownerOf(u) || ''));
const phishingFile = arg('phishing-file', '');
const phishCandidates = phishingFile
  ? urlsOf(fs.readFileSync(phishingFile, 'utf8').split('\n').map(l => l.trim()).filter(Boolean).map(l => (/^https?:\/\//.test(l) ? l : `https://${l}/`)).join('\n'))
  : [...shuffle(urlsOf(openphishText)), ...shuffle(urlsOf(pdbText))];
{
  const all = [...new Set(openphishText.split('\n').map(l => l.trim()).filter(l => /^https?:\/\//.test(l)))];
  console.log(`OpenPhish: ${all.length} URL, trùng URL tập đánh giá ${all.filter(u => excludedUrls.has(u)).length}, trùng tên miền tập đánh giá ${all.filter(u => !excludedUrls.has(u) && excludedOwners.has(ownerOf(u) || '')).length}, còn dùng được ${urlsOf(openphishText).length}`);
}

const trancoZip = await JSZip.loadAsync(await cached('https://tranco-list.eu/top-1m.csv.zip', 'tranco-top-1m.csv.zip'));
const trancoCsv = await Object.values(trancoZip.files).find(f => f.name.endsWith('.csv'))!.async('string');
const legitDomains = trancoCsv.split('\n').map(l => l.slice(l.indexOf(',') + 1).trim().toLowerCase()).filter(Boolean);
const phishOwners = new Set(phishText.split('\n').map(l => (l.startsWith('http') ? ownerOf(l.trim()) : null)).filter(Boolean) as string[]);
const legitPool = legitDomains.filter(d => !excludedOwners.has(d) && !phishOwners.has(d));
const vn = shuffle(legitPool.filter(d => d.endsWith('.vn')));
const other = shuffle(legitPool.filter(d => !d.endsWith('.vn')));
const legitCandidates = [...vn.slice(0, Math.round(LEGIT_TARGET * 0.6)), ...other.slice(0, LEGIT_TARGET * 3)]
  .map(d => `https://${d}/`);
shuffle(legitCandidates);
const legitFile = arg('legit-file', '');
if (legitFile) {
  legitCandidates.length = 0;
  legitCandidates.push(...fs.readFileSync(legitFile, 'utf8').split('\n').map(l => l.trim()).filter(l => /^https?:\/\//.test(l)).filter(u => !excludedUrls.has(u) && !excludedOwners.has(ownerOf(u) || '')));
}

// ---------------------------------------------------------------- tiếp tục từ lần chạy trước
fs.mkdirSync(path.dirname(OUT), { recursive: true });
const done = new Set<string>();
const counts = { 0: 0, 1: 0 } as Record<0 | 1, number>;
const perOwner = new Map<string, number>();
let vnLegit = 0;
if (fs.existsSync(OUT)) {
  for (const line of fs.readFileSync(OUT, 'utf8').split('\n')) {
    if (!line) continue;
    const r = JSON.parse(line);
    done.add(r.url);
    if (r.html) {
      counts[r.label as 0 | 1]++;
      perOwner.set(r.owner, (perOwner.get(r.owner) || 0) + 1);
      if (r.label === 0 && r.owner.endsWith('.vn')) vnLegit++;
    }
  }
}
console.log(`Ứng viên: ${phishCandidates.length.toLocaleString()} URL lừa đảo, ${legitCandidates.length.toLocaleString()} trang hợp pháp. Đã có: ${counts[1]} lừa đảo, ${counts[0]} hợp pháp.`);

const out = fs.createWriteStream(OUT, { flags: 'a' });
const stats = { fetched: 0, kept: 0, dead: 0, error: 0 };

async function collect(url: string, label: 0 | 1) {
  const owner = ownerOf(url);
  if (!owner || done.has(url) || (perOwner.get(owner) || 0) >= 2) return;
  done.add(url);
  let record: any = { url, label, owner, html: null };
  try {
    const res = await safeFetch(url, { timeoutMs: 6000, maxBytes: 1024 * 1024, headers: HEADERS });
    stats.fetched++;
    const ct = res.headers.get('content-type') || '';
    const finalOwner = ownerOf(res.finalUrl);
    if (res.status < 400 && (!ct || /html/i.test(ct))) {
      const html = analyzeHtml(res.body, res.finalUrl, finalOwner || owner);
      const looksDead = DEAD_PAGE.test(html.title) || DEAD_PAGE.test(html.text.slice(0, 200));
      // Trang lừa đảo chuyển hướng về site hợp pháp (vd google.com) không còn là mẫu lừa đảo
      const bouncedToLegit = label === 1 && finalOwner !== owner && /google|microsoft|apple|amazon|facebook|bing|yahoo|cloudflare/.test(finalOwner || '');
      // Tên miền xấu nhưng trang hiện ra không có gì xấu (che giấu nội dung, trang mặc định): dùng làm mẫu lừa đảo sẽ dạy sai
      const cloaked = label === 1 && CLOAKED_PAGE.test(html.title);
      if (!html.botChallenge && html.textLength >= 30 && !looksDead && !bouncedToLegit && !cloaked) {
        record = { ...record, finalUrl: res.finalUrl, status: res.status, html };
        counts[label]++;
        perOwner.set(owner, (perOwner.get(owner) || 0) + 1);
        if (label === 0 && owner.endsWith('.vn')) vnLegit++;
        stats.kept++;
      } else {
        stats.dead++;
      }
    } else {
      stats.dead++;
    }
  } catch {
    stats.error++;
  }
  out.write(JSON.stringify(record) + '\n');
}

async function run(candidates: string[], label: 0 | 1, target: number) {
  let next = 0;
  let lastLog = Date.now();
  await Promise.all(Array.from({ length: CONCURRENCY }, async () => {
    while (next < candidates.length && counts[label] < target) {
      await collect(candidates[next++], label);
      if (Date.now() - lastLog > 15_000) {
        lastLog = Date.now();
        console.log(`  [${label ? 'lừa đảo' : 'hợp pháp'}] giữ ${counts[label]}/${target} | đã thử ${next} | tải được ${stats.fetched}, loại ${stats.dead}, lỗi ${stats.error}`);
      }
    }
  }));
}

await run(phishCandidates, 1, PHISHING_TARGET);
await run(legitCandidates, 0, LEGIT_TARGET);
out.end();
console.log(`Xong: ${counts[1]} trang lừa đảo, ${counts[0]} trang hợp pháp (${vnLegit} trang .vn) -> ${OUT}`);
