/**
 * Đo độ chính xác của /api/analyze trên bộ dữ liệu có nhãn.
 *
 *   npx tsx scripts/eval-accuracy.ts [--base http://localhost:3000] [--phishing 60] [--out report.json]
 *     [--dataset eval/datasets/set-b-legit-gambling.json] [--phishing-file feed.txt] [--exclude-file used-urls.txt] [--seed 42]
 *
 * - Website hợp pháp + cờ bạc: eval/datasets/eval-dataset.json (mặc định)
 * - Phishing: lấy ngẫu nhiên N URL đang hoạt động từ feed công khai của OpenPhish tại thời điểm chạy
 *   (luôn là dữ liệu mới, hệ thống chưa từng "thấy"). Lưu ý: server sẽ tải HTML của các trang lừa đảo này.
 * - Nên chạy server với RATE_LIMIT_PER_MIN=0, và THREAT_FEEDS=off để đo khả năng tự phát hiện
 *   (không dựa vào danh sách đen chứa chính các URL được kiểm tra).
 *
 * Quy ước: điểm < 50 = "nguy hiểm". Website hợp pháp bị chấm < 50 là báo nhầm (false positive).
 */
import fs from 'node:fs';
import path from 'node:path';

const args = process.argv.slice(2);
const arg = (name: string, def: string) => {
  const i = args.indexOf(`--${name}`);
  return i >= 0 && args[i + 1] ? args[i + 1] : def;
};
const BASE = arg('base', 'http://localhost:3000');
const PHISHING_COUNT = parseInt(arg('phishing', '60'), 10);
const OUT = arg('out', '');
const SEED = parseInt(arg('seed', '42'), 10);
const CONCURRENCY = parseInt(arg('concurrency', '6'), 10);

interface Sample { url: string; label: 'safe' | 'dangerous'; group: string }
interface Outcome extends Sample { score: number | null; status: string; engine: string; ms: number; error?: string; jev?: unknown; factors?: Array<[string, number]> }

function seededShuffle<T>(arr: T[], seed: number): T[] {
  const a = [...arr];
  let s = seed;
  for (let i = a.length - 1; i > 0; i--) {
    s = (s * 1103515245 + 12345) & 0x7fffffff;
    const j = s % (i + 1);
    [a[i], a[j]] = [a[j], a[i]];
  }
  return a;
}

async function loadSamples(): Promise<Sample[]> {
  const ds = JSON.parse(fs.readFileSync(arg('dataset', path.join(import.meta.dirname, '..', 'eval', 'datasets', 'eval-dataset.json')), 'utf8'));
  const samples: Sample[] = [
    ...ds.safe.map((url: string) => ({ url, label: 'safe' as const, group: 'legit' })),
    ...ds.dangerous.map((url: string) => ({ url, label: 'dangerous' as const, group: 'gambling' })),
  ];
  if (PHISHING_COUNT > 0) {
    const cachePath = arg('phishing-file', '');
    const text = cachePath
      ? fs.readFileSync(cachePath, 'utf8')
      : await (await fetch('https://raw.githubusercontent.com/openphish/public_feed/refs/heads/main/feed.txt')).text();
    const urls = [...new Set(text.split('\n').map(l => l.trim()).filter(l => /^https?:\/\//.test(l)))];
    // --exclude-file: loại các URL đã dùng để tinh chỉnh (đo trên dữ liệu chưa từng thấy)
    const excludeFile = arg('exclude-file', '');
    const excluded = new Set(excludeFile ? fs.readFileSync(excludeFile, 'utf8').split('\n').map(l => l.trim()) : []);
    urls.splice(0, urls.length, ...urls.filter(u => !excluded.has(u)));
    for (const url of seededShuffle(urls, SEED).slice(0, PHISHING_COUNT)) {
      samples.push({ url, label: 'dangerous', group: 'phishing' });
    }
  }
  return samples;
}

async function evaluate(sample: Sample): Promise<Outcome> {
  const start = Date.now();
  try {
    const res = await fetch(`${BASE}/api/analyze`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ url: sample.url }),
      signal: AbortSignal.timeout(90_000),
    });
    const data: any = await res.json().catch(() => ({}));
    if (!res.ok) {
      return { ...sample, score: null, status: `HTTP ${res.status}`, engine: '', ms: Date.now() - start, error: data?.message };
    }
    return { ...sample, score: data.trust_score, status: data.status, engine: data.analysis_engine || '', ms: Date.now() - start, ...(data.score_breakdown?.jev_decision ? { jev: data.score_breakdown.jev_decision } : {}), factors: data.score_breakdown?.factors?.map((f: { id: string; delta: number }) => [f.id, f.delta]) };
  } catch (err: any) {
    return { ...sample, score: null, status: 'error', engine: '', ms: Date.now() - start, error: err?.message };
  }
}

async function main() {
  const samples = await loadSamples();
  console.log(`Đánh giá ${samples.length} mẫu qua ${BASE} ...`);
  const outcomes: Outcome[] = [];
  let next = 0;
  await Promise.all(Array.from({ length: CONCURRENCY }, async () => {
    while (next < samples.length) {
      const s = samples[next++];
      outcomes.push(await evaluate(s));
      process.stdout.write('.');
    }
  }));
  console.log('\n');

  const predicted = (o: Outcome) => (o.score !== null && o.score < 50 ? 'dangerous' : 'safe');
  const scored = outcomes.filter(o => o.score !== null);
  const tp = scored.filter(o => o.label === 'dangerous' && predicted(o) === 'dangerous').length;
  const fn = scored.filter(o => o.label === 'dangerous' && predicted(o) === 'safe').length;
  const fp = scored.filter(o => o.label === 'safe' && predicted(o) === 'dangerous').length;
  const tn = scored.filter(o => o.label === 'safe' && predicted(o) === 'safe').length;
  const pct = (a: number, b: number) => (b ? `${((100 * a) / b).toFixed(1)}%` : 'n/a');

  const byGroup = (g: string) => {
    const xs = scored.filter(o => o.group === g);
    const correct = xs.filter(o => predicted(o) === o.label).length;
    return `${g.padEnd(9)} ${String(correct).padStart(3)}/${String(xs.length).padEnd(3)} đúng (${pct(correct, xs.length)})`;
  };

  console.log('Theo nhóm:');
  for (const g of ['legit', 'gambling', 'phishing']) console.log('  ' + byGroup(g));
  console.log('\nTổng hợp (dương tính = nguy hiểm):');
  console.log(`  Accuracy          ${pct(tp + tn, scored.length)}  (${tp + tn}/${scored.length})`);
  console.log(`  Recall nguy hiểm  ${pct(tp, tp + fn)}  (bỏ sót ${fn})`);
  console.log(`  Precision         ${pct(tp, tp + fp)}  (báo nhầm ${fp})`);
  console.log(`  Lỗi / không chấm  ${outcomes.length - scored.length}`);
  const dangerousRatedSafe = scored.filter(o => o.label === 'dangerous' && /safe/i.test(o.status)).length;
  console.log(`  Trang nguy hiểm bị xếp "Safe" (lỗi nghiêm trọng nhất): ${dangerousRatedSafe}/${tp + fn}`);
  const legitSafe = scored.filter(o => o.group === 'legit' && /safe/i.test(o.status)).length;
  console.log(`  Web hợp pháp được xếp "Safe": ${pct(legitSafe, scored.filter(o => o.group === 'legit').length)}`);
  const lat = scored.map(o => o.ms).sort((a, b) => a - b);
  console.log(`  Độ trễ p50/p95    ${lat[Math.floor(lat.length * 0.5)]}ms / ${lat[Math.floor(lat.length * 0.95)]}ms`);

  const wrong = outcomes.filter(o => o.score === null || predicted(o) !== o.label);
  if (wrong.length) {
    console.log('\nCác mẫu sai / lỗi:');
    for (const o of wrong) {
      console.log(`  [${o.group}] ${o.url.slice(0, 70).padEnd(70)} ${String(o.score).padStart(4)} ${o.status} ${o.error ? '- ' + o.error.slice(0, 60) : ''}`);
    }
  }
  if (OUT) fs.writeFileSync(OUT, JSON.stringify(outcomes, null, 2));
}

main();
