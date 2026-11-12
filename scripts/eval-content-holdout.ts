/**
 * So sánh các mô hình nội dung trên một tập trang thật chưa dùng để huấn luyện (định dạng của import-pages.ts),
 * ở đúng các ngưỡng mà riskScoring.ts dùng (0,82 / 0,90 / 0,92) và ở các ngưỡng cho cùng tỷ lệ báo nhầm.
 *
 *   npx tsx scripts/eval-content-holdout.ts --data .cache/training/phreshphish-test.jsonl \
 *     --models server/models/phishing-content-model.bin.gz,artifacts/content-model.bin.gz [--json metrics.json]
 */
import fs from 'node:fs';
import { featurizeContent } from '../server/contentModel.ts';
import { auc, deserializeModel, forward } from '../server/hashedMlp.ts';

const args = process.argv.slice(2);
const arg = (name: string, def: string) => {
  const i = args.indexOf(`--${name}`);
  return i >= 0 && args[i + 1] ? args[i + 1] : def;
};
const rows = fs.readFileSync(arg('data', ''), 'utf8').split('\n').filter(Boolean).map(l => JSON.parse(l));
const labels: number[] = rows.map(r => r.label);
const positives = labels.filter(Boolean).length;
const SCORING_THRESHOLDS = [0.82, 0.9, 0.92];

const results = arg('models', '').split(',').filter(Boolean).map(file => {
  const { model } = deserializeModel(fs.readFileSync(file));
  const scores = rows.map(r => forward(model, featurizeContent(r.html, model.buckets)));
  const neg = scores.filter((_, i) => !labels[i]).sort((a, b) => b - a);
  const at = (t: number) => ({
    threshold: +t.toFixed(3),
    recall: +(scores.filter((s, i) => labels[i] && s >= t).length / positives).toFixed(4),
    fpr: +(neg.filter(s => s >= t).length / neg.length).toFixed(4),
  });
  return {
    model: file,
    auc: +auc(scores, labels).toFixed(4),
    atScoringThresholds: SCORING_THRESHOLDS.map(at),
    atMatchedFpr: [0.005, 0.01, 0.02].map(f => ({ targetFpr: f, ...at(neg[Math.floor(neg.length * f)]) })),
  };
});

const pct = (v: number) => `${(v * 100).toFixed(1)}%`;
const lines = [
  `Tập kiểm tra: ${rows.length} trang (${positives} lừa đảo, ${rows.length - positives} hợp pháp)`,
  '',
  '| Mô hình | AUC | ' + SCORING_THRESHOLDS.map(t => `Recall / FPR @${t}`).join(' | ') + ' | Recall @FPR 1% |',
  '|---|---|' + SCORING_THRESHOLDS.map(() => '---|').join('') + '---|',
  ...results.map(r => `| \`${r.model}\` | ${pct(r.auc)} | ` + r.atScoringThresholds.map(a => `${pct(a.recall)} / ${pct(a.fpr)}`).join(' | ') + ` | ${pct(r.atMatchedFpr[1].recall)} (ngưỡng ${r.atMatchedFpr[1].threshold}) |`),
];
console.log(lines.join('\n'));
const jsonOut = arg('json', '');
if (jsonOut) fs.writeFileSync(jsonOut, JSON.stringify({ samples: rows.length, positives, results }, null, 2));
