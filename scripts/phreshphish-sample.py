"""
Lấy mẫu trang thật từ PhreshPhish (https://huggingface.co/datasets/phreshphish/phreshphish, CC BY 4.0)
để huấn luyện mô hình nội dung. Bộ dữ liệu ~190 GB nên chỉ tải vài file parquet, đọc theo lô rồi xoá ngay.

  python3 scripts/phreshphish-sample.py --split train --shards 4 --per-class 15000 --out .cache/phreshphish/train.jsonl
  python3 scripts/phreshphish-sample.py --split test --shards 1 --per-class 3000 --out .cache/phreshphish/test.jsonl

- Chọn các file cách đều nhau trong danh sách (trải đều theo thời gian thu thập)
- Tối đa 2 trang mỗi host, cân bằng hai lớp, cắt HTML ở 400 KB
- Ghi JSONL: {"url", "label": 0|1, "target", "lang", "date", "html"}
"""
import argparse, json, os, random, sys
from urllib.parse import urlsplit

import pyarrow.parquet as pq
from huggingface_hub import HfApi, hf_hub_download

REPO = 'phreshphish/phreshphish'
MAX_HTML = 400_000

ap = argparse.ArgumentParser()
ap.add_argument('--split', default='train', choices=['train', 'test'])
ap.add_argument('--shards', type=int, default=4)
ap.add_argument('--per-class', type=int, default=15000)
ap.add_argument('--langs', default='', help='vd "en,vi"; để trống = mọi ngôn ngữ')
ap.add_argument('--seed', type=int, default=7)
ap.add_argument('--file', default='', help='chỉ định đúng một file, vd data/test-000.parquet (để thử nhanh)')
ap.add_argument('--out', required=True)
args = ap.parse_args()

random.seed(args.seed)
langs = {l.strip() for l in args.langs.split(',') if l.strip()}
files = sorted(f for f in HfApi().list_repo_files(REPO, repo_type='dataset')
               if f.startswith(f'data/{args.split}-') and f.endswith('.parquet'))
if not files:
    sys.exit(f'Không thấy file data/{args.split}-*.parquet trong {REPO}')
n = min(args.shards, len(files))
picked = [files[round(i * (len(files) - 1) / max(1, n - 1))] for i in range(n)] if n > 1 else [files[len(files) // 2]]
if args.file:
    picked, n = [args.file], 1
quota = args.per_class / len(picked)  # mỗi file đóng góp ngang nhau cho mỗi lớp
print(f'{args.split}: {len(files)} file, chọn {picked}', flush=True)

os.makedirs(os.path.dirname(os.path.abspath(args.out)), exist_ok=True)
per_host = {}
kept = [0, 0]
with open(args.out, 'w') as out:
    for idx, name in enumerate(picked, 1):
        path = hf_hub_download(REPO, name, repo_type='dataset')
        target = [round(quota * idx) - kept[0], round(quota * idx) - kept[1]]
        pf = pq.ParquetFile(path)
        rows = []
        for batch in pf.iter_batches(batch_size=512, columns=['url', 'label', 'target', 'lang', 'date', 'html']):
            for r in batch.to_pylist():
                y = 0 if r['label'] == 'benign' else 1
                if target[y] <= 0 or (langs and (r.get('lang') or '') not in langs):
                    continue
                html = r.get('html') or ''
                # Một số bản ghi lưu HTML dưới dạng chuỗi JSON (có dấu ngoặc kép bao ngoài)
                if html.startswith('"'):
                    try:
                        html = json.loads(html)
                    except Exception:
                        pass
                host = (urlsplit(r['url']).hostname or '').lower()
                if len(html) < 200 or not host or per_host.get(host, 0) >= 2:
                    continue
                # Lấy mẫu ngẫu nhiên trong file: giữ ~1/3 số dòng hợp lệ để không dồn hết vào đầu file
                if random.random() > 0.35:
                    continue
                per_host[host] = per_host.get(host, 0) + 1
                target[y] -= 1
                kept[y] += 1
                out.write(json.dumps({'url': r['url'], 'label': y, 'target': r.get('target'), 'lang': r.get('lang'),
                                      'date': str(r.get('date')), 'html': html[:MAX_HTML]}, ensure_ascii=False) + '\n')
            if target[0] <= 0 and target[1] <= 0:
                break
        os.remove(os.path.realpath(path))  # giải phóng ổ đĩa của runner
        print(f'  {name}: hợp pháp {kept[0]}, lừa đảo {kept[1]}', flush=True)
print(f'Xong: {kept[0]} hợp pháp + {kept[1]} lừa đảo -> {args.out}')
