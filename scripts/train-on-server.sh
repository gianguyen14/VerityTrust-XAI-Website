#!/usr/bin/env bash
# Huấn luyện mô hình đọc nội dung trên trang thật của PhreshPhish, chạy trên máy chủ Linux (Proxmox LXC/VM).
# Tự cài Node 22 + Python venv nếu thiếu, tải repo, lấy mẫu dữ liệu, huấn luyện và so với mô hình đang dùng.
#
#   nano train.sh        (dán nội dung, Ctrl+O, Enter, Ctrl+X)
#   bash train.sh        (hoặc chạy nền: nohup bash train.sh > train.log 2>&1 &   rồi   tail -f train.log)
#
# Đổi tham số bằng biến môi trường, vd:  SHARDS=8 PER_CLASS=30000 bash train.sh
# Gộp thêm trang tự thu:               EXTRA_PAGES=https://.../pages.jsonl.gz bash train.sh
set -euo pipefail

PER_CLASS="${PER_CLASS:-15000}"       # số trang mỗi lớp (lừa đảo / hợp pháp) để huấn luyện
# Mỗi file parquet (~0,5 GB, đọc xong là xoá) chỉ có ~9.000 trang cho cả hai lớp, sau khi lọc còn ~3.500 trang/lớp
SHARDS="${SHARDS:-$(( (PER_CLASS + 3499) / 3500 + 1 ))}"
TEST_PER_CLASS="${TEST_PER_CLASS:-3000}"
LANGS="${LANGS:-}"                    # vd "en,vi"; để trống = mọi ngôn ngữ
EPOCHS="${EPOCHS:-3}"
REAL_WEIGHT="${REAL_WEIGHT:-3}"
# Link tới file trang tự thu (định dạng real-pages*.jsonl, có thể nén .gz) để gộp vào tập train, vd trang .vn/web nhỏ
EXTRA_PAGES="${EXTRA_PAGES:-}"
DIR="${DIR:-/opt/verity-train}"
REPO="${REPO:-https://github.com/gianguyen14/VerityTrust-XAI-Website.git}"
NODE_VERSION="22.21.0"

log() { echo "[$(date +%H:%M:%S)] $*"; }

# ---------------------------------------------------------------- 1. Gói hệ thống
need=()
command -v git >/dev/null || need+=(git)
command -v curl >/dev/null || need+=(curl)
command -v xz >/dev/null || need+=(xz-utils)
command -v python3 >/dev/null || need+=(python3)
python3 -c 'import venv, ensurepip' 2>/dev/null || need+=(python3-venv)
if [ ${#need[@]} -gt 0 ]; then
  log "Cài gói: ${need[*]}"
  apt-get update -qq && DEBIAN_FRONTEND=noninteractive apt-get install -y -qq "${need[@]}"
fi

# ---------------------------------------------------------------- 2. Node 22 (cài riêng trong $DIR, không đụng Node của hệ thống)
mkdir -p "$DIR"
case "$(uname -m)" in
  x86_64) NODE_ARCH=x64 ;;
  aarch64|arm64) NODE_ARCH=arm64 ;;
  *) echo "Không hỗ trợ kiến trúc $(uname -m)"; exit 1 ;;
esac
NODE_DIR="$DIR/node-v$NODE_VERSION-linux-$NODE_ARCH"
if [ ! -x "$NODE_DIR/bin/node" ]; then
  log "Tải Node $NODE_VERSION ($NODE_ARCH)"
  curl -fsSL "https://nodejs.org/dist/v$NODE_VERSION/node-v$NODE_VERSION-linux-$NODE_ARCH.tar.xz" | tar -xJ -C "$DIR"
fi
export PATH="$NODE_DIR/bin:$PATH"

# ---------------------------------------------------------------- 3. Mã nguồn
if [ -d "$DIR/repo/.git" ]; then
  log "Cập nhật repo"
  git -C "$DIR/repo" fetch -q origin main && git -C "$DIR/repo" reset -q --hard origin/main
else
  log "Tải repo"
  git clone -q --depth 1 "$REPO" "$DIR/repo"
fi
cd "$DIR/repo"
log "Commit: $(git log -1 --format='%h %s')"
npm ci --no-audit --no-fund --loglevel=error

if [ ! -x "$DIR/venv/bin/python" ]; then
  python3 -m venv "$DIR/venv"
fi
"$DIR/venv/bin/pip" install -q --upgrade pip pyarrow huggingface_hub

# ---------------------------------------------------------------- 4. Dữ liệu
export HF_HUB_DISABLE_PROGRESS_BARS=1 THREAT_FEEDS=off POPULARITY_LIST=off
free_gb=$(df -BG --output=avail "$DIR" | tail -1 | tr -dc 0-9)
log "Ổ đĩa trống: ${free_gb} GB, RAM: $(free -g | awk '/Mem:/ {print $7}') GB khả dụng, CPU: $(nproc)"
# HTML thô trung bình ~180 KB/trang (đo trên PhreshPhish) + 1 file parquet đang đọc + node_modules
need_gb=$(( (PER_CLASS + TEST_PER_CLASS) * 2 * 180 / 1000000 + 3 ))
[ "$free_gb" -ge "$need_gb" ] || { echo "Cần khoảng ${need_gb} GB trống cho PER_CLASS=$PER_CLASS, hiện có ${free_gb} GB"; exit 1; }

DATA="$DIR/data"; mkdir -p "$DATA"
log "Lấy mẫu tập train: $SHARDS file, $PER_CLASS trang/lớp, ngôn ngữ: ${LANGS:-tất cả}"
"$DIR/venv/bin/python" scripts/phreshphish-sample.py --split train --shards "$SHARDS" \
  --per-class "$PER_CLASS" --langs "$LANGS" --out "$DATA/train-raw.jsonl"
log "Lấy mẫu tập test"
"$DIR/venv/bin/python" scripts/phreshphish-sample.py --split test --shards 1 \
  --per-class "$TEST_PER_CLASS" --langs "$LANGS" --seed 11 --out "$DATA/test-raw.jsonl"

log "Chuyển sang định dạng huấn luyện"
APPEND=()
if [ -n "$EXTRA_PAGES" ]; then
  log "Tải trang tự thu để gộp: $EXTRA_PAGES"
  curl -fsSL "$EXTRA_PAGES" -o "$DATA/extra.download"
  if gzip -t "$DATA/extra.download" 2>/dev/null; then gunzip -c "$DATA/extra.download" > "$DATA/extra.jsonl"; else mv "$DATA/extra.download" "$DATA/extra.jsonl"; fi
  rm -f "$DATA/extra.download"
  log "Trang tự thu: $(wc -l < "$DATA/extra.jsonl") trang"
  APPEND=(--append-to "$DATA/extra.jsonl")
fi
npx tsx scripts/import-pages.ts --in "$DATA/train-raw.jsonl" --out "$DATA/train.jsonl" "${APPEND[@]}"
npx tsx scripts/import-pages.ts --in "$DATA/test-raw.jsonl" --out "$DATA/test.jsonl" --exclude-owners "$DATA/train.jsonl"
rm -f "$DATA/train-raw.jsonl" "$DATA/test-raw.jsonl"

# ---------------------------------------------------------------- 5. Huấn luyện + so sánh
OUT="$DIR/artifacts/$(date +%Y%m%d-%H%M)"; mkdir -p "$OUT"
log "Huấn luyện ($EPOCHS epoch) -> $OUT"
npx tsx scripts/train-content-model.ts --real "$DATA/train.jsonl" --epochs "$EPOCHS" --real-weight "$REAL_WEIGHT" \
  --out "$OUT/content-model.bin.gz" 2>&1 | tee "$OUT/train.log"

log "So sánh với mô hình đang dùng"
npx tsx scripts/eval-content-holdout.ts --data "$DATA/test.jsonl" \
  --models server/models/phishing-content-model.bin.gz,"$OUT/content-model.bin.gz" --json "$OUT/metrics.json" | tee "$OUT/compare.md"

rm -rf ~/.cache/huggingface/hub/datasets--phreshphish--phreshphish
log "XONG. Mô hình: $OUT/content-model.bin.gz"
echo
echo "Lấy mô hình về máy Mac, chọn một cách:"
echo "  scp root@$(hostname -I | awk '{print $1}'):$OUT/content-model.bin.gz ."
echo "  hoặc trên server:  cd $OUT && python3 -m http.server 8765   rồi mở http://$(hostname -I | awk '{print $1}'):8765"
