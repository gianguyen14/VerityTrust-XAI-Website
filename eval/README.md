# Bộ dữ liệu đánh giá

Thư mục này chứa **toàn bộ dữ liệu kiểm thử** dùng để đo độ chính xác của Verity, cùng **kết quả chấm từng web**, để bất kỳ ai cũng kiểm tra lại được. Giải thích chỉ số và cách đo: [docs/DANH-GIA.md](../docs/DANH-GIA.md).

> ⚠️ **Cảnh báo:** các file `*-phishing*.txt` và nhóm `dangerous` chứa **đường link lừa đảo và cờ bạc thật**. Đừng mở chúng trong trình duyệt và đừng nhập bất kỳ thông tin nào vào các trang đó. Chúng chỉ dùng để chạy công cụ đo.

## `datasets/` — dữ liệu đầu vào

| File | Nội dung | Số lượng |
|---|---|---|
| `set-a-legit-gambling.json` | **Tập A**: web hợp pháp phổ biến (`safe`) + web cờ bạc (`dangerous`); gộp 3 file bên dưới | 205 + 33 |
| `set-a-phishing-openphish.txt` | **Tập A**: ảnh chụp feed OpenPhish ngày 07/11/2026; công cụ đo chọn ngẫu nhiên 120 URL (seed 3) | 300 |
| `set-b-legit-gambling.json` | **Tập B**: web hợp pháp ít phổ biến (`safe`) + web cờ bạc (`dangerous`), gán nhãn thủ công ngày 08/11/2026 | 318 + 192 |
| `set-b-phishing.txt` | **Tập B**: web lừa đảo đã xác minh thủ công (phishunt.io, tinnhiemmang.vn, blocklist web bán hàng lừa đảo, phishing.army) | 185 |
| `set-c-legit-gambling.json` | **Tập C**: web hợp pháp Tranco thứ hạng 10.000–1.000.000 (`safe`) + web cờ bạc (`dangerous`), gán nhãn thủ công ngày 08/11/2026; không trùng tên miền nào với tập A/B và dữ liệu huấn luyện | 105 + 171 |
| `set-c-phishing.txt` | **Tập C**: web lừa đảo từ OpenPhish và phishunt.io ngày 08/11/2026, chỉ giữ trang có dấu hiệu rõ ràng | 38 |
| `set-d-legit-gambling.json` | **Tập D**: web hợp pháp Tranco 10.000–1.000.000 (`safe`) + web cờ bạc (`dangerous`), gán nhãn thủ công ngày 09/11/2026; không trùng tập A/B/C, dữ liệu train hay danh sách cờ bạc đã rà soát | 122 + 132 |
| `set-d-phishing.txt` | **Tập D**: 10 trang lừa đảo từ feed + 22 shop/đầu tư giả, chỉ giữ trang có dấu hiệu rõ ràng | 32 |
| `eval-dataset.json` | Phần "tune" của tập A, dùng để tìm lỗi khi phát triển | 85 + 18 |
| `eval-holdout.json`, `eval-holdout2.json` | Phần "test" của tập A, chỉ dùng để báo cáo | 80 + 15, 40 + 0 |

Định dạng file JSON:

```json
{ "safe": ["kenh14.vn", "https://..."], "dangerous": ["https://..."] }
```

## `results/` — kết quả chấm từng web

| File | Mô tả |
|---|---|
| `set-a.json` | Kết quả của bản hiện tại trên tập A; mọi file `set-*.json` đo ngày 10/11/2026 và có trường `factors` (bằng chứng từng web) |
| `set-b.json` | Kết quả của bản hiện tại trên tập B |
| `set-c.json` | Kết quả của bản hiện tại trên tập C |
| `set-d.json` | Kết quả của bản hiện tại trên tập D |
| `set-b-veritytrust-engine-v2.json`, `set-b-veritytrust-engine-v3.json` | Tập B chạy kèm VerityTrust Decision Engine ở chế độ chạy ngầm; trường `jev` chứa câu trả lời của engine cho từng web |
| `set-b-before-brand-fix.json` | Kết quả trên tập B **trước** khi sửa luật giả danh thương hiệu, tức số đo chưa tinh chỉnh |

Mỗi phần tử có dạng:

```json
{ "url": "kenh14.vn", "label": "safe", "group": "legit", "score": 100, "status": "Safe", "engine": "…", "ms": 232 }
```

- `label`: nhãn thật (`safe` / `dangerous`).
- `group`: nhóm (`legit` / `gambling` / `phishing`).
- `score`, `status`: kết quả Verity chấm.
- `ms`: thời gian xử lý.

## Đo lại

```bash
THREAT_FEEDS=off RATE_LIMIT_PER_MIN=0 npm run dev
```

```bash
npm run eval:a && npm run eval:b && npm run eval:c && npm run eval:d && npm run eval:metrics
```
