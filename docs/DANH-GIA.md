# Đánh giá độ chính xác

[← Về README](../README.md)

Tài liệu này trả lời ba câu hỏi: **Verity chính xác đến đâu? Đo bằng dữ liệu gì? Tự đo lại thế nào?**

## Kết quả tổng hợp

Đo ngày 10/11/2026 trên **1.647 website thật, đang hoạt động**, chia thành 4 tập (6 web không truy cập được lúc đo nên không tính). Lúc đo, tra cứu danh sách đen bị **tắt** (`THREAT_FEEDS=off`), để hệ thống không "tra đáp án" từ chính nguồn dùng làm đề mà phải tự phát hiện từ bằng chứng. Trong ngoặc vuông là khoảng tin cậy 95% (bootstrap 2.000 lần).

**Quy ước:** *dương tính* = web nguy hiểm (lừa đảo hoặc cờ bạc); hệ thống kết luận "nguy hiểm" khi **điểm < 50**.

| | Dự đoán nguy hiểm | Dự đoán không nguy hiểm |
|---|---|---|
| **Thực tế nguy hiểm (899)** | ✅ TP = 855 | ❌ FN = 44 (bỏ sót) |
| **Thực tế hợp pháp (748)** | ❌ FP = 20 (báo nhầm) | ✅ TN = 728 |

| Chỉ số | Gộp (1.647) | Tập A (358) | Tập B (690) | Tập C (314) | Tập D (285) |
|---|---|---|---|---|---|
| **Accuracy** | **96,11%** [95,2 – 97,0] | 98,60% | 95,36% | 96,50% | 94,39% |
| **Precision** | **97,71%** [96,7 – 98,6] | 100,00% | 95,48% | 99,01% | 99,33% |
| **Recall (TPR)** | **95,11%** [93,7 – 96,5] | 96,73% | 95,99% | 95,69% | 90,80% |
| **F1-Score** | **96,39%** [95,5 – 97,3] | 98,34% | 95,73% | 97,32% | 94,87% |
| **AUC-ROC** | **98,89%** [98,4 – 99,3] | 99,97% | 98,20% | 99,07% | 98,84% |
| **FPR** | **2,67%** [1,6 – 3,9] | 0,00% | 5,38% | 1,90% | 0,82% |
| **Specificity** | 97,33% | 100,00% | 94,62% | 98,10% | 99,18% |
| **MCC** | 92,22% | 97,17% | 90,66% | 92,37% | 89,13% |

**Tập D phản ánh thực tế sát nhất:** nó được tạo sau khi các luật và mô hình đã gần hoàn chỉnh, và chứa 22 shop/sàn đầu tư giả, nhóm khó nhất. Recall thấp hơn (90,8%) chủ yếu vì các shop giả này.

### Các chỉ số nghĩa là gì?

| Chỉ số | Câu hỏi nó trả lời |
|---|---|
| **Accuracy** | Trong tất cả web đã quét, bao nhiêu phần trăm kết luận đúng? |
| **Precision** | Khi Verity báo "nguy hiểm", bao nhiêu phần trăm là nguy hiểm thật? (cao = ít báo động giả) |
| **Recall** | Trong tất cả web nguy hiểm, Verity bắt được bao nhiêu phần trăm? (cao = ít bỏ sót) |
| **F1-Score** | Trung bình điều hoà của Precision và Recall; hữu ích khi dữ liệu mất cân bằng |
| **AUC-ROC** | Chọn ngẫu nhiên một web nguy hiểm và một web hợp pháp: xác suất web nguy hiểm bị chấm điểm thấp hơn. Không phụ thuộc ngưỡng |
| **FPR** | Bao nhiêu phần trăm web hợp pháp bị báo nhầm là nguy hiểm? (thấp = tốt) |
| **MCC** | Hệ số tương quan giữa dự đoán và thực tế, từ −100% đến 100%; phạt cả báo nhầm lẫn bỏ sót |

### Nếu tính cả mức "Cảnh báo" là nguy hiểm (điểm < 75)

Bỏ sót gần như không còn, đổi lại nhiều web hợp pháp ít phổ biến bị xếp "Cảnh báo".

| Accuracy | Precision | Recall | F1 | FPR |
|---|---|---|---|---|
| 92,59% | 88,97% | **98,67%** | 93,57% | 14,71% |

Nói cách khác: chỉ **12/899** web nguy hiểm (1,3%) bị xếp nhầm vào mức "An toàn".

---

## Bốn tập dữ liệu

Mọi file nằm trong [`eval/`](../eval/README.md).

### Tập A — 358 web (dễ hơn)

| Nhóm | Số lượng | Nguồn |
|---|---|---|
| Hợp pháp | 205 | Web Việt Nam và quốc tế phổ biến: ngân hàng, báo, TMĐT, cơ quan nhà nước |
| Cờ bạc | 33 | Nhà cái và cờ bạc trá hình |
| Lừa đảo | 120 | Chọn ngẫu nhiên (seed 3) từ 300 URL của [OpenPhish](https://openphish.com), chụp ngày 07/11/2026 |

### Tập B — 695 web (khó hơn, gán nhãn thủ công ngày 08/11/2026)

| Nhóm | Số lượng | Nguồn |
|---|---|---|
| Hợp pháp | 318 | Web **ngoài top 10.000** Tranco (phần lớn `.vn`, tức web nhỏ, ít người biết); 12 web hợp pháp có tên thương hiệu trong tên miền (`whatsapp-fast.vercel.app`, `vodafone-business-berlin.de`…) |
| Cờ bạc | 192 | [hagezi gambling list](https://github.com/hagezi/dns-blocklists); 10 blog vệ tinh SEO cho casino; web cờ bạc giả trang Google Play |
| Lừa đảo | 185 | [phishunt.io](https://phishunt.io) (176 trong 1.003 URL), [tinnhiemmang.vn](https://tinnhiemmang.vn/website-lua-dao) (NCSC Việt Nam), blocklist web bán hàng lừa đảo, phishing.army |

**Cách gán nhãn tập B:** đọc tiêu đề và nội dung của khoảng 1.400 trang.
- Chỉ tính **lừa đảo** khi có dấu hiệu rõ ràng: form đăng nhập giả, trang ví crypto/seed phrase giả, file cài Chrome/Adobe giả, thẻ quà tặng giả, sàn đầu tư AI giả, shop bán súng/chó/cần sa giả.
- **Bỏ khỏi tập** các trang không chắc chắn: blog cũ chỉ có tên "facebook", đồ án sao chép giao diện có ghi chú rõ, trang đã chết, trang đỗ tên miền.
- Không trang nào thuộc hai tập này được dùng để huấn luyện mô hình.

### Tập C — 314 web (mẫu mới hoàn toàn, gán nhãn thủ công ngày 08/11/2026)

| Nhóm | Số lượng | Nguồn |
|---|---|---|
| Hợp pháp | 105 | Chọn ngẫu nhiên từ Tranco thứ hạng 10.000–1.000.000 (một nửa là `.vn`) |
| Cờ bạc | 171 | [hagezi gambling list](https://github.com/hagezi/dns-blocklists), cộng 7 web nằm trong Tranco nhưng thực chất là cờ bạc (tên miền hết hạn bị mua lại) và 2 trang trong feed phishing |
| Lừa đảo | 38 | [OpenPhish](https://openphish.com) và [phishunt.io](https://phishunt.io) ngày 08/11/2026 |

- **Không trùng tên miền nào** với tập A, tập B, dữ liệu huấn luyện hai mô hình (khoảng 406.000 tên miền) hay các feed lừa đảo dùng để huấn luyện.
- Trong 297 trang lừa đảo còn sống, chỉ giữ 38 trang có dấu hiệu rõ ràng: form đăng nhập Meta/Instagram/Google/Coinbase giả, trang nhập seed phrase, Ledger/Trezor giả, Allegro giả, Roblox giả, thông báo thuế giả.
- **Bỏ khỏi tập:** khoảng 60 trang `*-whatsapp.com` chỉ hiện bản sao Yahoo/Bing (che giấu nội dung thật), blog Blogspot cũ chỉ mang tên "facebook", đồ án clone trên GitHub, trang mô phỏng phishing để đào tạo nhân viên, trang chết, trang đỗ tên miền.

### Tập D — 286 web (mẫu mới, gán nhãn thủ công ngày 09/11/2026)

| Nhóm | Số lượng | Nguồn |
|---|---|---|
| Hợp pháp | 122 | Chọn ngẫu nhiên từ Tranco thứ hạng 10.000–1.000.000 |
| Cờ bạc | 132 | [hagezi gambling list](https://github.com/hagezi/dns-blocklists) |
| Lừa đảo | 32 | 10 trang từ OpenPhish/phishunt.io, cộng 22 shop giả và sàn đầu tư giả từ các blocklist web bán hàng lừa đảo |

- **Không trùng tên miền nào** với tập A/B/C, dữ liệu huấn luyện hay danh sách 1.697 tên miền cờ bạc đã rà soát thủ công trong Tranco.
- **Về độ "sạch" của số đo tập D:** luật "shop không minh bạch" (shop mới, trang chủ không có thông tin liên hệ) được viết sau khi xem các shop giả bị bỏ sót trên tập D, nên số đo tập D hơi lạc quan. Trước khi thêm luật: Accuracy 92,66%, Recall 87,80%. Trên tập A, B, C luật chỉ kích hoạt 1 lần, và lần đó là báo nhầm.

---

## Điểm yếu đã biết

Những ca Verity còn sai, rút từ tập B, C và D:

| Loại | Ví dụ | Vì sao khó |
|---|---|---|
| **Lừa đảo bán hàng / đầu tư không có form đăng nhập** | Shop súng giả (85 điểm), sàn đầu tư AI (82), đại lý vé giả mạo Vietnam Airlines (98), web bán bằng giả | Không có ô mật khẩu, không giả thương hiệu trên tên miền; trông như một shop bình thường. Trên tập D mới bắt được 12/22 |
| **Cờ bạc bằng ngôn ngữ ít gặp** | Trang cá cược tiếng Thái, Thổ Nhĩ Kỳ, Ba Tư, Indonesia | Từ khoá cờ bạc chủ yếu là tiếng Việt và tiếng Anh; chỉ bị xếp "Cảnh báo" (52–74) |
| **Web hợp pháp có tên thương hiệu trong tên miền** | `whatsapp-fast.vercel.app`, `netflixvoid.org`, `googleapps.lk` | Trông y hệt kỹ thuật mạo danh phổ biến nhất |
| **Tên miền cũ bị mua lại làm cờ bạc** | `stampinmagic.com` (95 điểm), `mobileslotsite.co.uk` (96), `black-satta.com` (100) — tập C | Tên miền lâu năm, vẫn còn trong Tranco nên được cộng điểm độ phổ biến |
| **Trang chỉ có form đăng nhập** | Cổng đăng nhập của cơ quan, ứng dụng nội bộ | Không có nội dung nào khác để phân biệt với trang phishing |

**Về độ "sạch" của số đo tập B:** luật giả danh thương hiệu được sửa sau khi xem lỗi trên tập B, nên số đo của tập B hơi lạc quan. Con số trước khi sửa (chưa tinh chỉnh) là: Accuracy 93,24%, Precision 93,65%, Recall 93,90%, F1 93,77%, AUC 97,66%, FPR 7,55%. Kết quả từng web của cả hai lần đo đều có trong [`eval/results/`](../eval/results/).

---

## Trọng tài VerityTrust Decision Engine (MiniLMv2 zero-shot)

Đo ngày 08/11/2026 trên tập B ở chế độ **chạy ngầm** (`JEV_MODE=veritytrust JEV_SHADOW=true JEV_GRAY_ZONE_ONLY=false`): engine được hỏi cho mọi web nhưng không đổi điểm. 526 web có đủ dữ liệu để gửi; kết quả từng web trong [`eval/results/set-b-veritytrust-engine-v2.json`](../eval/results/set-b-veritytrust-engine-v2.json).

| | AUC | Accuracy | Recall | FPR |
|---|---|---|---|---|
| Engine riêng, luật chặn `is_phishing > 0,6` hoặc `choice ≠ clean` | 57,9% | 49,2% | 9,6% | 14,9% |
| Verity (không có engine) | 97,0% | 92,6% | 90,4% | 5,4% |
| Verity + engine áp điểm ở vùng xám (giả lập) | — | 92,2% | 89,6% | 5,4% |

- **v1 của engine** (so "lừa đảo" với "an toàn" rồi khuếch đại) gần như chấm mọi thứ là lừa đảo: 204/271 web hợp pháp bị xếp `credential_theft`, xác suất lừa đảo trung bình 0,76; cả chuỗi `hello` cũng ra 98%.
- **v2** (chấm từng giả thuyết độc lập) hết báo động giả, nhưng 169/185 web lừa đảo và 57/65 web cờ bạc vẫn bị xếp `clean`. AUC 58% chỉ nhỉnh hơn đoán ngẫu nhiên (50%).
- **Lý do:** mô hình NLI zero-shot chỉ đoán theo câu chữ của dòng metadata, không biết `vietcombank.com.vn` là thật còn `vietcombank-otp.vip` là giả. Muốn engine có ích cần fine-tune trên dữ liệu đã gán nhãn.
- **Khuyến nghị:** chỉ dùng ở chế độ chạy ngầm cho tới khi đo lại đạt AUC cao.

Phân tích lại: `python3 scripts/analyze-jev-shadow.py eval/results/set-b-veritytrust-engine-v2.json`.

### Engine v3: `Horizon-Labs/phishing-scam-detector-base` (mmBERT, ONNX int8)

Mã nguồn: [`engine/engine.py`](../engine/engine.py). Mô hình trả về xác suất `fraud` / `spam` / `legitimate`. Đo ở chế độ chạy ngầm trên tập B (525 web có câu trả lời) và tập C (205 web):

| AUC | Tập B | Tập C |
|---|---|---|
| `fraud`, phishing so với hợp pháp | **88,5%** | **91,1%** |
| `fraud`, cờ bạc so với hợp pháp | 58,5% | 66,5% |
| `fraud + spam`, phishing so với hợp pháp | 48,6% | 48,9% |
| Verity (để so sánh), mọi web nguy hiểm | 96,8% | 96,8% |

| Luật chặn (tập B) | Precision | Recall | FPR |
|---|---|---|---|
| `fraud ≥ 0,5` | **98,4%** | 24,1% | **0,4%** |
| `fraud + spam ≥ 0,5` | 48,2% | 94,8% | **92,0%** |

- **`fraud` đáng tin, `spam` thì không.** Mô hình học từ email và SMS, nên chấm cả web hợp pháp (báo, shop) là spam: trung bình 0,77 trên web hợp pháp. Vì vậy engine v3 chỉ dùng `fraud`.
- **Chưa giúp tăng độ chính xác của Verity.** Những trang engine chấm `fraud` cao là trang đăng nhập giả, mà Verity vốn đã bắt được. Trên tập B, áp `fraud ≥ 0,5` cho mọi web chỉ cứu thêm 1 web lừa đảo và đổi lại 1 web hợp pháp bị báo nhầm. Các web Verity còn bỏ sót (shop giả, cờ bạc tiếng nước ngoài) đều bị engine chấm `fraud` thấp.
- **Khuyến nghị:** có thể bật áp điểm thật ở vùng xám vì gần như không báo nhầm, nhưng đừng kỳ vọng độ chính xác tăng.

Phân tích lại: `python3 scripts/analyze-jev-v3.py eval/results/set-b-veritytrust-engine-v3.json`.

---

## Tự đo lại

**1. Chạy máy chủ** với danh sách đen tắt và không giới hạn tần suất:

```bash
THREAT_FEEDS=off RATE_LIMIT_PER_MIN=0 npm run dev
```

**2. Mở terminal khác, chạy bốn tập** (mất khoảng 3–6 phút mỗi tập):

```bash
npm run eval:a
```

```bash
npm run eval:b
```

```bash
npm run eval:c
```

```bash
npm run eval:d
```

**3. Tính chỉ số:**

```bash
npm run eval:metrics
```

Muốn tính cho một tập riêng: `npx tsx scripts/eval-metrics.ts eval/results/set-b.json`.

> ⚠️ **Lưu ý:**
> - Máy yếu (RAM 8 GB) nên đo lần lượt từng tập và giảm `--concurrency` xuống 2: quét song song nhiều web có thể làm máy treo.
> - Web thật thay đổi theo thời gian: trang lừa đảo bị gỡ, web hợp pháp đổi giao diện. Kết quả đo lại sẽ chênh lệch vài phần trăm so với số ở trên; phần lớn chênh lệch đến từ trang đã chết.
> - Khi đo, máy chủ **sẽ tải HTML của các trang lừa đảo thật**. Hệ thống không chạy JavaScript của trang ở Tầng 2, nhưng vẫn nên chạy trong môi trường bạn chấp nhận được.

### Đo thử trên dữ liệu của bạn

Tạo file JSON có dạng:

```json
{ "safe": ["vietcombank.com.vn", "https://shopcuaban.vn/"], "dangerous": ["https://web-co-bac.xyz/"] }
```

Thêm danh sách phishing (mỗi dòng một URL) nếu có, rồi chạy:

```bash
npx tsx scripts/eval-accuracy.ts --dataset du-lieu.json --phishing-file phishing.txt --phishing 1000 --out ket-qua.json
```

```bash
npx tsx scripts/eval-metrics.ts ket-qua.json
```
