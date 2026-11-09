# Kiến trúc — đường ống quét nhiều tầng

[← Về README](../README.md)

Verity quét mỗi đường link qua tối đa **6 tầng**, sắp từ rẻ đến đắt. Ca nào đã đủ bằng chứng để kết luận thì **dừng sớm**, không chạy các tầng sau. Nhờ vậy web phổ biến (google.com, vietcombank.com.vn) có kết quả trong khoảng 0,2 giây, còn phần lớn thời gian xử lý dành cho các ca thật sự đáng ngờ.

Mã nguồn chính: [`server/scanPipeline.ts`](../server/scanPipeline.ts).

```mermaid
flowchart TD
    IN([Đường link]) --> T0
    subgraph T0 [Tầng 0 — NetSafety & DNS]
      direction LR
      a0[Chặn IP nội bộ / SSRF] --> b0[Phân giải DNS]
    end
    T0 -->|NXDOMAIN hoặc IP nội bộ| E0([Dừng: không truy cập được])
    T0 --> T1
    subgraph T1 [Tầng 1 — Danh tiếng cứng · trong bộ nhớ]
      direction LR
      a1[Tranco top 200k] --- b1[Danh sách đen] --- c1[Tên miền cờ bạc]
    end
    T1 -->|chính thống hoặc top 10k| SAFE([✅ An toàn])
    T1 -->|danh sách đen hoặc cờ bạc| DANGER([⛔ Nguy hiểm])
    T1 --> T2
    subgraph T2 [Tầng 2 — Bằng chứng & AI cục bộ]
      direction LR
      a2[HTML tĩnh] --- b2[TLS] --- c2[Tuổi tên miền RDAP] --- d2[2 mô hình học sâu]
    end
    T2 -->|điểm dưới 45 hoặc từ 75| OUT([Kết luận])
    T2 -->|HTML rỗng / SPA và điểm 45–74| T3[Tầng 3 — Chrome headless dựng trang, chấm lại]
    T2 -->|điểm 45–74| T4
    T3 --> T4[Tầng 4 — Trọng tài Jev / OpenJev · tuỳ chọn]
    T4 --> OUT
    OUT -. người dùng bấm .-> T5[Tầng 5 — LLM viết lời giải thích]
```

---

## Tầng 0 — NetSafety & phân giải DNS

**Mục đích:** không cho kẻ xấu lợi dụng máy chủ Verity để truy cập mạng nội bộ (tấn công SSRF), và loại ngay các tên miền không tồn tại.

- Từ chối mọi địa chỉ thuộc dải nội bộ hoặc đặc biệt: `127.0.0.0/8`, `10.0.0.0/8`, `192.168.0.0/16`, `169.254.0.0/16` (metadata đám mây), IPv6 nội bộ…
- Mỗi lần trang chuyển hướng (redirect) đều được kiểm tra lại DNS, tối đa 5 lần.
- **Dừng sớm khi:** tên miền không tồn tại (NXDOMAIN), hoặc tên miền công khai nhưng trỏ về IP nội bộ.

Mã: [`server/netSafety.ts`](../server/netSafety.ts), hàm `resolveTargetDns` trong [`server/evidence.ts`](../server/evidence.ts).

## Tầng 1 — Danh tiếng cứng (không tải trang)

**Mục đích:** trả lời ngay những ca hiển nhiên mà không cần tải HTML.

| Nguồn | Nội dung | Cập nhật |
|---|---|---|
| [Tranco](https://tranco-list.eu) | 200.000 tên miền phổ biến nhất thế giới | tải nền, lưu `.cache/` |
| Danh mục chính thống | ngân hàng, cơ quan nhà nước, sàn TMĐT lớn ([`domainRules.ts`](../server/domainRules.ts)) | trong mã |
| [Phishing.Database](https://github.com/Phishing-Database/Phishing.Database), [OpenPhish](https://openphish.com) | danh sách đen URL/tên miền lừa đảo | tải nền |
| Google Safe Browsing | tuỳ chọn, cần `GOOGLE_SAFE_BROWSING_API_KEY` | trực tuyến |
| Luật tên miền cờ bạc | `1xbet`, `fb88`, `nhacai`, `taixiu`… | trong mã |

- **Dừng "An toàn" khi:** tên miền thuộc danh mục chính thống, hoặc nằm trong top 10.000 Tranco. Subdomain người dùng tự tạo trên hosting miễn phí (`abc.vercel.app`, `xyz.github.io`…) không được hưởng ngoại lệ này.
- **Dừng "Nguy hiểm" khi:** có trong danh sách đen, hoặc là tên miền cờ bạc rõ ràng.

## Tầng 2 — Bằng chứng & AI cục bộ

**Mục đích:** thu thập mọi dấu vết kỹ thuật rồi chấm điểm theo bằng chứng. Đây là tầng làm việc chính.

1. **Tải HTML** qua `safeFetch`: tối đa 1 MB, hết thời gian sau 6 giây, không chạy JavaScript.
2. **Phân tích HTML** (`analyzeHtml`): ô mật khẩu, ô OTP/số thẻ/cụm từ khôi phục ví, form gửi dữ liệu sang tên miền khác, mã JavaScript bị làm rối, gửi dữ liệu qua Telegram bot, favicon của thương hiệu khác, thương hiệu được nhắc tới, logo Bộ Công Thương, mã số thuế…
3. **Chứng chỉ TLS:** còn hạn không, cấp bao lâu rồi.
4. **Tuổi tên miền** qua RDAP (tra trực tiếp registry theo bảng IANA).
5. **Hai mô hình học sâu** chạy cục bộ: một đọc tên miền, một đọc nội dung trang — xem [MO-HINH-AI.md](MO-HINH-AI.md).
6. **Chấm điểm** ([`riskScoring.ts`](../server/riskScoring.ts)) — xem [CHAM-DIEM.md](CHAM-DIEM.md).

- **Dừng khi:** điểm dưới 45 (rõ ràng nguy hiểm) hoặc từ 75 trở lên (rõ ràng an toàn).

## Tầng 3 — Trình duyệt headless (chỉ khi cần)

**Mục đích:** nhiều bộ công cụ lừa đảo chỉ vẽ form đăng nhập bằng JavaScript để né các bộ quét đọc HTML tĩnh. Tầng này dùng Chrome thật để dựng trang, lấy DOM cuối cùng, rồi chấm lại bằng logic của Tầng 2.

- **Chỉ chạy khi** HTML tĩnh gần như rỗng, là khung SPA hoặc trang chặn bot, **và** điểm còn ở vùng xám 45–74.
- Dùng Chrome/Chromium có sẵn trên máy qua `playwright-core` (không tải thêm trình duyệt). Không tìm thấy Chrome thì tầng này tự bỏ qua.
- **An toàn:**
  - Mỗi lần dựng dùng một phiên ẩn danh mới.
  - **Mọi request** của trình duyệt, kể cả request do JavaScript của trang tạo ra, đều qua bộ chặn SSRF.
  - Chặn ảnh, CSS, font, tải file, service worker và quyền truy cập thiết bị.
  - Tối đa 2 trang cùng lúc, mỗi trang tối đa 8 giây.

Mã: [`server/headless.ts`](../server/headless.ts). Cấu hình: `HEADLESS_RENDER`, `CHROME_PATH`, `HEADLESS_TIMEOUT_MS`, `HEADLESS_CONCURRENCY`.

## Tầng 4 — Trọng tài Jev / OpenJev (tuỳ chọn)

**Mục đích:** với ca vùng xám 45–74 điểm, hỏi thêm một mô hình ra quyết định bên ngoài.

[Jev](https://docs.typesafe.ai/introduction) của TypeSafe AI là mô hình "System One": nhận một *state* và các câu hỏi có kiểu, rồi trả về **xác suất đã hiệu chỉnh** thay vì văn bản tự do. Verity gửi:

- **state:** URL, tên miền, tuổi tên miền, thứ hạng Tranco, TLS, có ô mật khẩu/OTP hay không, form gửi ra ngoài, thương hiệu được nhắc tới, điểm bằng chứng hiện tại, tiêu đề và 3.000 ký tự đầu của trang.
- **4 câu hỏi:**

| Mã câu hỏi | Kiểu | Hỏi gì |
|---|---|---|
| `is_credential_harvesting` | Noul (có/không) | Trang có thu thập mật khẩu, OTP, số thẻ, cụm từ khôi phục ví của dịch vụ khác không? |
| `is_financial_or_gambling_scam` | Noul | Có phải cờ bạc, hoặc lừa đảo tài chính (đầu tư, việc ảo, đa cấp, shop giả)? |
| `is_brand_impersonation` | Noul | Có giả danh ngân hàng, thương hiệu, sàn TMĐT, cơ quan nhà nước không? |
| `final_verdict` | Choice | `safe` / `suspicious` / `phishing` / `gambling` / `malicious` |

**Cách áp dụng câu trả lời** — mỗi kết luận được ghi thành một bằng chứng có giải thích, như mọi bằng chứng khác:

| Câu trả lời | Tác động |
|---|---|
| Thu thập thông tin xác thực, xác suất ≥ 80% | −30 điểm, trần 15 |
| Giả danh thương hiệu ≥ 80% | −35 điểm, trần 15 |
| Lừa đảo tài chính / cờ bạc ≥ 80% | −35 điểm, trần 15 |
| `safe` ≥ 85% và không có dấu hiệu xấu nào ở trên | +15 điểm (tối đa 95) |

**Cấu hình:**

| `JEV_MODE` | Gọi tới | Cần |
|---|---|---|
| `off` (mặc định) | — | — |
| `api` | `https://api.typesafe.ai/v1/systemone`, model `jev-latest` | `JEV_API_KEY` (hoặc `TYPESAFE_API_KEY`) lấy tại [console.typesafe.ai](https://console.typesafe.ai/keys) |
| `openjev` | `OPENJEV_ENDPOINT` (mặc định `http://localhost:8080/v1/systemone`) | máy chủ tự host tương thích Jev |
| `veritytrust` | `VERITYTRUST_ENGINE_URL` (mặc định cổng OmniRoute `http://homenasproxmox.duckdns.org:20128/v1/chat/completions`), model `veritytrust-fast-decision` | `VERITYTRUST_ENGINE_KEY` |

**Chạy ngầm (`JEV_SHADOW=true`):** vẫn hỏi trọng tài và ghi câu trả lời vào `score_breakdown.jev_decision` (kèm `shadow: true`), nhưng **không đổi điểm**. Dùng để đo một trọng tài mới trước khi tin dùng. Thêm `JEV_GRAY_ZONE_ONLY=false` để hỏi trọng tài cho mọi web, không riêng vùng xám; công cụ đo `scripts/eval-accuracy.ts` tự lưu câu trả lời vào trường `jev` của từng web.

- Lỗi mạng, sai key hoặc quá thời gian (`JEV_TIMEOUT_MS`, mặc định 5 giây) → giữ nguyên kết luận theo bằng chứng.
- `JEV_MODE=api` mà thiếu key → tầng này tự bỏ qua, không gửi request.
- Tóm tắt nội dung trang chỉ được gửi tới Jev khi bạn bật tầng này.

### VerityTrust-Engine (`JEV_MODE=veritytrust`)

Một máy chủ riêng, đặt sau cổng OmniRoute (chuẩn OpenAI). Mã nguồn bản hiện tại: [`engine/engine.py`](../engine/engine.py), dùng mô hình phân loại lừa đảo đa ngôn ngữ [`Horizon-Labs/phishing-scam-detector-base`](https://huggingface.co/Horizon-Labs/phishing-scam-detector-base) (mmBERT, ONNX int8, chạy CPU bằng onnxruntime, khoảng 1 GB RAM). Bản cũ dùng mô hình NLI zero-shot `multilingual-MiniLMv2-L6-mnli-xnli` và bị loại sau khi đo (xem [DANH-GIA.md](DANH-GIA.md#trọng-tài-veritytrust-decision-engine-minilmv2-zero-shot)). Verity gửi **một dòng metadata** trong `messages[0].content`:

```
Tên miền: … | SSL: Hợp lệ/Hết hạn/Không có | Tuổi tên miền: … ngày | Xếp hạng Tranco: … | Biểu mẫu: Bắt buộc điền … | Tiêu đề: … | Nội dung: …
```

và nhận lại JSON trong `choices[0].message.content`:

```json
{ "is_phishing": { "probability": 0.94 }, "risk_vector": { "choice": "credential_theft", "confidence": 0.93 }, "trust_score": { "score": 1.15, "confidence": 0.94 } }
```

`risk_vector.choice` là `clean`, `credential_theft`, `gambling` hoặc `scam` (shop giả, đầu tư ảo). Cách quy đổi sang câu trả lời trọng tài: `credential_theft`, `gambling`, `scam` chỉ được tính khi `is_phishing ≥ 0,5`, với độ tin cậy = min(`is_phishing`, `risk_vector.confidence`); `clean` tính là `safe`. Sau đó áp dụng như bảng tác động ở trên.

Mã: [`server/jevDecision.ts`](../server/jevDecision.ts).

## Tầng 5 — LLM viết lời giải thích (theo yêu cầu)

**Mục đích:** diễn giải kết quả bằng ngôn ngữ dễ hiểu cho người dùng phổ thông.

- **Không nằm trong đường chấm điểm:** AI không thể thay đổi điểm số.
- Chỉ chạy khi người dùng bấm "Xem giải thích chi tiết (AI)" → `POST /api/explain`.
- Dùng Gemini hoặc OpenRouter nếu có API key; không có key thì dùng bản giải thích soạn từ bảng bằng chứng.

---

## Theo dõi hành trình qua các tầng

Mỗi kết quả của `/api/analyze` có trường `pipeline` cho biết dừng ở tầng nào, vì sao, và mỗi tầng mất bao lâu:

```json
"pipeline": {
  "exit_tier": 1,
  "exit_reason": "Website phổ biến (Tranco #1.234)",
  "total_ms": 180,
  "rendered_by_headless": false,
  "tiers": [
    { "tier": 0, "name": "NetSafety & Phân giải DNS", "status": "passed", "ms": 160, "note": "Phân giải 1.2.3.4 (IP công khai)" },
    { "tier": 1, "name": "Danh tiếng cứng & Tên miền", "status": "exit", "ms": 1, "note": "Website phổ biến (Tranco #1.234)" },
    { "tier": 2, "name": "Bằng chứng & AI cục bộ", "status": "skipped", "ms": 0, "note": "Dừng sớm ở Tầng 1 - bỏ qua tải HTML" }
  ]
}
```

Giao diện web hiển thị phần này ở mục **"Các Tầng Quét"**.

## Các lớp bảo vệ an toàn

| Rủi ro | Biện pháp |
|---|---|
| SSRF: dùng Verity để gọi vào mạng nội bộ | Chặn IP nội bộ ở mọi bước: DNS ban đầu, từng redirect, từng request của trình duyệt headless |
| Trang độc hại làm treo máy chủ | Giới hạn 1 MB, 6 giây cho mỗi trang; 2 trình duyệt đồng thời, 8 giây mỗi trang |
| Chứng chỉ lỗi trên trang lừa đảo | Chỉ request **tải trang đích** chấp nhận chứng chỉ lỗi (để vẫn đọc được trang). Mọi kết nối khác, như gọi API AI, vẫn kiểm tra chứng chỉ đầy đủ |
| Lạm dụng API | Giới hạn tần suất theo IP (`RATE_LIMIT_PER_MIN`, mặc định 30/phút) |
| Trang mở hộp thoại, tải file, xin quyền | Headless tự đóng hộp thoại, chặn tải file, không cấp quyền nào |
