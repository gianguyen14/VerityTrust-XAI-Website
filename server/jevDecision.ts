/**
 * Module tích hợp Jev / OpenJev Decision Gateway.
 * Cung cấp tùy chọn cấu hình linh hoạt:
 *   - JEV_MODE=off      : (Mặc định) Tắt, dùng động cơ bằng chứng và mạng nơ-ron Hashed MLP nội bộ (0đ, nhẹ máy, không cần AVX2).
 *   - JEV_MODE=api      : Sử dụng TypeSafe AI Jev Cloud API thương mại (cần JEV_API_KEY).
 *   - JEV_MODE=openjev  : Sử dụng OpenJev tự host (mã nguồn mở / open-weights) qua OPENJEV_ENDPOINT.
 *   - JEV_MODE=veritytrust : VerityTrust Decision Engine qua cổng OpenAI-compatible (OmniRoute), model veritytrust-fast-decision.
 * JEV_SHADOW=true: vẫn gọi trọng tài nhưng chỉ ghi lại kết quả, không đổi điểm (dùng để đo trước khi tin dùng).
 */

import type { SiteEvidence } from './evidence.ts';
import type { RiskAssessment } from './riskScoring.ts';

export type JevMode = 'off' | 'api' | 'openjev' | 'veritytrust';

/** Vùng xám: điểm bằng chứng chưa dứt khoát, cần trọng tài phân xử (Tầng 4) */
export const GRAY_ZONE_MIN = 45;
export const GRAY_ZONE_MAX = 74;

export interface JevDecisionResult {
  engine: 'jev-api' | 'openjev' | 'VerityTrust-Engine';
  latencyMs: number;
  /** true khi JEV_SHADOW=true: kết quả chỉ được ghi lại, không áp vào điểm */
  shadow?: boolean;
  /** Câu trả lời gốc của VerityTrust Decision Engine (is_phishing, risk_vector, trust_score) */
  raw?: unknown;
  isCredentialHarvesting: boolean;
  isCredentialHarvestingConfidence: number;
  isFinancialOrGamblingScam: boolean;
  isFinancialOrGamblingScamConfidence: number;
  isBrandImpersonation: boolean;
  isBrandImpersonationConfidence: number;
  verdict: 'safe' | 'suspicious' | 'phishing' | 'gambling' | 'malicious';
  verdictProbabilities: Record<string, number>;
}

export interface JevConfig {
  mode: JevMode;
  model: string;
  apiUrl: string;
  apiKey: string;
  openJevEndpoint: string;
  openJevApiKey: string;
  veritytrustUrl: string;
  veritytrustKey: string;
  veritytrustModel: string;
  shadow: boolean;
  grayZoneOnly: boolean;
  timeoutMs: number;
}

export function getJevConfig(): JevConfig {
  const rawMode = (process.env.JEV_MODE || 'off').toLowerCase().trim();
  const mode: JevMode = rawMode === 'api' || rawMode === 'openjev' || rawMode === 'veritytrust' ? rawMode : 'off';
  return {
    mode,
    model: process.env.JEV_MODEL || 'jev-latest',
    apiUrl: process.env.JEV_API_URL || 'https://api.typesafe.ai/v1/systemone',
    apiKey: process.env.JEV_API_KEY || process.env.TYPESAFE_API_KEY || '',
    // Các bản OpenJev tự host đều mô phỏng cùng endpoint System One của Jev
    openJevEndpoint: process.env.OPENJEV_ENDPOINT || 'http://localhost:8080/v1/systemone',
    openJevApiKey: process.env.OPENJEV_API_KEY || '',
    veritytrustUrl: process.env.VERITYTRUST_ENGINE_URL || 'http://homenasproxmox.duckdns.org:20128/v1/chat/completions',
    veritytrustKey: process.env.VERITYTRUST_ENGINE_KEY || '',
    veritytrustModel: process.env.VERITYTRUST_ENGINE_MODEL || 'veritytrust-fast-decision/veritytrust-fast-decision',
    shadow: process.env.JEV_SHADOW === 'true',
    grayZoneOnly: process.env.JEV_GRAY_ZONE_ONLY !== 'false', // Mặc định chỉ gọi cho ca vùng xám 45-74 điểm
    timeoutMs: parseInt(process.env.JEV_TIMEOUT_MS || '5000', 10),
  };
}

/**
 * Trích xuất State cô đọng từ Evidence kỹ thuật để gửi cho Decision Model
 */
export function buildJevState(e: SiteEvidence, a: RiskAssessment) {
  const html = e.html;
  return {
    url: e.finalUrl || e.url,
    domain: e.domain.host,
    domain_suffix: e.domain.publicSuffix,
    domain_age_days: e.domainAge?.ageDays ?? null,
    is_popular: e.popularityRank !== null && e.popularityRank <= 200000,
    popularity_rank: e.popularityRank ?? null,
    tls_valid: e.tls?.ok ?? false,
    tls_age_days: e.tls?.certAgeDays ?? null,
    tls_issuer: e.tls?.issuer ?? null,
    has_password_field: html?.hasPasswordField ?? false,
    sensitive_inputs: html?.sensitiveFields ?? [],
    external_form_action: html?.externalFormAction ?? null,
    telegram_exfiltration: html?.telegramExfiltration ?? false,
    brand_mentions: html?.brandMentions ?? [],
    bot_challenge: html?.botChallenge ?? false,
    base_evidence_score: a.score,
    page_title: html?.title ?? '',
    page_markdown: html?.text ? html.text.slice(0, 3000) : '',
  };
}

/**
 * Bộ câu hỏi gửi cho Jev theo chuẩn System One (https://docs.typesafe.ai/primitives):
 * Noul = xác suất câu trả lời là "có" (0-1); Choice = chọn một nhãn kèm xác suất từng nhãn.
 * Mã câu hỏi (khoá) không được gửi cho mô hình, chỉ dùng để ghép câu trả lời.
 */
export const STANDARD_JEV_QUESTIONS = {
  is_credential_harvesting: {
    type: 'noul',
    instructions: 'Does this web page try to collect login credentials or secrets (passwords, SMS OTP codes, bank card numbers, crypto wallet recovery phrases) for an account that does not belong to the site owner?',
    criteria: {
      true: 'Asks visitors to enter passwords, OTPs, card details or a seed phrase for a bank, wallet, email or social account it does not operate',
      false: 'No such form, or a normal login for the site\'s own service',
    },
  },
  is_financial_or_gambling_scam: {
    type: 'noul',
    instructions: 'Is this web page online gambling or betting, or a financial scam (unrealistic investment returns, paid "tasks", Ponzi or pyramid schemes, fake loans, fake shops)?',
  },
  is_brand_impersonation: {
    type: 'noul',
    instructions: 'Does this web page pretend to be a bank, well-known brand, e-commerce marketplace or government service that does not own this domain?',
    criteria: {
      true: 'Uses another organisation\'s name, logo or login page on a domain that organisation does not own',
      false: 'The brand is the site\'s own, or is only mentioned (resellers, social login buttons, news, app-store links)',
    },
  },
  final_verdict: {
    type: 'choice',
    instructions: 'What is this web page?',
    criteria: {
      safe: 'A legitimate website',
      suspicious: 'Unclear or low-quality, but no clear sign of fraud',
      phishing: 'Steals credentials or impersonates another organisation',
      gambling: 'Online casino, betting or lottery',
      malicious: 'Other fraud or malware: fake shop, investment scam, fake download',
    },
  },
} as const;

/**
 * Gửi yêu cầu phân xử tới Jev Cloud API hoặc OpenJev Local/Worker Endpoint
 */
let warnedMissingKey = false;

export async function queryJevDecision(e: SiteEvidence, a: RiskAssessment, opts: { ignoreGrayZone?: boolean } = {}): Promise<JevDecisionResult | null> {
  const cfg = getJevConfig();
  if (cfg.mode === 'off') return null;

  // Nếu chỉ bật cho vùng xám (45 - 74 điểm) và bằng chứng đã dứt khoát rõ ràng -> Bỏ qua
  if (!opts.ignoreGrayZone && cfg.grayZoneOnly && (a.score < GRAY_ZONE_MIN || a.score > GRAY_ZONE_MAX)) {
    return null;
  }

  if (cfg.mode === 'veritytrust') return queryVeritytrustEngine(e, a, cfg);

  const targetUrl = cfg.mode === 'api' ? cfg.apiUrl : cfg.openJevEndpoint;
  const headers: Record<string, string> = {
    'Content-Type': 'application/json',
  };
  if (cfg.mode === 'api' && cfg.apiKey) {
    headers['Authorization'] = `Bearer ${cfg.apiKey}`;
  } else if (cfg.mode === 'openjev' && cfg.openJevApiKey) {
    headers['Authorization'] = `Bearer ${cfg.openJevApiKey}`;
  }

  if (cfg.mode === 'api' && !cfg.apiKey) {
    if (!warnedMissingKey) console.warn('[Jev Gateway] JEV_MODE=api nhưng chưa có JEV_API_KEY (hoặc TYPESAFE_API_KEY) - bỏ qua Tầng 4.');
    warnedMissingKey = true;
    return null;
  }

  // Chuẩn System One: POST /v1/systemone { model, state, questions } -> { model, answers, usage }
  const payload = {
    model: cfg.model,
    state: buildJevState(e, a),
    questions: STANDARD_JEV_QUESTIONS,
  };

  const t0 = Date.now();
  try {
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), cfg.timeoutMs);

    const res = await fetch(targetUrl, {
      method: 'POST',
      headers,
      body: JSON.stringify(payload),
      signal: controller.signal,
    });
    clearTimeout(timer);

    if (!res.ok) {
      const body = await res.text().catch(() => '');
      console.warn(`[Jev Gateway] ${cfg.mode} trả về lỗi HTTP ${res.status}: ${body.slice(0, 200) || res.statusText}`);
      return null;
    }

    const data: any = await res.json();
    const latencyMs = Date.now() - t0;

    // Câu trả lời nằm trong data.answers theo đúng khoá câu hỏi (giữ tương thích định dạng cũ data.decisions)
    const decisions = data.answers || data.decisions || data;
    const cred = decisions.is_credential_harvesting;
    const fin = decisions.is_financial_or_gambling_scam;
    const brand = decisions.is_brand_impersonation;
    const verdictData = decisions.final_verdict;

    const parseNoul = (n: any) => {
      if (typeof n?.noul === 'number') return { val: n.noul >= 0.5, conf: n.noul };
      if (typeof n === 'boolean') return { val: n, conf: 1 };
      if (typeof n === 'number') return { val: n >= 0.5, conf: n };
      return {
        val: n?.value === true || (typeof n?.confidence === 'number' && n.confidence >= 0.5),
        conf: typeof n?.confidence === 'number' ? n.confidence : 0.5,
      };
    };

    const cRes = parseNoul(cred);
    const fRes = parseNoul(fin);
    const bRes = parseNoul(brand);

    let finalChoice: JevDecisionResult['verdict'] = 'suspicious';
    let probs: Record<string, number> = {};

    if (typeof verdictData === 'string' && ['safe', 'suspicious', 'phishing', 'gambling', 'malicious'].includes(verdictData)) {
      finalChoice = verdictData as any;
      probs[finalChoice] = 1;
    } else if (verdictData?.choice) {
      finalChoice = verdictData.choice;
      probs = verdictData.probabilities || {};
    }

    console.log(`[Jev Gateway] 🎯 Phân xử (${cfg.mode}${data.model ? `, ${data.model}` : ''}) hoàn tất trong ${latencyMs}ms: ${finalChoice} (Cred: ${(cRes.conf * 100).toFixed(0)}%, Brand: ${(bRes.conf * 100).toFixed(0)}%, Fin: ${(fRes.conf * 100).toFixed(0)}%)`);

    return {
      engine: cfg.mode === 'api' ? 'jev-api' : 'openjev',
      latencyMs,
      isCredentialHarvesting: cRes.val,
      isCredentialHarvestingConfidence: cRes.conf,
      isFinancialOrGamblingScam: fRes.val,
      isFinancialOrGamblingScamConfidence: fRes.conf,
      isBrandImpersonation: bRes.val,
      isBrandImpersonationConfidence: bRes.conf,
      verdict: finalChoice,
      verdictProbabilities: probs,
      shadow: cfg.shadow,
    };
  } catch (err: any) {
    console.warn(`[Jev Gateway] Không gọi được ${cfg.mode} (${err?.message || err}) sau ${Date.now() - t0}ms. Rơi về chấm điểm bằng chứng nội bộ.`);
    return null;
  }
}

/**
 * Chuỗi metadata một dòng cho VerityTrust Decision Engine, theo đúng dạng engine được huấn luyện:
 * "Tên miền: … | SSL: … | Biểu mẫu: …"
 */
export function buildVeritytrustMetadata(e: SiteEvidence): string {
  const html = e.html;
  const parts = [`Tên miền: ${(e.finalDomain || e.domain).host}`];
  if (e.tls) parts.push(`SSL: ${!e.tls.ok ? 'Không có' : e.tls.daysRemaining !== null && e.tls.daysRemaining < 0 ? 'Hết hạn' : e.tls.authorized ? 'Hợp lệ' : 'Không hợp lệ'}`);
  if (e.domainAge?.ageDays != null) parts.push(`Tuổi tên miền: ${e.domainAge.ageDays} ngày`);
  parts.push(`Xếp hạng Tranco: ${e.popularityRank ?? 'ngoài top 1 triệu'}`);
  if (html) {
    const fields = [...(html.hasPasswordField ? ['mật khẩu'] : []), ...html.sensitiveFields];
    parts.push(`Biểu mẫu: ${fields.length ? `Bắt buộc điền ${[...new Set(fields)].join(', ')}` : 'không có'}`);
    if (html.externalFormAction) parts.push(`Gửi biểu mẫu tới: ${html.externalFormAction}`);
    if (html.telegramExfiltration) parts.push('Gửi dữ liệu qua Telegram bot');
    if (html.brandMentions.length) parts.push(`Nhắc tới thương hiệu: ${html.brandMentions.join(', ')}`);
    // "|" là dấu phân cách trường, nên thay trong tiêu đề/nội dung để engine tách trường đúng
    if (html.title) parts.push(`Tiêu đề: ${html.title.replace(/\|/g, '/').slice(0, 120)}`);
    if (html.text) parts.push(`Nội dung: ${html.text.replace(/\s+/g, ' ').replace(/\|/g, '/').slice(0, 1500)}`);
  }
  return parts.join(' | ');
}

/**
 * VerityTrust Decision Engine (OpenAI-compatible chat completions). Nội dung trả về là JSON:
 * { is_phishing: { probability }, risk_vector: { choice: clean|credential_theft|gambling|scam, confidence }, trust_score: { score 1-4, confidence } }
 */
async function queryVeritytrustEngine(e: SiteEvidence, a: RiskAssessment, cfg: JevConfig): Promise<JevDecisionResult | null> {
  if (!cfg.veritytrustKey) {
    if (!warnedMissingKey) console.warn('[Jev Gateway] JEV_MODE=veritytrust nhưng chưa có VERITYTRUST_ENGINE_KEY - bỏ qua Tầng 4.');
    warnedMissingKey = true;
    return null;
  }
  const t0 = Date.now();
  try {
    const res = await fetch(cfg.veritytrustUrl, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${cfg.veritytrustKey}` },
      body: JSON.stringify({ model: cfg.veritytrustModel, messages: [{ role: 'user', content: buildVeritytrustMetadata(e) }] }),
      signal: AbortSignal.timeout(cfg.timeoutMs),
    });
    if (!res.ok) {
      const body = await res.text().catch(() => '');
      console.warn(`[Jev Gateway] veritytrust trả về lỗi HTTP ${res.status}: ${body.slice(0, 200) || res.statusText}`);
      return null;
    }
    const data: any = await res.json();
    const raw = JSON.parse(data?.choices?.[0]?.message?.content ?? '');
    const pPhish = Number(raw?.is_phishing?.probability);
    const choice = String(raw?.risk_vector?.choice ?? '');
    const choiceConf = Number(raw?.risk_vector?.confidence);
    if (!Number.isFinite(pPhish) || !Number.isFinite(choiceConf)) throw new Error('nội dung trả về sai định dạng');

    // Chỉ tin khi xác suất lừa đảo và loại rủi ro cùng chỉ một hướng: độ tin cậy = giá trị nhỏ hơn
    const harmConf = Math.min(pPhish, choiceConf);
    const isCred = choice === 'credential_theft' && pPhish >= 0.5;
    const isGambling = choice === 'gambling' && pPhish >= 0.5;
    const isScam = choice === 'scam' && pPhish >= 0.5; // shop giả, đầu tư ảo… (engine v3)
    const safeProb = choice === 'clean' ? Math.min(1 - pPhish, choiceConf) : 0;
    const verdict: JevDecisionResult['verdict'] = choice === 'clean' && pPhish < 0.5 ? 'safe' : isCred ? 'phishing' : isGambling ? 'gambling' : isScam ? 'malicious' : 'suspicious';
    const latencyMs = Date.now() - t0;
    console.log(`[Jev Gateway] 🎯 Phân xử (veritytrust, ${cfg.veritytrustModel}${cfg.shadow ? ', chạy ngầm' : ''}) ${latencyMs}ms: ${choice} (phishing ${(pPhish * 100).toFixed(0)}%, loại ${(choiceConf * 100).toFixed(0)}%)`);

    return {
      engine: 'VerityTrust-Engine',
      latencyMs,
      isCredentialHarvesting: isCred,
      isCredentialHarvestingConfidence: isCred ? harmConf : 0,
      isFinancialOrGamblingScam: isGambling || isScam,
      isFinancialOrGamblingScamConfidence: isGambling || isScam ? harmConf : 0,
      // Engine không tách riêng giả danh thương hiệu; chỉ coi là giả danh khi trang có nhắc tới thương hiệu
      isBrandImpersonation: isCred && (e.html?.brandMentions.length ?? 0) > 0,
      isBrandImpersonationConfidence: isCred && (e.html?.brandMentions.length ?? 0) > 0 ? harmConf : 0,
      verdict,
      verdictProbabilities: { safe: safeProb, phishing: isCred ? harmConf : 0, gambling: isGambling ? harmConf : 0, malicious: isScam ? harmConf : 0 },
      shadow: cfg.shadow,
      raw,
    };
  } catch (err: any) {
    console.warn(`[Jev Gateway] Không gọi được veritytrust (${err?.message || err}) sau ${Date.now() - t0}ms. Rơi về chấm điểm bằng chứng nội bộ.`);
    return null;
  }
}

/**
 * Áp dụng kết quả từ Jev/OpenJev vào bảng điểm bằng chứng (RiskAssessment).
 * Tuân thủ nguyên tắc XAI: Mọi phán quyết của Jev đều được chuyển đổi thành
 * các yếu tố rủi ro có giải thích minh bạch (Factor Breakdown).
 */
export function applyJevDecision(a: RiskAssessment, j: JevDecisionResult): RiskAssessment {
  const engineName = j.engine === 'jev-api' ? 'Jev AI (TypeSafe)' : j.engine === 'VerityTrust-Engine' ? 'VerityTrust-Engine' : 'OpenJev Decision Gateway';
  const factors = [...a.factors];
  let score = a.score;
  let cap = a.cap;
  let verdict = a.verdict;

  if (j.isBrandImpersonation && j.isBrandImpersonationConfidence >= 0.80) {
    const pct = Math.round(j.isBrandImpersonationConfidence * 100);
    factors.push({
      id: 'jev_brand_impersonation',
      label: `${engineName}: Xác nhận mạo danh thương hiệu (${pct}%)`,
      detail: `Mô hình ra quyết định xác nhận website này cố tình giả mạo logo, giao diện hoặc tên tuổi của tổ chức/doanh nghiệp hợp pháp khác với độ tin cậy ${pct}%.`,
      delta: -35,
    });
    score = Math.min(score, 15);
    cap = cap !== null ? Math.min(cap, 15) : 15;
    verdict = 'phishing';
  }

  if (j.isCredentialHarvesting && j.isCredentialHarvestingConfidence >= 0.80) {
    const pct = Math.round(j.isCredentialHarvestingConfidence * 100);
    factors.push({
      id: 'jev_credential_harvesting',
      label: `${engineName}: Phát hiện bẫy thu thập OTP/Mật khẩu (${pct}%)`,
      detail: `Mô hình phát hiện biểu mẫu thu thập dữ liệu nhạy cảm có mục đích đánh cắp tài khoản (độ tin cậy ${pct}%).`,
      delta: -30,
    });
    score = Math.min(score, 15);
    cap = cap !== null ? Math.min(cap, 15) : 15;
    verdict = 'phishing';
  }

  if (j.isFinancialOrGamblingScam && j.isFinancialOrGamblingScamConfidence >= 0.80) {
    const pct = Math.round(j.isFinancialOrGamblingScamConfidence * 100);
    factors.push({
      id: 'jev_financial_scam',
      label: `${engineName}: Phát hiện lừa đảo tài chính / cờ bạc (${pct}%)`,
      detail: `Mô hình nhận diện dấu hiệu lừa đảo đa cấp, nhiệm vụ ảo, đầu tư tiền ảo hoặc hoạt động cờ bạc bất hợp pháp (độ tin cậy ${pct}%).`,
      delta: -35,
    });
    score = Math.min(score, 15);
    cap = cap !== null ? Math.min(cap, 15) : 15;
    verdict = j.verdict === 'gambling' ? 'gambling' : 'malicious';
  }

  // Nếu Jev xác nhận an toàn cao trên ca nghi ngờ oan (giải oan cho website hợp pháp mới tạo)
  const safeProb = j.verdictProbabilities['safe'] || 0;
  if (j.verdict === 'safe' && safeProb >= 0.85 && !j.isBrandImpersonation && !j.isCredentialHarvesting && !j.isFinancialOrGamblingScam) {
    factors.push({
      id: 'jev_safe_confirmation',
      label: `${engineName}: Xác nhận trang web hợp pháp/an toàn (${Math.round(safeProb * 100)}%)`,
      detail: `Mô hình kiểm định toàn diện nội dung và cấu trúc, xác nhận website hoạt động bình thường, không chứa mã độc hay bẫy lừa đảo.`,
      delta: +15,
    });
    score = Math.min(95, score + 15);
    if (score >= 75) verdict = 'legit';
  }

  // Tính lại status theo điểm
  const status: RiskAssessment['status'] = score >= 75 ? 'Safe' : score >= 50 ? 'Warning' : 'Dangerous';

  return {
    ...a,
    score: Math.max(0, Math.min(100, Math.round(score))),
    status,
    verdict,
    factors,
    cap,
  };
}
