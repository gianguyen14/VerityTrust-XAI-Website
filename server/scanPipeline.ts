import { analyzeHtml, collectPageEvidence, createEvidence, resolveTargetDns, type SiteEvidence } from './evidence.ts';
import { scoreEvidence, type RiskAssessment } from './riskScoring.ts';
import { isGamblingHost, isTrustedHost } from './domainRules.ts';
import { GRAY_ZONE_MAX, GRAY_ZONE_MIN, applyJevDecision, getJevConfig, queryJevDecision, type JevDecisionResult } from './jevDecision.ts';
import { isHeadlessAvailable, renderPage } from './headless.ts';

// ============================================================================
// ĐƯỜNG ỐNG QUÉT NHIỀU TẦNG (Multi-Tier Scanning Pipeline) với DỪNG SỚM
//
//  Tầng 0  NetSafety & DNS      chặn SSRF, phân giải tên miền        -> dừng nếu không tồn tại / IP nội bộ
//  Tầng 1  Danh tiếng cứng       Tranco, danh sách đen, tên miền cờ bạc (trong bộ nhớ, không tải HTML)
//                                -> dừng "An toàn" nếu chính thống/top 10k, "Nguy hiểm" nếu trong danh sách đen
//  Tầng 2  Bằng chứng & AI cục bộ  HTML tĩnh, TLS, RDAP, 2 mô hình học sâu -> dừng nếu điểm < 45 hoặc >= 75
//  Tầng 3  Headless (khi cần)    trang SPA/HTML rỗng: dựng bằng trình duyệt thật rồi chấm lại ở Tầng 2
//  Tầng 4  Trọng tài VerityTrust-Engine     chỉ cho ca vùng xám 45-74 (khi JEV_MODE bật)
//  Tầng 5  LLM giải thích        không nằm trong đường ống chấm điểm: /api/explain gọi khi người dùng yêu cầu
// ============================================================================

export type TierStatus = 'passed' | 'exit' | 'skipped';

export interface TierTrace {
  tier: number;
  name: string;
  status: TierStatus;
  ms: number;
  note: string;
}

export interface PipelineResult {
  evidence: SiteEvidence;
  assessment: RiskAssessment;
  jevDecision: JevDecisionResult | null;
  tiers: TierTrace[];
  exitTier: number;
  exitReason: string;
  totalMs: number;
  renderedByHeadless: boolean;
}

const TIER_NAMES = [
  'NetSafety & Phân giải DNS',
  'Danh tiếng cứng & Tên miền',
  'Bằng chứng & AI cục bộ',
  'Headless Browser (khi cần)',
  'Trọng tài VerityTrust-Engine (vùng xám)',
] as const;

// Tầng 2 -> Tầng 3: HTML tĩnh gần như rỗng hoặc là khung SPA (nội dung thật do JavaScript vẽ)
function needsHeadless(e: SiteEvidence): boolean {
  if (!e.dns.ip) return false;
  if (!e.html) return e.http.status !== null && e.http.status < 400;
  return e.html.isSpa || e.html.textLength < 300 || e.html.botChallenge;
}

export async function runScanPipeline(targetUrl: string): Promise<PipelineResult> {
  const started = Date.now();
  const tiers: TierTrace[] = [];
  let t = Date.now();
  const mark = (tier: number, status: TierStatus, note: string) => {
    tiers.push({ tier, name: TIER_NAMES[tier], status, ms: Date.now() - t, note });
    t = Date.now();
  };
  const skipFrom = (fromTier: number, reason: string) => {
    for (let k = fromTier; k < TIER_NAMES.length; k++) tiers.push({ tier: k, name: TIER_NAMES[k], status: 'skipped', ms: 0, note: reason });
  };
  const finish = (evidence: SiteEvidence, assessment: RiskAssessment, exitTier: number, exitReason: string, extra: Partial<PipelineResult> = {}): PipelineResult => ({
    evidence, assessment, jevDecision: null, tiers, exitTier, exitReason, totalMs: Date.now() - started, renderedByHeadless: false, ...extra,
  });

  // ---------------------------------------------------------------- Tầng 0
  const evidence = createEvidence(targetUrl); // tín hiệu trong bộ nhớ, dùng ở Tầng 1
  const reachable = await resolveTargetDns(evidence);
  if (!reachable) {
    const assessment = scoreEvidence(evidence);
    const reason = evidence.dns.privateResolution ? 'Tên miền trỏ về IP nội bộ - không truy cập tiếp' : 'Tên miền không tồn tại (NXDOMAIN)';
    mark(0, 'exit', reason);
    skipFrom(1, 'Dừng sớm ở Tầng 0');
    return finish(evidence, assessment, 0, reason);
  }
  mark(0, 'passed', `Phân giải ${evidence.dns.ip} (IP công khai)`);

  // ---------------------------------------------------------------- Tầng 1
  const d = evidence.domain;
  const rank = evidence.popularityRank;
  // Top 10k: cả subdomain (mail.google.com) cũng được tính; trừ subdomain do người dùng tạo trên nền tảng hosting miễn phí
  const topTier = rank !== null && rank <= 10_000 && !d.isFreeHosting;
  const trusted = isTrustedHost(d.host) && !d.isFreeHosting;
  const blacklisted = evidence.threatListings.length > 0;
  const gamblingDomain = !trusted && isGamblingHost(d.host);

  if (blacklisted || gamblingDomain) {
    const assessment = scoreEvidence(evidence);
    const reason = blacklisted ? `Có trong danh sách đen: ${evidence.threatListings.join('; ')}` : 'Tên miền cờ bạc / cá cược rõ ràng';
    mark(1, 'exit', reason);
    skipFrom(2, 'Dừng sớm ở Tầng 1 - không cần tải trang');
    return finish(evidence, assessment, 1, reason);
  }
  if (trusted || topTier) {
    const assessment = scoreEvidence(evidence);
    const reason = trusted ? 'Tên miền chính thống đã xác thực' : `Website phổ biến (Tranco #${rank!.toLocaleString()})`;
    mark(1, 'exit', reason);
    skipFrom(2, 'Dừng sớm ở Tầng 1 - bỏ qua tải HTML');
    return finish(evidence, assessment, 1, reason);
  }
  mark(1, 'passed', rank ? `Tranco #${rank.toLocaleString()}, không trong danh sách đen` : 'Ngoài top 200.000, không trong danh sách đen');

  // ---------------------------------------------------------------- Tầng 2
  await collectPageEvidence(evidence);
  let assessment = scoreEvidence(evidence);
  mark(2, 'passed', `Điểm bằng chứng ${assessment.score}/100${evidence.html ? `, ${evidence.html.textLength} ký tự nội dung` : ', không tải được HTML'}`);

  // ---------------------------------------------------------------- Tầng 3 (chỉ khi HTML rỗng/SPA và chưa dứt khoát nguy hiểm)
  let renderedByHeadless = false;
  // Chỉ dựng trang khi bằng chứng còn chưa dứt khoát (vùng 45-74): site uy tín rõ ràng hoặc đã nguy hiểm rõ ràng thì bỏ qua
  if (needsHeadless(evidence) && assessment.score >= GRAY_ZONE_MIN && assessment.score <= GRAY_ZONE_MAX) {
    if (!isHeadlessAvailable()) {
      mark(3, 'skipped', 'Trang SPA/HTML rỗng nhưng chưa bật trình duyệt headless (HEADLESS_RENDER / CHROME_PATH)');
    } else {
      const rendered = await renderPage(evidence.finalUrl || evidence.url);
      const renderedHtml = rendered ? analyzeHtml(rendered.html, rendered.finalUrl, (evidence.finalDomain || d).ownerDomain) : null;
      if (renderedHtml && renderedHtml.textLength > (evidence.html?.textLength ?? 0)) {
        const before = assessment.score;
        evidence.html = renderedHtml;
        renderedByHeadless = true;
        assessment = scoreEvidence(evidence);
        mark(3, 'passed', `Dựng DOM thật: ${renderedHtml.textLength} ký tự (chặn ${rendered!.blockedRequests} request), chấm lại ở Tầng 2: ${before} -> ${assessment.score}`);
      } else {
        mark(3, 'passed', rendered ? 'Đã dựng nhưng không có thêm nội dung' : 'Không dựng được trang');
      }
    }
  } else {
    mark(3, 'skipped', needsHeadless(evidence) ? `Trang SPA/HTML rỗng nhưng điểm ${assessment.score} đã dứt khoát, không cần dựng trang` : 'HTML tĩnh đã đủ nội dung');
  }

  // ---------------------------------------------------------------- Tầng 4 (vùng xám)
  const inGrayZone = assessment.score >= GRAY_ZONE_MIN && assessment.score <= GRAY_ZONE_MAX;
  const jevCfg = getJevConfig();
  // Chạy ngầm có thể đo trên mọi web (JEV_GRAY_ZONE_ONLY=false) vì không đổi điểm
  if (jevCfg.shadow && jevCfg.mode !== 'off' && (inGrayZone || !jevCfg.grayZoneOnly)) {
    const jevDecision = await queryJevDecision(evidence, assessment, { ignoreGrayZone: true });
    mark(4, 'passed', jevDecision
      ? `Trọng tài ${jevDecision.engine} chạy ngầm: ${jevDecision.verdict} (không đổi điểm ${assessment.score})`
      : 'Trọng tài chạy ngầm không phản hồi');
    return finish(evidence, assessment, renderedByHeadless ? 3 : 2, `Kết luận theo bằng chứng (${assessment.score}/100), trọng tài chạy ngầm`, { jevDecision, renderedByHeadless });
  }
  if (!inGrayZone) {
    tiers.push({ tier: 4, name: TIER_NAMES[4], status: 'skipped', ms: 0, note: `Điểm ${assessment.score} đã dứt khoát (ngoài vùng xám ${GRAY_ZONE_MIN}-${GRAY_ZONE_MAX})` });
    return finish(evidence, assessment, renderedByHeadless ? 3 : 2, `Kết luận theo bằng chứng kỹ thuật (${assessment.score}/100)`, { renderedByHeadless });
  }
  if (jevCfg.mode === 'off') {
    tiers.push({ tier: 4, name: TIER_NAMES[4], status: 'skipped', ms: 0, note: 'Vùng xám nhưng chưa bật trọng tài (JEV_MODE=off)' });
    return finish(evidence, assessment, renderedByHeadless ? 3 : 2, `Vùng xám, kết luận theo bằng chứng (${assessment.score}/100)`, { renderedByHeadless });
  }
  const jevDecision = await queryJevDecision(evidence, assessment);
  if (jevDecision) {
    const before = assessment.score;
    assessment = applyJevDecision(assessment, jevDecision);
    mark(4, 'passed', `Trọng tài ${jevDecision.engine}: ${before} -> ${assessment.score}`);
  } else {
    mark(4, 'passed', 'Trọng tài không phản hồi, giữ kết luận theo bằng chứng');
  }
  return finish(evidence, assessment, 4, `Vùng xám được trọng tài phân xử (${assessment.score}/100)`, { jevDecision, renderedByHeadless });
}
