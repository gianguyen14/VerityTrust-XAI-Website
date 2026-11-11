import {
  HIGH_RISK_TLDS,
  TARGETED_BRAND_NAMES,
  PHISHING_HOST_KEYWORDS,
  analyzeLabelShape,
  findImpersonatedBrand,
  findTyposquatTarget,
  isGamblingTarget,
  isFakeShopTemplate,
  isOpaqueShop,
  VIETNAMESE_BRANDS,
  detectProhibitedGoods,
  isTrustedHost,
} from './domainRules.ts';
import type { SiteEvidence } from './evidence.ts';
import { getPopularityRank } from './reputation.ts';
import { predictContentRisk } from './contentModel.ts';

// Tổ chức trên GitHub/GitLab Pages trùng tên một website top 10.000 (mozilla.github.io <-> mozilla.org) là chính chủ
function isPopularOrgAccount(label: string): boolean {
  return ['com', 'org', 'io', 'dev', 'net'].some(tld => {
    const rank = getPopularityRank(`${label}.${tld}`);
    return rank !== null && rank <= 10_000;
  });
}

// ============================================================================
// CHẤM ĐIỂM RỦI RO DỰA TRÊN BẰNG CHỨNG (Explainable, deterministic)
// Mỗi yếu tố cộng/trừ điểm kèm lời giải thích; các dấu hiệu nghiêm trọng đặt "trần" điểm (cap).
// Thang điểm: >= 75 Safe, 50-74 Warning, < 50 Dangerous.
// ============================================================================

export type RiskVerdict = 'trusted' | 'legit' | 'unknown' | 'suspicious' | 'phishing' | 'gambling' | 'malicious' | 'unreachable';

export interface RiskFactor {
  id: string;
  label: string;
  detail: string;
  delta: number;
}

export interface RiskAssessment {
  score: number;
  status: 'Safe' | 'Warning' | 'Dangerous';
  verdict: RiskVerdict;
  factors: RiskFactor[];
  cap: number | null;
  floor: number | null;
  /** 0-1: lượng bằng chứng thu thập được (DNS, TLS, nội dung, tuổi tên miền, độ phổ biến) */
  confidence: number;
  isGambling: boolean;
  isTrusted: boolean;
}

const BASE_SCORE = 70;

// Ngưỡng xác suất của mô hình học sâu (chọn theo tỉ lệ báo nhầm trên tập validation, xem scripts/train-url-model.ts)
const ML_STRONG = 0.95;
const ML_MODERATE = 0.85;
// Mô hình nội dung (huấn luyện bằng label smoothing nên đầu ra tối đa ~0,95); ngưỡng chọn trên nửa "tune" của tập trang thật.
// Trọng số nhỏ (-10) vì A/B cho thấy mô hình đôi khi trừ điểm trang bán lẻ Việt Nam hợp pháp (ngôn ngữ khuyến mãi).
const CONTENT_ML_THRESHOLD = 0.9;

export function statusFromScore(score: number): RiskAssessment['status'] {
  if (score >= 75) return 'Safe';
  if (score >= 50) return 'Warning';
  return 'Dangerous';
}

export function scoreEvidence(e: SiteEvidence): RiskAssessment {
  const factors: RiskFactor[] = [];
  const caps: Array<{ value: number; verdict: RiskVerdict }> = [];
  let floor: number | null = null;
  const add = (id: string, delta: number, label: string, detail: string) => factors.push({ id, delta, label, detail });
  const capAt = (value: number, verdict: RiskVerdict) => caps.push({ value, verdict });

  const d = e.domain;
  const effective = e.finalDomain || d;
  const html = e.html;
  // Độ phổ biến thuộc về tên miền gốc. Subdomain (không phải www) của tên miền tầm trung có thể là trang
  // do người dùng tự tạo trên một nền tảng (vd user123.some-platform.site) -> không thừa hưởng trọn uy tín.
  const isSubdomainHost = d.host !== d.ownerDomain && d.host !== `www.${d.ownerDomain}`;
  const rank = e.popularityRank;
  const inheritsPopularity = rank !== null && (!isSubdomainHost || rank <= 10_000);
  const isPopular = rank !== null && rank <= 100_000 && inheritsPopularity;
  const verifiedAccount = d.isVerifiedBrandAccount || (d.onVerifiedAccountPlatform && isPopularOrgAccount(d.ownerLabel));
  const isTrusted = (isTrustedHost(d.host) && !d.isFreeHosting) || verifiedAccount;
  const ageDays = e.domainAge.ageDays;
  const isEstablished = isPopular || isTrusted || (ageDays !== null && ageDays >= 3 * 365 && !isSubdomainHost);
  // Kiểm tra nội dung (form đăng nhập, giả danh thương hiệu...) áp dụng cho mọi site không phổ biến/chính thống,
  // kể cả tên miền lâu năm - website cũ bị chiếm quyền để cài trang phishing là hình thức rất phổ biến
  const contentExempt = isPopular || isTrusted;
  const pageText = html ? `${html.title} ${html.description} ${html.text}` : '';

  // ---------------------------------------------------------------- Danh sách đen & cờ bạc
  if (e.threatListings.length) {
    add('threat_list', -60, 'Có trong danh sách đen lừa đảo/mã độc', e.threatListings.join('; '));
    capAt(8, 'malicious');
  }

  const gambling = !isTrusted && (
    isGamblingTarget(e.url, d.host, pageText) ||
    (!!e.finalDomain && isGamblingTarget(e.finalUrl || e.url, e.finalDomain.host, pageText))
  );
  if (gambling) {
    add('gambling', -60, 'Hoạt động cờ bạc / cá cược trực tuyến', 'Tên miền, đường dẫn hoặc nội dung trang có dấu hiệu cờ bạc - bị cấm theo Điều 321, 322 BLHS và Điều 8 Luật An ninh mạng.');
    capAt(12, 'gambling');
  }

  // ---------------------------------------------------------------- DNS
  if (e.dns.privateResolution) {
    add('private_dns', -55, 'Tên miền trỏ về địa chỉ mạng nội bộ', 'Tên miền công khai nhưng phân giải ra IP nội bộ/không công khai (dấu hiệu sinkhole hoặc tấn công DNS rebinding).');
    capAt(15, 'malicious');
  } else if (e.dns.nxdomain) {
    add('nxdomain', -50, 'Tên miền không tồn tại', 'Không phân giải được tên miền (NXDOMAIN): trang đã bị gỡ, ngừng hoạt động hoặc chưa từng tồn tại.');
    capAt(20, 'unreachable');
  }

  // ---------------------------------------------------------------- Danh tiếng
  if (isTrusted) {
    if (verifiedAccount) {
      add('trusted', 15, 'Trang chính chủ của tổ chức đã xác thực', `"${d.ownerDomain}" là trang của tài khoản tổ chức "${d.ownerLabel}" trên ${d.publicSuffix}.`);
      floor = 80;
    } else {
      add('trusted', 20, 'Tên miền chính thống đã được xác thực', `"${d.icannDomain}" thuộc danh mục tổ chức/doanh nghiệp/cơ quan nhà nước uy tín.`);
      floor = 90;
    }
  }
  if (rank !== null) {
    const fullDelta = rank <= 1_000 ? 25 : rank <= 10_000 ? 20 : rank <= 100_000 ? 14 : 8;
    const delta = inheritsPopularity ? fullDelta : Math.round(fullDelta / 2);
    add('popularity', delta, inheritsPopularity ? 'Tên miền phổ biến toàn cầu' : 'Tên miền gốc phổ biến (trang là subdomain)',
      `"${d.ownerDomain}" xếp hạng #${rank.toLocaleString()} trong danh sách Tranco${inheritsPopularity ? '' : `; "${d.host}" là subdomain nên chỉ được tính một phần uy tín`}.`);
  }

  if (ageDays !== null) {
    if (ageDays < 30) add('domain_age', -35, 'Tên miền vừa mới đăng ký', `Đăng ký cách đây ${ageDays} ngày - phần lớn trang lừa đảo dùng tên miền mới tạo.`);
    else if (ageDays < 180) add('domain_age', -22, 'Tên miền còn rất mới', `Đăng ký cách đây ${ageDays} ngày (dưới 6 tháng).`);
    else if (ageDays < 365) add('domain_age', -10, 'Tên miền mới hoạt động dưới 1 năm', `Đăng ký cách đây ${ageDays} ngày.`);
    else if (ageDays >= 10 * 365) add('domain_age', 12, 'Tên miền hoạt động lâu năm', `Đăng ký từ ${e.domainAge.registeredAt?.slice(0, 10)} (hơn 10 năm).`);
    else if (ageDays >= 3 * 365) add('domain_age', 8, 'Tên miền hoạt động ổn định', `Đăng ký từ ${e.domainAge.registeredAt?.slice(0, 10)}.`);
  }

  // ---------------------------------------------------------------- Cấu trúc tên miền
  const domainsToCheck = e.finalDomain && e.finalDomain.ownerDomain !== d.ownerDomain ? [d, e.finalDomain] : [d];
  for (const dom of domainsToCheck) {
    const where = dom === d ? '' : ' (trang đích sau chuyển hướng)';
    const domTrusted = (isTrustedHost(dom.host) && !dom.isFreeHosting) || dom.isVerifiedBrandAccount ||
      (dom.onVerifiedAccountPlatform && isPopularOrgAccount(dom.ownerLabel));
    const domRank = dom === d ? rank : e.finalPopularityRank;
    const domPopular = domRank !== null && domRank <= 100_000;
    if (domTrusted || domPopular) continue;

    if (dom.isIp) {
      add('ip_host', -25, `Truy cập trực tiếp bằng địa chỉ IP${where}`, 'Website hợp pháp hầu như luôn dùng tên miền; trang dùng IP trần thường là máy chủ tạm của kẻ gian.');
    }
    if (dom.isFreeHosting) {
      add('free_hosting', -20, `Chạy trên nền tảng hosting miễn phí${where}`, `"${dom.ownerDomain}" là subdomain ẩn danh trên ${dom.publicSuffix || 'nền tảng miễn phí'}, ai cũng có thể tạo trong vài giây.`);
    }
    const brand = findImpersonatedBrand(dom.host);
    if (brand) {
      add('brand_in_domain', -40, `Tên miền chứa thương hiệu "${brand}" nhưng không phải tên miền chính thức${where}`, `"${dom.host}" mượn tên thương hiệu để tạo lòng tin - kỹ thuật mạo danh phổ biến nhất.`);
    } else {
      const typo = findTyposquatTarget(dom.ownerLabel);
      if (typo) {
        add('typosquat', -40, `Tên miền nhái thương hiệu "${typo}"${where}`, `"${dom.ownerLabel}" gần giống "${typo}" (đổi/thêm/bớt ký tự hoặc dùng ký tự trông giống nhau).`);
      }
    }
    // Mô hình học sâu trên chuỗi tên miền (huấn luyện từ ~380 nghìn tên miền phishing thật)
    const mlProbability = dom === d ? e.urlModelProbability : e.finalUrlModelProbability;
    if (mlProbability !== null) {
      const pct = Math.round(mlProbability * 100);
      const delta = mlProbability >= ML_STRONG ? -20 : mlProbability >= ML_MODERATE ? -12 : 0;
      if (delta) {
        add('ml_domain', delta, `Mô hình học sâu nhận diện tên miền giống tên miền lừa đảo${where}`, `Mạng nơ-ron phân tích cấu trúc ký tự của "${dom.ownerDomain}" cho xác suất lừa đảo ${pct}% (học từ hàng trăm nghìn tên miền phishing đã xác minh).`);
      }
    }
    const shape = analyzeLabelShape(dom.ownerLabel);
    if (shape.allDigits && shape.length >= 5) {
      add('numeric_domain', -25, `Tên miền chỉ gồm chữ số${where}`, `"${dom.ownerLabel}" là chuỗi số vô nghĩa, đặc trưng của tên miền dùng một lần.`);
    } else if (shape.looksRandom) {
      add('random_label', -15, `Tên miền có cấu trúc ngẫu nhiên${where}`, `"${dom.ownerLabel}" chứa nhiều gạch nối/chữ số đan xen như được sinh tự động.`);
    }
    if (dom.isIdn) {
      add('idn', -15, `Tên miền quốc tế hoá (punycode)${where}`, 'Có thể dùng ký tự Unicode trông giống chữ Latin để giả mạo tên miền thật (homograph attack).');
    }
    if (HIGH_RISK_TLDS.some(tld => dom.host.endsWith(tld))) {
      add('risky_tld', -12, `Đuôi tên miền rủi ro cao${where}`, `Đuôi ".${dom.host.split('.').pop()}" nằm trong nhóm bị lạm dụng nhiều nhất cho lừa đảo (thống kê Spamhaus/Interisle).`);
    }
    const keyword = PHISHING_HOST_KEYWORDS.find(k => dom.host.includes(k));
    if (keyword) {
      add('phishing_keyword', -20, `Tên miền chứa từ khoá lừa đảo "${keyword}"${where}`, 'Từ khoá thường dùng để dụ người dùng xác thực tài khoản/nhận thưởng.');
    }
  }

  // ---------------------------------------------------------------- Cấu trúc URL (chỉ xét với host chưa có uy tín)
  if (!isEstablished) {
    let urlObjects: URL[] = [];
    try {
      urlObjects = [new URL(e.url), ...(e.finalUrl ? [new URL(e.finalUrl)] : [])];
    } catch {
      urlObjects = [];
    }
    if (urlObjects.some(u => u.port && u.port !== '80' && u.port !== '443')) {
      add('odd_port', -10, 'Dùng cổng mạng không tiêu chuẩn', `URL chạy trên cổng :${urlObjects.find(u => u.port)?.port} - website hợp pháp hầu như chỉ dùng cổng 80/443.`);
    }
    const paths = urlObjects.map(u => {
      try {
        return decodeURIComponent(u.pathname + u.search).toLowerCase();
      } catch {
        return (u.pathname + u.search).toLowerCase();
      }
    }).join(' ');
    const pathBrand = TARGETED_BRAND_NAMES.find(b => b.length >= 5 && new RegExp(`(?:^|[^a-z])${b}(?:[^a-z]|$)`).test(paths) && !d.host.includes(b));
    if (pathBrand) {
      add('brand_in_path', -20, `Đường dẫn chứa tên thương hiệu "${pathBrand}"`, 'Trang trên tên miền không liên quan nhưng mượn tên thương hiệu trong đường dẫn để tạo lòng tin.');
    }
    if (/(?:^|[/_.-])(?:log-?in|sign-?in|signon|verify|verification|webscr|auth|account|secure|update|unlock|wallet|xac-?thuc|dang-?nhap)(?:[/_.?=-]|$)/.test(paths)) {
      add('login_path', -8, 'Đường dẫn dạng trang đăng nhập/xác minh', 'URL trỏ tới trang đăng nhập/xác minh trên tên miền chưa có uy tín.');
    }
    const subLabels = d.host.slice(0, Math.max(0, d.host.length - d.ownerDomain.length)).split('.').filter(l => l && l !== 'www');
    if (subLabels.some(l => analyzeLabelShape(l).looksRandom)) {
      add('random_subdomain', -10, 'Subdomain có cấu trúc ngẫu nhiên', `"${subLabels.join('.')}" trông như được sinh tự động cho từng chiến dịch.`);
    }
  }

  const finalPopular = e.finalPopularityRank !== null && e.finalPopularityRank <= 100_000;
  if (e.finalDomain && e.finalDomain.ownerDomain !== d.ownerDomain && !isTrusted && !isPopular && !finalPopular) {
    add('cross_redirect', -8, 'Chuyển hướng sang tên miền khác', `${d.host} → ${e.finalDomain.host}`);
  }

  // ---------------------------------------------------------------- TLS / HTTP
  if (!e.dns.nxdomain && !e.dns.privateResolution) {
    if (e.tls?.ok && e.tls.authorized) {
      add('tls_valid', 4, 'Chứng chỉ TLS hợp lệ', `${e.tls.protocol || 'TLS'} - cấp bởi ${e.tls.issuer || 'CA tin cậy'}${e.tls.daysRemaining !== null ? `, còn hạn ${e.tls.daysRemaining} ngày` : ''}.`);
      if (e.tls.certAgeDays !== null && e.tls.certAgeDays <= 7 && !isEstablished) {
        add('fresh_cert', -6, 'Chứng chỉ TLS vừa được cấp', `Chứng chỉ được cấp cách đây ${e.tls.certAgeDays} ngày cho một tên miền chưa có lịch sử.`);
      }
    } else if (e.tls?.ok && !e.tls.authorized) {
      // Tên miền lâu năm quên gia hạn chứng chỉ là lỗi vận hành, nhẹ hơn chứng chỉ tự ký/sai tên miền trên host lạ
      const expiredOnly = /EXPIRED/i.test(e.tls.authorizationError || '');
      add('tls_invalid', expiredOnly && isEstablished ? -10 : -20, 'Chứng chỉ TLS không hợp lệ', e.tls.authorizationError || 'Chứng chỉ tự ký, hết hạn hoặc không khớp tên miền.');
    } else if (!e.http.usedHttps && e.http.status !== null) {
      add('no_https', -12, 'Không mã hoá HTTPS', 'Trang chỉ phục vụ qua HTTP: dữ liệu nhập vào có thể bị nghe lén.');
    }
    if (e.http.hsts) add('hsts', 2, 'Bật HSTS', 'Trình duyệt luôn bắt buộc kết nối HTTPS tới trang này.');
    if (e.http.fetchError && !html) {
      add('unreachable', isEstablished ? 0 : -5, 'Không tải được nội dung trang', e.http.fetchError.slice(0, 160));
    }
  }

  // ---------------------------------------------------------------- Nội dung trang
  if (html) {
    const isAnonymousHost = !contentExempt;
    if (html.botChallenge && isAnonymousHost) {
      add('bot_challenge', -12, 'Nội dung bị che sau thử thách bot (Cloudflare/DDoS)', 'Trang chặn bot tự động, chưa thể kiểm chứng nội dung thực tế bên trong.');
    }
    // Shop/web dịch vụ nhỏ ở Việt Nam hay nhận đơn qua Telegram bot; trang phishing thì ngắn, gần như không có liên kết
    const credentialInputs = html.hasPasswordField || html.sensitiveFields.length > 0;
    const telegramOrderForm = !credentialInputs && html.textLength >= 3000 && html.linkCount >= 30;
    if (html.telegramExfiltration && telegramOrderForm) {
      add('telegram_exfil', -15, 'Biểu mẫu gửi dữ liệu qua Telegram Bot', 'Mã trang gọi api.telegram.org/bot... Trang không có ô mật khẩu hay thông tin nhạy cảm, có thể chỉ là form nhận đơn, nhưng dữ liệu bạn nhập sẽ đi thẳng tới một tài khoản Telegram.');
    } else if (html.telegramExfiltration) {
      add('telegram_exfil', -45, 'Gửi dữ liệu người dùng qua Telegram Bot', 'Mã trang gọi api.telegram.org/bot... - kỹ thuật đặc trưng của bộ công cụ phishing để chuyển mật khẩu/OTP cho kẻ gian.');
      capAt(15, 'phishing');
    }
    if (html.externalFormAction && isAnonymousHost) {
      add('external_form', -20, 'Biểu mẫu gửi dữ liệu sang tên miền khác', `Thông tin nhập vào được gửi tới "${html.externalFormAction}".`);
    }
    if (html.sensitiveFields.length && isAnonymousHost) {
      add('sensitive_fields', -25, 'Yêu cầu thông tin cực kỳ nhạy cảm', `Trang có ô nhập: ${html.sensitiveFields.join(', ')}.`);
    }
    if (html.hasPasswordField && isAnonymousHost) {
      add('password_form', -12, 'Có ô nhập mật khẩu trên tên miền chưa xác minh', 'Trang đăng nhập trên tên miền không phổ biến và chưa được xác minh là dấu hiệu thu thập tài khoản.');
    }
    // Site lâu năm (không phổ biến): chỉ xét thương hiệu xuất hiện ở tiêu đề/mô tả, tránh báo nhầm shop ghi "chuyển khoản Vietcombank"
    const brandSource = isEstablished ? `${html.title} ${html.description}`.toLowerCase() : null;
    // Web TMĐT đã thông báo Bộ Công Thương có tài khoản khách và hay nhắc thương hiệu quốc tế đang bán (Google Pixel)
    // hoặc nút đăng nhập Google. Trang giả ngân hàng/sàn Việt có thể chép cả huy hiệu, nên thương hiệu Việt vẫn bị xét.
    const registeredShop = html.moitBadge && !html.sensitiveFields.length;
    const impersonated = html.brandMentions
      .filter(b => !d.host.includes(b) && !(e.finalDomain?.host || '').includes(b))
      .filter(b => brandSource === null || brandSource.includes(b))
      .filter(b => !registeredShop || VIETNAMESE_BRANDS.includes(b));
    // Thương hiệu ở tiêu đề/mô tả + lời mời đăng nhập/xác minh là đủ; nếu thương hiệu chỉ xuất hiện trong thân trang
    // (trang SaaS/báo chí nhắc tới đối tác kèm nút "Đăng nhập") thì phải có ô mật khẩu hoặc ô thông tin nhạy cảm thật
    const headline = `${html.title} ${html.description}`.toLowerCase();
    const brandInHeadline = impersonated.some(b => headline.includes(b));
    if (impersonated.length && isAnonymousHost && (credentialInputs || (brandInHeadline && html.credentialPrompt))) {
      add('brand_impersonation', -35, `Giả danh thương hiệu ${impersonated.slice(0, 3).join(', ')}`, 'Trang nhắc tới thương hiệu lớn và yêu cầu đăng nhập/xác minh, nhưng không chạy trên tên miền chính thức của thương hiệu đó.');
      if (html.hasPasswordField || html.sensitiveFields.length) capAt(15, 'phishing');
    }
    if (html.faviconBrand && isAnonymousHost) {
      add('favicon_impersonation', -35, `Biểu tượng (Favicon) giả mạo thương hiệu "${html.faviconBrand}"`, `Trang sử dụng favicon của "${html.faviconBrand}" trên tên miền không thuộc quyền sở hữu của thương hiệu này.`);
      capAt(15, 'phishing');
    }
    if (html.imageDominantForm && isAnonymousHost) {
      add('image_phishing', -25, 'Giao diện dạng hình ảnh kết hợp ô nhập liệu', 'Trang dùng hình ảnh thay vì văn bản HTML kèm ô nhập dữ liệu - thủ thuật né tránh bộ quét an ninh văn bản.');
      if (html.hasPasswordField || html.sensitiveFields.length) capAt(20, 'phishing');
    }
    if (html.isSpa && html.telegramExfiltration && isAnonymousHost) {
      add('spa_telegram_exfil', -45, 'Ứng dụng SPA âm thầm gửi dữ liệu qua Telegram/Discord', 'Trang SPA ẩn danh gửi thông tin người dùng trực tiếp tới máy chủ Telegram bot hoặc webhook.');
      capAt(15, 'phishing');
    }
    const totalContentLen = html.textLength + (html.description?.length || 0) + (html.title?.length || 0);
    if (isAnonymousHost && !html.botChallenge && totalContentLen >= 30) {
      const contentRisk = predictContentRisk(html);
      if (contentRisk !== null) {
        const pct = Math.round(contentRisk * 100);
        if (contentRisk >= 0.92) {
          add('ml_content', -25, 'Mô hình học sâu nhận diện nội dung lừa đảo / cờ bạc rất cao', `Mạng nơ-ron đọc tiêu đề, mô tả và cấu trúc trang cho xác suất rủi ro ${pct}%.`);
          if (!html.moitBadge && !html.taxId) capAt(35, 'suspicious');
        } else if (contentRisk >= CONTENT_ML_THRESHOLD) {
          add('ml_content', -15, 'Mô hình học sâu nhận diện nội dung giống kịch bản lừa đảo', `Mạng nơ-ron đọc tiêu đề, mô tả và cấu trúc trang cho xác suất rủi ro ${pct}%.`);
        } else if (contentRisk >= 0.82) {
          add('ml_content', -8, 'Mô hình học sâu cảnh báo nội dung có yếu tố rủi ro', `Mạng nơ-ron đánh giá xác suất rủi ro ${pct}%.`);
        }
      }
    }
    if (isAnonymousHost) {
      const credential = html.hasPasswordField || html.sensitiveFields.length > 0;
      const themes = new Set(html.scamThemes);
      if (themes.has('bank_login') && credential) {
        add('bank_login', -35, 'Trang đăng nhập ngân hàng trên tên miền không phải ngân hàng', `Nội dung trang là cổng ngân hàng trực tuyến (tiêu đề "${html.title.slice(0, 60)}") và yêu cầu mật khẩu/thông tin nhạy cảm, nhưng "${d.host}" không phải tên miền ngân hàng chính thức.`);
        capAt(15, 'phishing');
      }
      if (themes.has('wallet_brand')) {
        add('wallet_brand', -30, 'Mạo danh ví tiền mã hoá', 'Trang dùng tên ví crypto nổi tiếng (Atomic, Exodus, MetaMask, Trust Wallet, TokenPocket...) trên tên miền không chính thức - kiểu lừa đảo đánh cắp cụm từ khôi phục/phát tán app giả.');
      }
      if (themes.has('meta_support')) {
        add('meta_support', -30, 'Giả mạo trung tâm hỗ trợ Meta/Facebook', 'Nội dung "Business Help Center/tài khoản bị hạn chế/vi phạm bản quyền" trên tên miền không thuộc Meta - chiến dịch chiếm đoạt tài khoản quảng cáo rất phổ biến.');
      }
      if (themes.has('fake_download')) {
        add('fake_download', -15, 'Trang tải ứng dụng "chính thức" trên tên miền không chính thức', 'Kẻ gian thường dựng trang tải app giả (ví crypto, ngân hàng) để phát tán ứng dụng chứa mã độc.');
      }
      const prohibitedGoods = detectProhibitedGoods(html.title, html.text);
      if (prohibitedGoods) {
        add('prohibited_goods', -40, `Rao bán hàng cấm: ${prohibitedGoods}`, 'Trang trực tiếp chào bán mặt hàng bị cấm mua bán trên mạng; đây cũng là vỏ bọc lừa đảo chiếm đoạt tiền đặt cọc phổ biến.');
        capAt(25, 'malicious');
      }
      // Shop thật cũng có thể trùng khuôn này, nên chỉ áp dụng khi tên miền mới hoặc không rõ tuổi
      const recentlyRegistered = ageDays === null || ageDays < 2 * 365;
      if (recentlyRegistered && isFakeShopTemplate(html.title, html.text, d.ownerDomain)) {
        add('fake_shop_template', -40, 'Trang khớp khuôn shop giả hàng loạt', 'Tiêu đề chỉ là tên miền, kèm câu miễn phí vận chuyển theo ngưỡng đơn hàng: khuôn được dùng lặp lại trên rất nhiều tên miền shop lừa đảo.');
        capAt(30, 'malicious');
      }
      // Đã đọc trang liên hệ/pháp lý: dùng kết quả đó thay cho luật chỉ nhìn trang chủ
      const shopPages = e.shopPages;
      if (shopPages && shopPages.checked > 0 && recentlyRegistered && !isEstablished) {
        if (!shopPages.contact) {
          add('shop_no_contact', -25, 'Shop không công bố điện thoại hay email', 'Đã đọc trang liên hệ/giới thiệu: chỉ có form gửi tin nhắn, không có số điện thoại, email hay thông tin doanh nghiệp. Shop lừa đảo thường giấu danh tính theo cách này.');
          capAt(40, 'suspicious');
        }
      } else if (ageDays !== null && ageDays < 2 * 365 && isOpaqueShop(html, d.ownerDomain)) {
        add('opaque_shop', -25, 'Shop mới, trang chủ không có thông tin liên hệ', 'Tên miền chưa đầy 2 năm tuổi, trang chào bán nhưng không công bố điện thoại, email hay thông tin doanh nghiệp; đây là đặc điểm phổ biến của shop lừa đảo.');
        capAt(40, 'suspicious');
      }
      // Luật Đức bắt buộc mọi shop có Impressum, kể cả shop lâu năm; tên miền cũ bị mua lại làm shop giả vẫn thiếu trang này
      if (html.germanShop && !html.legalPageLink && !html.legalId && !shopPages?.legalId) {
        add('shop_no_imprint', -20, 'Shop tiếng Đức không có Impressum', 'Luật Đức bắt buộc shop trực tuyến công bố Impressum (tên công ty, địa chỉ, số đăng ký). Trang này không có Impressum hay số đăng ký doanh nghiệp nào.');
        capAt(45, 'suspicious');
      }
      if (themes.has('prize_scam')) {
        add('prize_scam', -20, 'Thông báo trúng thưởng/nhận quà', 'Nội dung dụ dỗ nhận thưởng - kịch bản lừa đảo kinh điển.');
      }
      const hasUnlicensedFinancial = /(?:^|[^\p{L}\p{N}])(?:đổi thẻ cào|doi the cao|gạch thẻ|rút tiền mặt|chiết khấu đổi thẻ|đổi thẻ game)(?=$|[^\p{L}\p{N}])/iu.test(pageText);
      if (hasUnlicensedFinancial && isAnonymousHost && !html.moitBadge && !html.taxId) {
        add('unlicensed_financial', -20, 'Dịch vụ đổi thẻ cào / tài chính tự phát chưa được cấp phép', 'Website cung cấp dịch vụ đổi thẻ cào ra tiền mặt nhưng không có giấy phép trung gian thanh toán hoặc đăng ký Bộ Công Thương.');
        capAt(55, 'suspicious');
      }
    }
    if (html.externalRedirect && isAnonymousHost) {
      add('js_redirect', -10, 'Tự động chuyển hướng bằng mã trang', `Trang chuyển người dùng sang "${html.externalRedirect}".`);
    }
    if (html.obfuscationSignals >= 2 || (html.obfuscationSignals >= 1 && isAnonymousHost && (html.hasPasswordField || html.formCount > 0))) {
      add('obfuscation', -12, 'Mã JavaScript bị làm rối', 'Trang che giấu mã nguồn (eval/atob/packer) - thường để né bộ quét an ninh.');
    }
    if (isAnonymousHost && html.linkCount >= 5 && html.nullLinkRatio > 0.6) {
      add('null_links', -8, 'Phần lớn liên kết không dẫn đi đâu', `${Math.round(html.nullLinkRatio * 100)}% liên kết là "#" hoặc javascript: - đặc trưng của trang sao chép giao diện.`);
    }
    if (isAnonymousHost && html.textLength < 400 && (html.formCount > 0 || html.hasPasswordField)) {
      add('thin_form_page', -8, 'Trang gần như chỉ có biểu mẫu', 'Rất ít nội dung nhưng có biểu mẫu nhập liệu.');
    }

    // Tín hiệu minh bạch (tối đa +15)
    let transparency = 0;
    const positives: string[] = [];
    if (html.moitBadge) { transparency += 10; positives.push('đã thông báo/đăng ký với Bộ Công Thương (online.gov.vn)'); }
    if (html.taxId) { transparency += 5; positives.push('công bố mã số thuế/đăng ký kinh doanh'); }
    if (html.policyLinks) { transparency += 3; positives.push('có chính sách bảo mật/điều khoản'); }
    if (html.contactInfo) { transparency += 3; positives.push('có thông tin liên hệ'); }
    if (transparency && !d.isFreeHosting) {
      add('transparency', Math.min(15, transparency), 'Minh bạch thông tin chủ sở hữu', positives.join(', ') + '.');
    }

    // Khiên bảo hộ doanh nghiệp minh bạch (SMB Transparency Shield)
    // Bảo vệ các startup, doanh nghiệp vừa và nhỏ, cửa hàng hợp pháp (chưa có thứ hạng Tranco cao, tên miền trẻ)
    // nhưng công khai thông tin pháp lý/MST/chính sách và hoàn toàn không có dấu hiệu mạo danh hay đánh cắp dữ liệu.
    const hasTransparencyShield = (html.moitBadge || html.taxId || (html.contactInfo && html.policyLinks)) &&
      !html.telegramExfiltration &&
      html.sensitiveFields.length === 0 &&
      impersonated.length === 0 &&
      !factors.some(f => f.id === 'brand_in_domain' || f.id === 'typosquat') &&
      !html.faviconBrand &&
      !gambling &&
      !d.isFreeHosting &&
      !d.isIp;

    if (hasTransparencyShield && isAnonymousHost) {
      const targetFloor = (html.moitBadge || html.taxId) ? 75 : 65;
      floor = floor === null ? targetFloor : Math.max(floor, targetFloor);
      add('smb_shield', 10, 'Kích hoạt Khiên bảo hộ doanh nghiệp minh bạch', 'Website công bố đầy đủ thông tin pháp lý/MST/chính sách/liên hệ và không có dấu hiệu mạo danh thương hiệu hay đánh cắp dữ liệu.');
    }
  }

  // ---------------------------------------------------------------- Tổng hợp
  const raw = BASE_SCORE + factors.reduce((sum, f) => sum + f.delta, 0);
  let score = Math.max(0, Math.min(100, Math.round(raw)));
  const strongestCap = caps.sort((a, b) => a.value - b.value)[0];
  if (strongestCap) score = Math.min(score, strongestCap.value);
  else if (floor !== null) score = Math.max(score, floor);

  const confidence = [
    !!e.dns.ip || e.dns.nxdomain,
    !!e.tls?.ok,
    !!html && !html.botChallenge && html.textLength > 200,
    e.domainAge.ageDays !== null,
    rank !== null || isTrusted,
  ].filter(Boolean).length / 5;

  let verdict: RiskVerdict;
  if (strongestCap) verdict = strongestCap.verdict;
  else if (isTrusted) verdict = 'trusted';
  else if (score < 50) verdict = factors.some(f => ['brand_in_domain', 'typosquat', 'brand_impersonation', 'sensitive_fields'].includes(f.id)) ? 'phishing' : 'suspicious';
  else if (score >= 75 && (isPopular || (ageDays ?? 0) >= 365)) verdict = 'legit';
  else verdict = score >= 75 ? 'legit' : 'unknown';

  return {
    score,
    status: statusFromScore(score),
    verdict,
    factors: factors.sort((a, b) => a.delta - b.delta),
    cap: strongestCap?.value ?? null,
    floor,
    confidence,
    isGambling: gambling,
    isTrusted,
  };
}
