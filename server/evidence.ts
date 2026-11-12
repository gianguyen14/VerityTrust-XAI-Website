import net from 'node:net';
import tls from 'node:tls';
import { BlockedTargetError, FetchRedirectError, resolvePublicAddress, safeFetch } from './netSafety.ts';

import { TARGETED_BRAND_NAMES, getDomainParts, isShopPage, isTrustedHost, type DomainParts } from './domainRules.ts';
import { predictPhishingProbability } from './urlModel.ts';
import {
  checkSafeBrowsing,
  checkThreatFeeds,
  getPopularityRank,
  lookupDomainAge,
  type DomainAge,
} from './reputation.ts';

// ============================================================================
// THU THẬP BẰNG CHỨNG KỸ THUẬT VỀ MỘT WEBSITE
// Tất cả đều là quan sát thụ động (DNS, bắt tay TLS, một request GET, tra cứu công khai),
// không thực thi JavaScript của trang đích.
// ============================================================================

export interface TlsEvidence {
  ok: boolean;
  authorized: boolean;
  authorizationError: string | null;
  protocol: string | null;
  issuer: string | null;
  validFrom: string | null;
  validTo: string | null;
  certAgeDays: number | null;
  daysRemaining: number | null;
  error?: string;
}

export interface HtmlEvidence {
  title: string;
  description: string;
  text: string;
  textLength: number;
  formCount: number;
  hasPasswordField: boolean;
  sensitiveFields: string[];
  externalFormAction: string | null;
  telegramExfiltration: boolean;
  linkCount: number;
  externalLinkRatio: number;
  nullLinkRatio: number;
  iframeCount: number;
  obfuscationSignals: number;
  externalRedirect: string | null;
  moitBadge: boolean;
  taxId: boolean;
  contactInfo: boolean;
  policyLinks: boolean;
  /** Điện thoại hoặc email ở mọi định dạng quốc tế (contactInfo chỉ nhận số Việt Nam) */
  contactDetails: boolean;
  /** Số đăng ký doanh nghiệp / mã số thuế / VAT ở mọi quốc gia */
  legalId: boolean;
  /** Có liên kết tới trang thông tin pháp lý (Impressum, mentions légales...) */
  legalPageLink: boolean;
  /** Shop tiếng Đức (có giỏ hàng/phí vận chuyển bằng tiếng Đức): luật Đức bắt buộc có Impressum */
  germanShop: boolean;
  /** Trang liên hệ / pháp lý / giới thiệu cùng tên miền, trang pháp lý xếp trước */
  infoPages: string[];
  brandMentions: string[];
  credentialPrompt: boolean;
  botChallenge: boolean;
  /** Chủ đề lừa đảo nhận ra từ nội dung (đa ngôn ngữ) */
  scamThemes: ScamTheme[];
  /** Dấu hiệu Single Page App (SPA) với HTML rỗng và script động */
  isSpa: boolean;
  /** Dấu hiệu giao diện lừa đảo dạng ảnh kèm ô nhập liệu */
  imageDominantForm: boolean;
  /** Đường dẫn Favicon trích xuất được */
  faviconUrl: string | null;
  /** Thương hiệu bị mạo danh qua biểu tượng Favicon */
  faviconBrand: string | null;
}

export type ScamTheme = 'bank_login' | 'wallet_brand' | 'meta_support' | 'fake_download' | 'prize_scam';

// Mẫu nội dung của các chiến dịch lừa đảo phổ biến; chỉ dùng kết hợp với tên miền không phổ biến/chính thống
const SCAM_THEME_PATTERNS: Array<[ScamTheme, RegExp]> = [
  ['bank_login', /\b(?:online banking|internet banking|e-?banking|home ?banking|mobile banking|netbank|banca (?:online|en l[ií]nea|por internet|digital)|banco [a-z]+|bankowo[sś][cć] internetowa)\b|ngân hàng điện tử|ngân hàng số|đăng nhập ngân hàng/i],
  ['wallet_brand', /\b(?:atomic wallet|exodus wallet|trust ?wallet|metamask|phantom wallet|ledger live|trezor suite|trezor\.io|trezor (?:bridge|wallet|hardware|model)|ledger (?:wallet|nano|hardware)|tokenpocket|imtoken|safepal|bitget wallet|okx wallet|coinbase wallet)\b|tp\s*钱包|tp官方/i],
  ['meta_support', /\b(?:business help center|meta business (?:support|suite)|meta verified|facebook (?:help|support) (?:center|team)|page (?:appeal|restricted|has been (?:restricted|disabled))|violat(?:ed|ion of) (?:our )?community standards|copyright infringement (?:notice|report)|account (?:has been )?(?:restricted|disabled|suspended))\b/i],
  ['fake_download', /官方下载|官方正版|official (?:app )?download|download (?:the )?official app|tải (?:ứng dụng|app) chính thức/i],
  ['prize_scam', /\b(?:congratulations[,!]? you(?:'ve| have) (?:won|been selected)|claim your (?:prize|reward|gift)|you are (?:our )?lucky winner)\b|chúc mừng bạn đã trúng|bạn đã trúng thưởng|nhận quà tri ân|nhận thưởng ngay/i],
];

export function detectScamThemes(lowerText: string): ScamTheme[] {
  // Kẻ gian hay thêm dấu vào tên thương hiệu để né bộ lọc (Trézor, Lédger): so cả bản đã bỏ dấu
  const unaccented = lowerText.normalize('NFD').replace(/[\u0300-\u036f]/g, '');
  return SCAM_THEME_PATTERNS
    .filter(([theme, re]) => re.test(lowerText) || (theme === 'wallet_brand' && re.test(unaccented)))
    .map(([theme]) => theme);
}

export interface SiteEvidence {
  url: string;
  finalUrl: string | null;
  domain: DomainParts;
  finalDomain: DomainParts | null;
  dns: { ip: string | null; nxdomain: boolean; privateResolution: boolean; error?: string };
  tls: TlsEvidence | null;
  http: { status: number | null; usedHttps: boolean; hsts: boolean; csp: boolean; fetchError: string | null };
  html: HtmlEvidence | null;
  popularityRank: number | null;
  finalPopularityRank: number | null;
  /** Xác suất lừa đảo theo mô hình học sâu trên tên miền (null nếu chưa có mô hình) */
  urlModelProbability: number | null;
  finalUrlModelProbability: number | null;
  domainAge: DomainAge;
  threatListings: string[];
  /** Kết quả đọc trang liên hệ/pháp lý của shop chưa lâu năm (null nếu không đọc) */
  shopPages: ShopPagesEvidence | null;
  collectedMs: number;
}

export interface ShopPagesEvidence {
  checked: number;
  contact: boolean;
  legalId: boolean;
}

const BROWSER_HEADERS = {
  'User-Agent': 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/128.0.0.0 Safari/537.36',
  'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
  'Accept-Language': 'vi-VN,vi;q=0.9,en-US;q=0.8,en;q=0.7',
};

function probeTls(hostname: string, ip: string, port: number, timeoutMs: number): Promise<TlsEvidence> {
  return new Promise(resolve => {
    let done = false;
    const finish = (value: TlsEvidence) => {
      if (done) return;
      done = true;
      try {
        socket.end();
      } catch {}
      setTimeout(() => {
        try { socket.destroy(); } catch {}
      }, 500).unref();
      resolve(value);
    };
    const socket = tls.connect({
      host: ip,
      port,
      servername: net.isIP(hostname) ? undefined : hostname,
      rejectUnauthorized: false,
      timeout: timeoutMs,
    }, () => {
      const cert = socket.getPeerCertificate();
      const validFrom = cert?.valid_from ? new Date(cert.valid_from) : null;
      const validTo = cert?.valid_to ? new Date(cert.valid_to) : null;
      const rawIssuer = cert?.issuer?.O || cert?.issuer?.CN || null;
      finish({
        ok: true,
        authorized: socket.authorized,
        authorizationError: socket.authorizationError ? String(socket.authorizationError) : null,
        protocol: socket.getProtocol(),
        issuer: Array.isArray(rawIssuer) ? rawIssuer.join(', ') : rawIssuer,
        validFrom: validFrom?.toISOString() || null,
        validTo: validTo?.toISOString() || null,
        certAgeDays: validFrom ? Math.floor((Date.now() - validFrom.getTime()) / 86_400_000) : null,
        daysRemaining: validTo ? Math.floor((validTo.getTime() - Date.now()) / 86_400_000) : null,
      });
    });
    const fail = (error: string) => finish({
      ok: false, authorized: false, authorizationError: null, protocol: null, issuer: null,
      validFrom: null, validTo: null, certAgeDays: null, daysRemaining: null, error,
    });
    socket.on('timeout', () => fail('TLS timeout'));
    socket.on('error', err => fail(err.message));
  });
}

function decodeEntities(text: string): string {
  return text
    .replace(/&nbsp;/g, ' ')
    .replace(/&amp;/g, '&')
    .replace(/&quot;/g, '"')
    .replace(/&#39;|&apos;/g, "'")
    .replace(/&lt;/g, '<')
    .replace(/&gt;/g, '>')
    .replace(/&copy;/g, '©')
    .replace(/&reg;/g, '®')
    .replace(/&trade;/g, '™')
    .replace(/&#(\d+);/g, (_, code) => {
      try { return String.fromCodePoint(Number(code)); } catch { return ' '; }
    })
    .replace(/&#x([0-9a-f]+);/gi, (_, code) => {
      try { return String.fromCodePoint(parseInt(code, 16)); } catch { return ' '; }
    });
}

/**
 * Tiền xử lý HTML thành Markdown gọn nhẹ (HTML-to-Markdown).
 * Kỹ thuật lấy cảm hứng từ nghiên cứu "Content-Aware Malicious Website Detection Using Multilingual BERT"
 * (Springer Nature - Discover Computing, 2026; mô hình vietcuong/scam-website-detector).
 *
 * Loại bỏ 95%+ nhiễu mã hiển thị (div, class, script, style) nhưng GIỮ NGUYÊN các mặt trận tấn công:
 * - Tiêu đề: # Tiêu đề chính, ## Tiêu đề phụ
 * - Ô nhập liệu: [input: placeholder / name] (đặc biệt là OTP, password, tên đăng nhập)
 * - Nút bấm: [button: text] (Đăng nhập, Rút tiền, Tải app)
 * - Hình ảnh: ![alt] (logo thương hiệu bị giả mạo thường nằm ở thuộc tính alt)
 * - Liên kết: [text](hostname/path) (đặc biệt là t.me, zalo.me, kênh CSKH Telegram)
 */
export function htmlToMarkdown(html: string): string {
  if (!html) return '';
  let s = html
    .replace(/<!--[\s\S]*?-->/g, ' ')
    .replace(/<script\b[^>]*>[\s\S]*?<\/script>/gi, ' ')
    .replace(/<style\b[^>]*>[\s\S]*?<\/style>/gi, ' ')
    .replace(/<noscript\b[^>]*>[\s\S]*?<\/noscript>/gi, ' ')
    .replace(/<svg\b[^>]*>[\s\S]*?<\/svg>/gi, ' ')
    .replace(/<template\b[^>]*>[\s\S]*?<\/template>/gi, ' ')
    // HTML bị cắt ở giới hạn 1MB có thể dừng giữa thẻ <script>/<style> chưa đóng: bỏ phần còn lại,
    // nếu không cả trăm nghìn ký tự mã JavaScript sẽ bị coi là nội dung trang
    .replace(/<(script|style|noscript|svg|template)\b[^>]*>(?![\s\S]*<\/\1>)[\s\S]*$/i, ' ')
    // Loại bỏ banner Cookie, GDPR, OnTrust, Modal che phủ gây nhiễu ngữ nghĩa
    .replace(/<(?:div|section|aside|dialog)[^>]*(?:id|class)\s*=\s*["'][^"']*(?:cookie|gdpr|consent|onetrust|privacy-modal|cc-banner|cc-window)[^"']*["'][^>]*>[\s\S]*?<\/(?:div|section|aside|dialog)>/gi, ' ');

  // Tiêu đề h1..h6 -> Markdown heading
  s = s.replace(/<h([1-6])\b[^>]*>([\s\S]*?)<\/h\1>/gi, (_, lvl, text) => {
    const clean = text.replace(/<[^>]+>/g, ' ').trim();
    return clean ? '\n' + '#'.repeat(Number(lvl)) + ' ' + clean + '\n' : ' ';
  });

  // Nút bấm -> [button: ...]
  s = s.replace(/<button\b[^>]*>([\s\S]*?)<\/button>/gi, (_, text) => {
    const clean = text.replace(/<[^>]+>/g, ' ').trim();
    return clean ? ' [button: ' + clean + '] ' : ' ';
  });

  // Ô nhập liệu (input) -> [input: ...] hoặc [button: ...] cho submit
  s = s.replace(/<input\b([^>]*)>/gi, (_, attrs) => {
    const type = (attrs.match(/\btype\s*=\s*["']?([^"'\s>]+)/i)?.[1] || 'text').toLowerCase();
    if (type === 'hidden') return ' ';
    const placeholder = attrs.match(/\bplaceholder\s*=\s*["']([^"']+)["']/i)?.[1] || '';
    const name = attrs.match(/\bname\s*=\s*["']([^"']+)["']/i)?.[1] || '';
    const aria = attrs.match(/\baria-label\s*=\s*["']([^"']+)["']/i)?.[1] || '';
    const val = attrs.match(/\bvalue\s*=\s*["']([^"']+)["']/i)?.[1] || '';
    const label = placeholder || aria || val || name;
    if (type === 'submit' || type === 'button') {
      return label ? ' [button: ' + label + '] ' : ' ';
    }
    return label ? ' [input: ' + (type === 'password' ? 'password ' + label : label) + '] ' : (type === 'password' ? ' [input: password] ' : ' ');
  });

  // Hình ảnh có alt -> ![alt]
  s = s.replace(/<img\b([^>]*)>/gi, (_, attrs) => {
    const alt = attrs.match(/\balt\s*=\s*["']([^"']+)["']/i)?.[1];
    return alt && alt.trim() ? ' ![' + alt.trim() + '] ' : ' ';
  });

  // Liên kết -> [text](url)
  s = s.replace(/<a\b([^>]*)>([\s\S]*?)<\/a>/gi, (_, attrs, content) => {
    const text = content.replace(/<[^>]+>/g, ' ').trim();
    const href = attrs.match(/\bhref\s*=\s*["']([^"']+)["']/i)?.[1] || '';
    if (!text && !href) return ' ';
    if (href.startsWith('http://') || href.startsWith('https://') || href.startsWith('//')) {
      try {
        const u = new URL(href.startsWith('//') ? 'https:' + href : href);
        const hostPath = u.hostname + (u.pathname !== '/' ? u.pathname.slice(0, 30) : '');
        return ' [' + (text || hostPath) + '](' + hostPath + ') ';
      } catch {
        return text ? ' [' + text + '] ' : ' ';
      }
    }
    return text ? ' [' + text + '] ' : ' ';
  });

  // Thẻ khối phân cách dòng
  s = s.replace(/<\/(p|div|section|article|li|tr|header|footer)>/gi, '\n');
  s = s.replace(/<br\s*\/?>/gi, '\n');

  // Xóa các thẻ HTML còn lại
  s = s.replace(/<[^>]+>/g, ' ');

  // Giải mã ký tự HTML entities
  s = decodeEntities(s);

  // Chuẩn hóa khoảng trắng
  return s.replace(/[ \t]+/g, ' ').replace(/\n\s*\n+/g, '\n\n').trim();
}

function ownerDomainOf(href: string, base: string): string | null {
  try {
    const u = new URL(href, base);
    if (u.protocol !== 'http:' && u.protocol !== 'https:') return null;
    return getDomainParts(u.hostname).ownerDomain;
  } catch {
    return null;
  }
}

// CDN / kho ảnh dùng chung: ai cũng có thể lưu favicon ở đây, nên tên máy chủ không cho biết ai sở hữu biểu tượng
const SHARED_ASSET_HOSTS = [
  'googleusercontent.com', 'gstatic.com', 'googleapis.com', 'ggpht.com', 'blogger.com', 'blogspot.com',
  'githubusercontent.com', 'github.io', 'cloudflare.com', 'cloudfront.net', 'akamaihd.net', 'akamaized.net',
  'fbcdn.net', 'wp.com', 'wordpress.com', 'shopify.com', 'squarespace-cdn.com', 'wixstatic.com', 'jsdelivr.net',
  'unpkg.com', 'imgur.com', 'amazonaws.com', 'azureedge.net', 'twimg.com', 'ytimg.com', 'licdn.com',
];

const CONTACT_DETAILS = /[\w.+-]+@[\w-]+(?:\.[\w-]+)*\.[a-z]{2,}\b(?<!\.(?:png|jpe?g|webp|gif|svg))|(?:\+|\b00)\d{1,3}[\s()./-]*\d(?:[\s()./-]*\d){6,12}|(?:tel(?:efon|éfono|efono)?|phone|téléphone|điện thoại|hotline|call us)\s*[:.]?\s*\(?\+?\d[\d\s()./-]{6,}/i;
const LEGAL_ID = /\bHR[AB]\s?\d{3,}|handelsregister|registergericht|ust[\s.-]*id|umsatzsteuer-?identifikationsnummer|steuer-?nr|\bvat\s*(?:no|number|id|reg)|\bsire[nt]\b|\brcs\s+[a-z]|\bkvk\b|partita iva|\bp\.\s?iva\b|\b[nc]if\s*:?\s*[a-z]?\d{7}|company (?:no|number|registration)|registered in (?:england|scotland|wales|ireland)|\babn\s*:?\s*\d|mã số (?:thuế|doanh nghiệp)|\bmst\b/i;
const LEGAL_PAGE = /impressum|imprint|anbieterkennzeichnung|rechtliche[sn]? hinweise|legal[-_ ]notice|mentions[-_ ]l[ée]gales|aviso[-_ ]legal|note[-_ ]legali|colofon/i;
const CONTACT_PAGE = /kontakt|contact|lien-he|liên hệ|contatti|contacto/i;
const ABOUT_PAGE = /about|[uü]ber[-_ ]uns|chi[-_ ]siamo|qui[-_ ]sommes|gioi-thieu|giới thiệu/i;
// Số điện thoại/email đôi khi chỉ nằm trong liên kết tel:/mailto: (vd tổng đài 1900xxxx)
const CONTACT_LINK = /href\s*=\s*["']\s*(?:tel|mailto):\s*[+\w]/i;
const GERMAN_SHOP = /\b(?:warenkorb|versandkosten|inkl\.? mwst|zur kasse|in den korb|kostenloser versand)\b/i;

const SENSITIVE_FIELD_PATTERNS: Array<[string, RegExp]> = [
  ['OTP', /\b(?:otp|one[-_ ]?time|mã\s*otp|ma[-_]?otp|verification[-_ ]?code|sms[-_ ]?code)\b/i],
  ['Thẻ thanh toán', /\b(?:card[-_ ]?num|cc[-_ ]?num|cardnumber|cc-number|cvv|cvc|csc|expiry|exp[-_ ]?date|số\s*thẻ)\b/i],
  ['Mã PIN', /\b(?:pin|atm[-_ ]?pin)\b/i],
  ['Cụm từ khôi phục ví', /\b(?:seed|mnemonic|recovery[-_ ]?phrase|secret[-_ ]?phrase|private[-_ ]?key|passphrase)\b/i],
  ['Giấy tờ tùy thân', /\b(?:ssn|social[-_ ]?security|cccd|cmnd|căn\s*cước|passport|dni|cpf|nif|nie|curp)\b/i],
];

export function analyzeHtml(html: string, pageUrl: string, ownerDomain: string): HtmlEvidence {
  const title = decodeEntities((html.match(/<title[^>]*>([\s\S]*?)<\/title>/i)?.[1] || '').replace(/\s+/g, ' ').trim()).slice(0, 300);
  const description = decodeEntities(
    html.match(/<meta[^>]*name=["']description["'][^>]*content=["']([^"']+)["']/i)?.[1] ||
    html.match(/<meta[^>]*content=["']([^"']+)["'][^>]*name=["']description["']/i)?.[1] ||
    html.match(/<meta[^>]*property=["']og:description["'][^>]*content=["']([^"']+)["']/i)?.[1] || ''
  ).trim().slice(0, 500);

  const scripts = [...html.matchAll(/<script\b[^>]*>([\s\S]*?)<\/script>/gi)].map(m => m[1]).join('\n');
  const text = htmlToMarkdown(html);

  const inputs = [...html.matchAll(/<input\b[^>]*>/gi)].map(m => m[0]);
  const hasPasswordField = inputs.some(i => /type\s*=\s*["']?password/i.test(i));
  const fieldText = inputs.map(i => (i.match(/(?:name|id|placeholder|autocomplete|aria-label)\s*=\s*["'][^"']*["']/gi) || []).join(' ')).join(' ');
  const sensitiveFields = SENSITIVE_FIELD_PATTERNS
    .filter(([, re]) => re.test(fieldText) || (re.source.includes('seed') && /\b(?:seed phrase|recovery phrase|secret recovery|12[- ]word|24[- ]word)\b/i.test(text)))
    .map(([label]) => label);

  const formActions = [...html.matchAll(/<form\b[^>]*action\s*=\s*["']([^"']+)["']/gi)].map(m => m[1]);
  const externalFormAction = formActions
    .map(a => ({ a, d: ownerDomainOf(a, pageUrl) }))
    .find(x => x.d && x.d !== ownerDomain)?.d || null;

  const hrefs = [...html.matchAll(/<a\b[^>]*href\s*=\s*["']([^"']*)["']/gi)].map(m => m[1].trim());
  const anchors = [...html.matchAll(/<a\b[^>]*href\s*=\s*["']([^"']*)["'][^>]*>([\s\S]{0,200}?)<\/a>/gi)]
    .map(m => ({ href: m[1].trim(), label: `${m[1]} ${m[2].replace(/<[^>]+>/g, ' ')}` }));
  const legalAnchors = anchors.filter(a => LEGAL_PAGE.test(a.label));
  // Trang phụ cần đọc: pháp lý trước, rồi liên hệ, rồi giới thiệu
  const infoPages = [...new Set([...legalAnchors, ...anchors.filter(a => CONTACT_PAGE.test(a.label)), ...anchors.filter(a => ABOUT_PAGE.test(a.label))].flatMap(a => {
    try {
      const u = new URL(a.href, pageUrl);
      return ownerDomainOf(u.href, pageUrl) === ownerDomain && u.href.split('#')[0] !== pageUrl.split('#')[0] ? [u.href.split('#')[0]] : [];
    } catch {
      return [];
    }
  }))].slice(0, 3);
  const nullLinks = hrefs.filter(h => h === '' || h === '#' || /^javascript:/i.test(h)).length;
  const linkDomains = hrefs.map(h => ownerDomainOf(h, pageUrl)).filter((d): d is string => !!d);
  const externalLinks = linkDomains.filter(d => d !== ownerDomain).length;

  const redirectTarget =
    html.match(/<meta[^>]*http-equiv=["']?refresh["']?[^>]*content=["'][^"']*url=([^"'>\s]+)/i)?.[1] ||
    scripts.match(/(?:window\.|document\.|top\.)?location(?:\.href)?\s*=\s*["']([^"']+)["']/i)?.[1] ||
    scripts.match(/location\.(?:replace|assign)\(\s*["']([^"']+)["']/i)?.[1] || null;
  const redirectDomain = redirectTarget ? ownerDomainOf(redirectTarget, pageUrl) : null;

  const obfuscationSignals = [
    /eval\s*\(\s*function\s*\(\s*p\s*,\s*a\s*,\s*c\s*,\s*k\s*,\s*e/i,
    /eval\s*\(\s*(?:atob|unescape|decodeURIComponent)\s*\(/i,
    /document\.write\s*\(\s*(?:unescape|atob)\s*\(/i,
    /String\.fromCharCode\s*\((?:\s*\d+\s*,){20,}/i,
    /\\x[0-9a-f]{2}(?:\\x[0-9a-f]{2}){30,}/i,
    /[A-Za-z0-9+/]{2000,}={0,2}/,
  ].filter(re => re.test(scripts)).length;

  const lowerText = `${title} ${description} ${text.slice(0, 6000)}`.toLowerCase();
  // Bỏ các cụm thương hiệu xuất hiện tự nhiên trên web hợp pháp: nút đăng nhập mạng xã hội, link kho ứng dụng, mục "theo dõi chúng tôi"
  const brandText = lowerText
    .replace(/\((?:https?:\/\/)?[a-z0-9.-]+\.[a-z]{2,}[^\s)]*\)/g, ' ') // đích của liên kết (vd "(www.facebook.com/trang-cua-truong)")
    .replace(/protected by recaptcha and the google[^.]{0,120}/g, ' ')
    .replace(/\[[a-z0-9.-]+\.[a-z]{2,}\/[^\]]*\]/g, ' ') // chữ của liên kết là một đường dẫn
    // biểu tượng mạng xã hội: [fa-facebook-f], [![facebook]], [google+], [Facebook] đứng một mình trong liên kết
    .replace(/\[!?\[?\s*(?:fa-|icon-)?[a-z]+(?:-[a-z]+)?\+?\s*\]?\]/g, m => (/[a-z]{3,}/.test(m) && m.length <= 26 ? ' ' : m))
    // đại lý/cửa hàng bán sản phẩm của thương hiệu
    .replace(/(?:apple|google|samsung) (?:pixel|watch|tv|pencil|airpods|homepod|nest|chromecast|galaxy)/g, ' ')
    .replace(/(?:revendeur agréé|partenaire agréé|authori[sz]ed (?:reseller|dealer|partner)|đại lý (?:ủy quyền|chính hãng)|nhà phân phối chính hãng)[^.]{0,40}/g, ' ')
    .replace(/(?:đăng nhập|đăng ký|tiếp tục|login|log in|sign in|sign up|continue|connect)\s*(?:bằng|với|qua|with|using|via)\s*(?:tài khoản\s*)?(?:google|facebook|apple|microsoft|zalo|github|twitter|linkedin)/g, ' ')
    .replace(/(?:google play|app store|apple store|get it on google|download on the app store|tải (?:ứng dụng|app) (?:trên|tại))/g, ' ')
    .replace(/(?:theo dõi|follow|kết nối với) (?:chúng tôi|us)(?: trên| on)?[^.]{0,80}/g, ' ');
  const brandMentions = TARGETED_BRAND_NAMES.filter(b => b.length >= 5 && new RegExp(`\\b${b}\\b`, 'i').test(brandText));

  // Nhận diện Single Page Application (SPA như React, Vue, Next.js với HTML rỗng)
  const hasSpaContainer = /<div\b[^>]*(?:id|class)\s*=\s*["'](?:root|app|__next|__nuxt)["']/i.test(html);
  const isSpa = hasSpaContainer && text.length < 350;

  // Nếu là SPA và chưa phát hiện thương hiệu trong HTML tĩnh, quét mã kịch bản inline/bundles
  if (isSpa && brandMentions.length === 0 && scripts.length > 0) {
    const lowerScripts = scripts.slice(0, 15000).toLowerCase();
    for (const b of TARGETED_BRAND_NAMES) {
      if (b.length >= 5 && new RegExp(`\\b${b}\\b`, 'i').test(lowerScripts)) {
        brandMentions.push(b);
      }
    }
  }

  // Phát hiện giao diện dạng ảnh kết hợp ô nhập liệu (image-dominant form) né bộ lọc văn bản
  const imgCount = (html.match(/<img\b/gi) || []).length;
  const imageDominantForm = text.length < 250 && imgCount >= 1 && (inputs.length >= 1 || hasPasswordField);

  // Kênh tuồn dữ liệu ngầm (Telegram Bot API hoặc Discord Webhooks)
  const telegramExfiltration = /api\.telegram\.org\/bot/i.test(html) || /discord(?:app)?\.com\/api\/webhooks/i.test(html);

  // Trích xuất Favicon và kiểm tra giả mạo biểu tượng thương hiệu
  const faviconHrefMatch = html.match(/<link\b[^>]*rel\s*=\s*["'](?:shortcut )?icon["'][^>]*href\s*=\s*["']([^"']+)["']/i) ||
    html.match(/<link\b[^>]*href\s*=\s*["']([^"']+)["'][^>]*rel\s*=\s*["'](?:shortcut )?icon["']/i);
  const rawFavicon = faviconHrefMatch ? faviconHrefMatch[1].trim() : null;
  let faviconUrl: string | null = null;
  let faviconBrand: string | null = null;
  if (rawFavicon) {
    try {
      const favU = new URL(rawFavicon, pageUrl);
      faviconUrl = favU.href;
      const favHost = favU.hostname.toLowerCase();
      const favDomain = ownerDomainOf(favU.href, pageUrl);
      const onSharedHost = SHARED_ASSET_HOSTS.some(d => favHost === d || favHost.endsWith(`.${d}`));
      // 1) Tên thương hiệu trong ĐƯỜNG DẪN/TÊN FILE favicon (vd /img/vietcombank-logo.ico), khớp theo ranh giới từ.
      //    Không xét tên máy chủ: lh3.googleusercontent.com chứa "google" nhưng chỉ là CDN chứa ảnh của bất kỳ ai.
      let favPath = favU.pathname;
      try {
        favPath = decodeURIComponent(favPath);
      } catch {
        // giữ nguyên đường dẫn nếu không giải mã được
      }
      const pathTokens = favPath.toLowerCase().split(/[^a-z0-9]+/).filter(Boolean);
      faviconBrand = TARGETED_BRAND_NAMES.find(b =>
        b.length >= 4 &&
        !ownerDomain.includes(b) &&
        pathTokens.some(t => t === b || (b.length >= 6 && t.startsWith(b))),
      ) ?? null;
      // 2) Favicon lấy thẳng từ website chính thức của thương hiệu khác (hotlink vd vietcombank.com.vn/favicon.ico).
      //    CDN/kho ảnh dùng chung không được tính dù nằm trong danh sách tin cậy.
      if (!faviconBrand && favDomain && favDomain !== ownerDomain && !onSharedHost && isTrustedHost(favHost)) {
        faviconBrand = TARGETED_BRAND_NAMES.find(b => favDomain.includes(b)) ?? favDomain;
      }
    } catch {
      faviconUrl = rawFavicon;
    }
  }

  return {
    title,
    description,
    text: text.slice(0, 6000),
    textLength: text.length,
    formCount: (html.match(/<form\b/gi) || []).length,
    hasPasswordField,
    sensitiveFields,
    externalFormAction,
    telegramExfiltration,
    linkCount: hrefs.length,
    externalLinkRatio: linkDomains.length ? externalLinks / linkDomains.length : 0,
    nullLinkRatio: hrefs.length ? nullLinks / hrefs.length : 0,
    iframeCount: (html.match(/<iframe\b/gi) || []).length,
    obfuscationSignals,
    externalRedirect: redirectDomain && redirectDomain !== ownerDomain ? redirectDomain : null,
    moitBadge: /online\.gov\.vn/i.test(html),
    taxId: /(?:mã số thuế|mst|mã số doanh nghiệp|gpkd|giấy chứng nhận đăng ký (?:doanh nghiệp|kinh doanh)|tax id|company registration)[^0-9]{0,40}\d{9,13}/i.test(text),
    contactInfo: /(?:\+84|\b0)[1-9](?:[\s.-]?\d){8}\b|hotline|[\w.+-]+@[\w-]+\.[\w.]+/i.test(text),
    policyLinks: /privacy|chính sách bảo mật|chính sách quyền riêng tư|terms of (?:service|use)|điều khoản (?:sử dụng|dịch vụ)/i.test(`${text} ${hrefs.join(' ')}`),
    contactDetails: CONTACT_DETAILS.test(text) || CONTACT_LINK.test(html),
    legalId: LEGAL_ID.test(text),
    legalPageLink: legalAnchors.length > 0,
    // Giỏ hàng của theme WooCommerce/Shopify hay nằm trong thuộc tính title/aria-label, không có trong nội dung chữ
    germanShop: GERMAN_SHOP.test(`${title} ${text}`) || (/<html\b[^>]*\blang\s*=\s*["']?de\b/i.test(html) && /warenkorb|zur kasse/i.test(html)),
    infoPages,
    brandMentions,
    credentialPrompt: /\b(?:sign in|log ?in|verify your|confirm your|account (?:suspended|locked|limited)|unusual activity|đăng nhập|xác minh tài khoản|xác thực tài khoản|tài khoản (?:bị|đã bị) (?:khóa|tạm khóa)|cập nhật thông tin)\b/i.test(lowerText),
    botChallenge: /just a moment|attention required|checking your browser|cf-browser-verification|ddos-guard|client challenge|verify you are human|enable javascript and cookies to continue/i.test(`${title} ${text.slice(0, 500)}`),
    scamThemes: detectScamThemes(lowerText),
    isSpa,
    imageDominantForm,
    faviconUrl,
    faviconBrand,
  };
}

/**
 * Tầng 1 (trong bộ nhớ, < 1ms): khởi tạo bằng chứng với các tín hiệu không cần mạng -
 * độ phổ biến Tranco, danh sách đen phishing, mô hình học sâu trên tên miền.
 */
export function createEvidence(targetUrl: string): SiteEvidence {
  const parsed = new URL(targetUrl);
  const domain = getDomainParts(parsed.hostname);
  return {
    url: targetUrl,
    finalUrl: null,
    domain,
    finalDomain: null,
    dns: { ip: null, nxdomain: false, privateResolution: false },
    tls: null,
    http: { status: null, usedHttps: parsed.protocol === 'https:', hsts: false, csp: false, fetchError: null },
    html: null,
    popularityRank: getPopularityRank(domain.ownerDomain),
    finalPopularityRank: null,
    urlModelProbability: domain.isIp ? null : predictPhishingProbability(domain.host),
    finalUrlModelProbability: null,
    domainAge: { registeredAt: null, ageDays: null, registrar: null },
    threatListings: checkThreatFeeds(domain.host, domain.ownerDomain, targetUrl),
    shopPages: null,
    collectedMs: 0,
  };
}

/**
 * Tầng 0: phân giải DNS qua bộ chặn SSRF. Trả về false nếu không thể truy cập tiếp
 * (tên miền không tồn tại / trỏ về IP nội bộ) - khi đó vẫn bổ sung tuổi tên miền và Safe Browsing.
 * Ném BlockedTargetError nếu người dùng nhập trực tiếp IP nội bộ / localhost.
 */
export async function resolveTargetDns(evidence: SiteEvidence): Promise<boolean> {
  const started = Date.now();
  const parsed = new URL(evidence.url);
  const domain = evidence.domain;
  const targetUrl = evidence.url;
  try {
    evidence.dns.ip = await resolvePublicAddress(parsed.hostname, 2500);
    return true;
  } catch (err: any) {
    // Người dùng nhập trực tiếp IP nội bộ / localhost -> từ chối như cũ
    if (err instanceof BlockedTargetError && (domain.isIp || /^localhost$|\.localhost$/i.test(parsed.hostname))) throw err;
    if (err instanceof BlockedTargetError) {
      // Tên miền công khai nhưng trỏ về IP nội bộ: dấu hiệu sinkhole/DNS rebinding, không truy cập tiếp
      evidence.dns.privateResolution = true;
    }
    evidence.dns.error = err?.message || String(err);
    evidence.dns.nxdomain = /ENOTFOUND|NXDOMAIN|ENODATA/i.test(evidence.dns.error || '');
    const [domainAge, safeBrowsing] = await Promise.all([
      domain.isFreeHosting || domain.isIp ? evidence.domainAge : lookupDomainAge(domain.icannDomain),
      checkSafeBrowsing(targetUrl),
    ]);
    evidence.domainAge = domainAge;
    evidence.threatListings.push(...safeBrowsing);
    evidence.collectedMs += Date.now() - started;
    return false;
  }
}

/** Tầng 2: tải HTML tĩnh + bắt tay TLS + tuổi tên miền RDAP + Safe Browsing (song song). */
export async function collectPageEvidence(evidence: SiteEvidence): Promise<void> {
  const started = Date.now();
  const parsed = new URL(evidence.url);
  const domain = evidence.domain;
  const targetUrl = evidence.url;
  if (!evidence.dns.ip) return;
  const port = parsed.port ? parseInt(parsed.port, 10) : 443;
  const fetchPage = async () => {
    try {
      return await safeFetch(parsed.href, { timeoutMs: 6000, maxBytes: 1024 * 1024, headers: BROWSER_HEADERS });
    } catch (err: any) {
      if (err instanceof BlockedTargetError) throw err;
      // Nhiều trang lừa đảo chỉ chạy HTTP: thử lại bằng http:// nếu https:// thất bại
      if (parsed.protocol === 'https:' && !parsed.port) {
        const httpUrl = parsed.href.replace(/^https:/, 'http:');
        const res = await safeFetch(httpUrl, { timeoutMs: 4000, maxBytes: 1024 * 1024, headers: BROWSER_HEADERS });
        evidence.http.usedHttps = false;
        return res;
      }
      throw err;
    }
  };

  const [page, tlsResult, domainAge, safeBrowsing] = await Promise.allSettled([
    fetchPage(),
    parsed.protocol === 'https:' || !parsed.port ? probeTls(parsed.hostname, evidence.dns.ip, port, 3000) : Promise.resolve(null),
    domain.isFreeHosting || domain.isIp ? Promise.resolve(evidence.domainAge) : lookupDomainAge(domain.icannDomain),
    checkSafeBrowsing(targetUrl),
  ]);

  if (tlsResult.status === 'fulfilled') evidence.tls = tlsResult.value;
  if (domainAge.status === 'fulfilled') evidence.domainAge = domainAge.value;
  if (safeBrowsing.status === 'fulfilled') evidence.threatListings.push(...safeBrowsing.value);

  if (page.status === 'fulfilled') {
    const res = page.value;
    evidence.finalUrl = res.finalUrl;
    evidence.http.status = res.status;
    evidence.http.usedHttps = res.finalUrl.startsWith('https:');
    evidence.http.hsts = !!res.headers.get('strict-transport-security');
    evidence.http.csp = !!res.headers.get('content-security-policy');
    const finalHost = new URL(res.finalUrl).hostname;
    if (finalHost !== domain.host) {
      evidence.finalDomain = getDomainParts(finalHost);
      evidence.finalPopularityRank = getPopularityRank(evidence.finalDomain.ownerDomain);
      evidence.finalUrlModelProbability = evidence.finalDomain.isIp ? null : predictPhishingProbability(finalHost);
      evidence.threatListings.push(...checkThreatFeeds(finalHost, evidence.finalDomain.ownerDomain, res.finalUrl));
    }
    const contentType = res.headers.get('content-type') || '';
    if (!contentType || /html|xml|text/i.test(contentType)) {
      evidence.html = analyzeHtml(res.body, res.finalUrl, (evidence.finalDomain || domain).ownerDomain);
      if (needsShopPages(evidence)) evidence.shopPages = await collectShopPages(evidence.html, (evidence.finalDomain || domain).ownerDomain);
    }
  } else {
    if (page.reason instanceof BlockedTargetError) {
      evidence.dns.privateResolution = true;
    }
    if (page.reason instanceof FetchRedirectError && page.reason.lastUrl) {
      evidence.finalUrl = page.reason.lastUrl;
      try {
        const finalHost = new URL(page.reason.lastUrl).hostname;
        evidence.finalDomain = getDomainParts(finalHost);
        evidence.finalPopularityRank = getPopularityRank(evidence.finalDomain.ownerDomain);
        evidence.finalUrlModelProbability = evidence.finalDomain.isIp ? null : predictPhishingProbability(finalHost);
        evidence.threatListings.push(...checkThreatFeeds(finalHost, evidence.finalDomain.ownerDomain, page.reason.lastUrl));
      } catch {}
    }
    evidence.http.fetchError = page.reason?.message || String(page.reason);
  }

  evidence.threatListings = [...new Set(evidence.threatListings)];
  evidence.collectedMs += Date.now() - started;
}

// Shop lừa đảo hay để trang liên hệ chỉ có form, không có điện thoại/email/thông tin doanh nghiệp.
// Chỉ đọc thêm trang phụ với shop chưa lâu năm và chưa có số đăng ký doanh nghiệp trên trang chủ.
function needsShopPages(e: SiteEvidence): boolean {
  const html = e.html;
  if (!html || !html.infoPages.length || html.legalId || html.taxId || html.moitBadge) return false;
  if (e.domainAge.ageDays !== null && e.domainAge.ageDays >= 2 * 365) return false;
  if (e.popularityRank !== null && e.popularityRank <= 100_000) return false;
  return isShopPage(html.title, html.text);
}

async function collectShopPages(html: HtmlEvidence, ownerDomain: string): Promise<ShopPagesEvidence> {
  const result: ShopPagesEvidence = { checked: 0, contact: html.contactDetails || html.contactInfo, legalId: false };
  const pages = await Promise.allSettled(html.infoPages.slice(0, 2).map(url =>
    safeFetch(url, { timeoutMs: 4000, maxBytes: 512 * 1024, headers: BROWSER_HEADERS })));
  for (const page of pages) {
    if (page.status !== 'fulfilled' || page.value.status >= 400 || ownerDomainOf(page.value.finalUrl, page.value.finalUrl) !== ownerDomain) continue;
    const body = page.value.body;
    const text = htmlToMarkdown(body);
    result.checked++;
    result.contact ||= CONTACT_DETAILS.test(text) || CONTACT_LINK.test(body);
    result.legalId ||= LEGAL_ID.test(text) || /online\.gov\.vn/i.test(body);
  }
  return result;
}

/** Thu thập toàn bộ bằng chứng một lượt (Tầng 0 -> 2, không dừng sớm). Dùng cho script đánh giá/huấn luyện. */
export async function collectEvidence(targetUrl: string): Promise<SiteEvidence> {
  const evidence = createEvidence(targetUrl);
  if (await resolveTargetDns(evidence)) await collectPageEvidence(evidence);
  return evidence;
}
