import fs from 'node:fs';
import path from 'node:path';
import { parse as parseDomain } from 'tldts';

// ============================================================================
// VERIFIED WEBSITE IDENTIFICATION ENGINE & SECURITY CLASSIFICATION
// Rigorous domain separation, anti-impersonation, live DNS & TLS validation
// ============================================================================

// Authoritative Whitelist of Known Official Enterprise, Government & Media Apex Domains
export const TRUSTED_APEX_DOMAINS = new Set([
  // Vietnam Banking, FinTech & Payment Gateways
  'vietcombank.com.vn', 'vcb.com.vn', 'techcombank.com.vn', 'techcombank.vn',
  'bidv.com.vn', 'agribank.com.vn', 'mbbank.com.vn', 'acb.com.vn', 'shb.com.vn',
  'vpbank.com.vn', 'sacombank.com.vn', 'tpbank.com.vn', 'hdbank.com.vn', 'vib.com.vn',
  'seabank.com.vn', 'ocb.com.vn', 'msb.com.vn', 'bacabank.com.vn', 'pvcombank.com.vn',
  'momo.vn', 'vnpay.vn', 'zalopay.vn', 'viettelmoney.vn', 'sbv.gov.vn',

  // Vietnam National Government, Ministries & Public Portals
  'chinhphu.vn', 'bocongan.gov.vn', 'mic.gov.vn', 'moit.gov.vn', 'mof.gov.vn',
  'dichvucong.gov.vn', 'vneid.gov.vn', 'baohiemxahoi.gov.vn', 'gdt.gov.vn',
  'customs.gov.vn', 'monre.gov.vn', 'bgtv.gov.vn', 'mpi.gov.vn', 'molisa.gov.vn',

  // Vietnam Top News Agencies & Accredited Press
  'vnexpress.net', 'tuoitre.vn', 'thanhnien.vn', 'dantri.com.vn', 'vietnamnet.vn',
  'vtv.vn', 'vov.vn', 'znews.vn', 'laodong.vn', 'nhandan.vn', 'plo.vn', 'sggp.org.vn',
  'tienphong.vn', 'baotintuc.vn', 'cafef.vn', 'cafebiz.vn',

  // Vietnam Leading E-Commerce, Retail & Telecommunications
  'shopee.vn', 'tiki.vn', 'lazada.vn', 'sendo.vn', 'fpt.com', 'fptshop.com.vn',
  'thegioididong.com', 'dienmayxanh.com', 'topzone.vn', 'cellphones.com.vn',
  'bachhoaxanh.com', 'hoanghamobile.com', 'viettelstore.vn', 'viettel.vn', 'vinaphone.vn',

  // Global Trusted Technology, Cloud & Research Authorities
  'google.com', 'google.com.vn', 'youtube.com', 'facebook.com', 'zalo.me',
  'github.com', 'microsoft.com', 'apple.com', 'amazon.com', 'cloudflare.com',
  'wikipedia.org', 'wikimedia.org', 'linkedin.com', 'x.com', 'twitter.com',
  'gitlab.com', 'mozilla.org', 'w3.org', 'ietf.org', 'nist.gov',

  // Tên miền chính thức của các thương hiệu hay bị mạo danh & hạ tầng CDN/API của họ
  'paypal.com', 'binance.com', 'netflix.com', 'instagram.com', 'whatsapp.com', 'messenger.com',
  'fbcdn.net', 'googleusercontent.com', 'googleapis.com', 'gstatic.com', 'youtu.be',
  'icloud.com', 'live.com', 'outlook.com', 'office.com', 'microsoftonline.com',
  'roblox.com', 'spotify.com', 'xfinity.com', 'telegram.org', 't.me', 'discord.com', 'discord.gg',
  'discordapp.com', 'coinbase.com', 'metamask.io', 'docusign.com', 'docusign.net', 'tiktok.com',
  'steamcommunity.com', 'steampowered.com', 'wellsfargo.com', 'bankofamerica.com', 'usps.com', 'fedex.com',
  'whatsapp.net'
]);

// ============================================================================
// BỘ LỌC TOÀN DIỆN: CỜ BẠC, CÁ CƯỢC, CASINO, GAME BÀI THEO PHÁP LUẬT VIỆT NAM
// Căn cứ: Điều 321, 322 Bộ luật Hình sự 2015 & Điều 8 Luật An ninh mạng 2018
// ============================================================================
export const GAMBLING_TLDS = ['.casino', '.bet', '.poker', '.bingo'];

// Cụm từ nghiệp vụ cờ bạc trong NỘI DUNG trang (cần khớp ít nhất 2 cụm khác nhau để tránh báo nhầm bài báo/tin tức)
export const GAMBLING_KEYWORDS_CONTENT = [
  'cá cược', 'cược thể thao', 'kèo nhà cái', 'tỷ lệ kèo', 'kèo bóng đá', 'sòng bài', 'sòng bạc', 'casino',
  'đánh bài', 'game bài đổi thưởng', 'game bài', 'nổ hũ', 'quay hũ', 'tài xỉu', 'xóc đĩa', 'lô đề', 'soi cầu',
  'baccarat', 'roulette', 'poker trực tuyến', 'đặt cược', 'đá gà', 'bắn cá đổi thưởng', 'nạp rút 1:1',
  'nạp rút nhanh', 'tặng code tân thủ', 'đăng ký đại lý cược',
  // Tiếng Anh: chỉ dùng cụm từ đặc trưng của nhà cái, không dùng từ đơn dễ gặp trong tin tức
  'sportsbook', 'online casino', 'live casino', 'casino games', 'sports betting', 'online betting',
  'betting odds', 'live betting', 'free bets', 'free spins', 'place your bet', 'bet now', 'slot games',
  'blackjack', 'online lottery', 'lottery', 'wingo',
  // Tiếng Trung (nhiều trang cờ bạc nhắm tới châu Á)
  '真人视讯', '娱乐场', '滚球', '赔率', '体育投注', '百家乐', '老虎机', '博彩', '棋牌', '电子游艺', '彩票投注', '下注',
  // Các ngôn ngữ khác hay gặp trong tập đánh giá (bị lọt khi chỉ có Việt/Anh/Trung)
  'slot gacor', 'gacor', 'maxwin', 'situs slot', 'slot online', 'judi online', 'togel', 'link alternatif', 'rtp slot',
  'สล็อต', 'คาสิโน', 'บาคาร่า', 'แทงบอล', 'เว็บพนัน',
  'ক্যাসিনো', 'বেটিং', 'স্লট',
  // Không dùng từ đơn "satta"/"matka": trùng tên báo Ấn Độ (Loksatta, Jansatta) và tiếng Phần Lan ("matka" = chuyến đi)
  'satta king', 'satta matka', 'kalyan matka', 'matka result', 'disawar',
  'apostas esportivas', 'cassino', 'rodadas grátis', 'apuestas deportivas', 'casino en línea', 'tragamonedas', 'giros gratis',
  'казино', 'игровые автоматы', 'ставки на спорт', 'букмекер', 'фриспины',
  'bahis', 'canlı casino', 'deneme bonusu',
  'spielautomaten', 'freispiele', 'sportwetten', 'casino en ligne', 'paris sportifs', 'machines à sous',
  '카지노', '토토사이트', 'オンラインカジノ',
  'pokies', 'bookmaker', 'gamstop', 'no deposit bonus', 'welcome bonus', 'real money'
];
export const GAMBLING_CONTENT_MIN_HITS = 2;

// Nhà cái quốc tế/mới nổi có tên dễ trùng từ thông dụng -> chỉ khớp chính xác tên miền
const GAMBLING_EXACT_DOMAINS = new Set([
  'stake.com', 'stake.us', 'stake.bet', 'pinnacle.com', 'pinnacle888.com', 'bc.game', 'bwin.com', 'bovada.lv',
]);

// Tên nhà cái đặc trưng (>= 6 ký tự) - khớp ở bất kỳ vị trí nào trong tên miền, vd vietnambetway88.com
const GAMBLING_BRAND_SUBSTRINGS = [
  'betway', 'mostbet', 'melbet', 'parimatch', 'betfair', 'williamhill', 'ladbrokes', 'paddypower',
  'draftkings', 'fanduel', 'betmgm', 'pokerstars', 'betsson', 'leovegas', 'rollbit', 'roobet', 'betonline',
  'mybookie', 'sportsbet', 'unibet', 'hitclub', 'nhatvip', 'kubet88', 'xbet',
];

// Prohibited & Blacklisted Domains Under Vietnamese Law (Art. 321, 322 Criminal Code & Art. 8 Cybersecurity Law)
// and US UIGEA (31 U.S.C. § 5361) / Unlicensed Offshore Gambling Platforms
export const PROHIBITED_GAMBLING_BETTING_DOMAINS = new Set([
  'm88.com', 'm88', 'ms88.com', 'm88cvf.com', 'm88bet.com', 'm88so.com', 'm88link.com', 'm88vin.com', 'm88asia.com', 'm88u.com', 'm88id.com',
  'w88.com', 'w88', 'w88link.com', 'w88vn.com', 'w88yes.com', 'w88club.com', 'w88hcm.com', 'w88top.com', 'w88cuoc.com',
  '188bet.com', '188bet', '188betvn.com', '188betlink.com', '188bet.net', '188betup.com',
  'fun88.com', 'fun88', 'fun88vn.com', 'fun88link.com', 'fun88tl.com', 'fun88vi.com',
  'kubet.com', 'kubet', 'kucasino.com', 'kucasino', 'ku11.net', 'ku777.net', 'ku888.net', 'thabet.com', 'thabet', 'ku999.net',
  'bk8.com', 'bk8', 'bk8vn.com', 'bk8link.com', 'bk8live.com', 'bk8viet.com',
  'fb88.com', 'fb88', 'fb88vn.com', 'fb88link.com', 'fb88top.com', 'fb88en.com',
  '12bet.com', '12bet', '12betvn.com', '12betlink.com', '12betpro.com',
  'dafabet.com', 'dafabet', 'dafavn.com', 'dafabetlink.com',
  'b52.club', 'b52.vin', 'b52', 'b52club',
  'sunwin.club', 'sunwin.vn', 'sunwin.us', 'sunwin', 'sunwin20.club',
  'go88.info', 'go88.club', 'go88.vn', 'go88', 'go88c.club', 'go88vn.pro',
  'rikvip.club', 'rikvip.tip', 'rikvip',
  'iwin.club', 'iwin.net', 'iwin', 'iwin68.club',
  '789club.org', '789club.vin', '789club',
  'yo88.vin', 'yo88.club', 'yo88',
  'fa88.club', 'fa88.online', 'fa88',
  'manclub.vin', 'manclub',
  'sodo66.com', 'sodo66', 'sodo.com', 'sodo',
  'oxbet.com', 'oxbet', 'may88.com', 'may88',
  'sin88.com', 'sin88', 'red88.com', 'red88',
  'five88.com', 'five88', 'lucky88.com', 'lucky88',
  'zbet.com', 'zbet', 'fabet.com', 'fabet',
  'debet.com', 'debet', 'dabet.com', 'dabet',
  'sv388.com', 'sv388', 's128.net', 's128',
  'loto188.com', 'loto188',
  'k8.com', 'k8', 'v9bet.com', 'v9bet',
  'happyluke.com', 'happyluke',
  'vn88.com', 'vn88', 'jbo.com', 'jbo', 'jbo088.com',
  'mu9.com', 'mu9', 'ta88.com', 'ta88', 'sky88.com', 'sky88',
  'bong88.com', 'bong88', 'viva88.net', 'viva88.com', 'viva88',
  'sbobet.com', 'sbobet', 'ibet888.com', 'ibet888',
  'sclub88.com', 'bet365.com'
]);

// Tên miền đầy đủ trong danh sách đen (khớp chính xác hoặc subdomain)
const GAMBLING_BLACKLIST_DOMAINS = [...PROHIBITED_GAMBLING_BETTING_DOMAINS].filter(d => d.includes('.'));

// Tên miền cờ bạc rà soát thủ công trong Tranco: nhiều tên miền cũ bị mua lại nên vẫn được cộng điểm độ phổ biến.
// Thiếu hoặc lỗi file thì chỉ mất danh sách này, không được làm dừng máy chủ.
function loadAuditedGamblingDomains(): Set<string> {
  try {
    const file = path.resolve(process.env.GAMBLING_AUDIT_PATH || 'server/data/tranco-gambling-audit.txt');
    return new Set(fs.readFileSync(file, 'utf8').split('\n').map(l => l.trim().toLowerCase()).filter(l => l && !l.startsWith('#')));
  } catch (err: any) {
    console.warn(`[Domain Rules] Không đọc được danh sách cờ bạc đã rà soát (${err?.message || err}).`);
    return new Set();
  }
}
const AUDITED_GAMBLING_DOMAINS = loadAuditedGamblingDomains();

// Thương hiệu nhà cái (không kèm TLD) - khớp ở ĐẦU một nhãn tên miền, vd: m88vin.com, link-fb88.net, sunwin20.club
const GAMBLING_BRAND_TOKENS = [...new Set([
  ...[...PROHIBITED_GAMBLING_BETTING_DOMAINS].filter(d => !d.includes('.')),
  'ku11', 'ku777', 'ku888', 'ku999', 'b52club', 'yo88', 'sodo66', 'loto188', 'ibet888', 'fun88', 'vn88',
  // Thương hiệu cờ bạc trực tuyến nhắm tới người dùng Việt Nam xuất hiện gần đây
  'jun88', 'new88', 'hi88', 'f8bet', 'shbet', 'mb66', 'j88', 'okvip', '8kbet', 'tf88', 'qh88', 'oc88',
  'ae888', 'kubet11', 'zowin', 'gemwin', 'manvip', 'iwin68', 'sun52', 'go99', '79king', '8day', 'nbet',
])];

function labelMatchesBrand(part: string, brand: string): boolean {
  if (part.startsWith('vn') && part.length > 2 && labelMatchesBrand(part.slice(2), brand)) return true;
  if (!part.startsWith(brand)) return false;
  const rest = part.slice(brand.length);
  if (!rest) return true;
  // Thương hiệu đặc trưng (có chữ số và dài >= 3 như m88, fb88, 188bet; hoặc toàn chữ dài >= 5 như kubet, sunwin)
  // cho phép hậu tố tuỳ ý: m88vin, kubetvn. Thương hiệu ngắn/dễ trùng (k8, jbo, iwin, sodo) chỉ chấp nhận số theo sau,
  // để không bắt nhầm k8s.io, jboss.org, iwinsoft...
  if ((/\d/.test(brand) && brand.length >= 3) || (!/\d/.test(brand) && brand.length >= 5)) return true;
  return /^\d/.test(rest);
}

// Từ khoá cờ bạc trong TÊN MIỀN. Từ dài, đặc trưng: khớp ở bất kỳ đâu. Từ ngắn dễ trùng (slot, lode, sode, nohu):
// phải đứng riêng giữa các ranh giới (đầu/cuối nhãn, dấu chấm, gạch nối, chữ số) -> không bắt nhầm "episode", "explode".
const GAMBLING_HOST_WORDS_ANYWHERE = /(?:casino|baccarat|roulette|gambl|sportsbook|keo-?nha-?cai|ty-?le-?keo|nha-?cai|tai-?xiu|xoc-?dia|game-?bai|danh-?bai|ca-?cuoc|soi-?cau|quay-?hu|ban-?ca-?doi-?thuong|\d+bet|\d+club|club\d+|wingo)/;
const GAMBLING_HOST_WORDS_BOUNDED = /(?:^|[.\-_\d])(?:poker|slots?|lo-?de|so-?de|no-?hu|bet\d+|ibet\d*|ku\d+)(?=$|[.\-_\d])/;

// Từ khoá cờ bạc trong ĐƯỜNG DẪN URL - luôn yêu cầu ranh giới
const GAMBLING_PATH_REGEX = /(?:^|[\/\-_.])(?:keo-?nha-?cai|ty-?le-?keo|nha-?cai|tai-?xiu|xoc-?dia|game-?bai|danh-?bai|ca-?cuoc|soi-?cau|lo-de|so-de|quay-?hu|no-?hu|ban-?ca-?doi-?thuong|casino|baccarat|roulette)(?=$|[\/\-_.\d])/;

export function isTrustedHost(hostname: string): boolean {
  const host = (hostname || '').toLowerCase();
  if (!host) return false;
  for (const apex of TRUSTED_APEX_DOMAINS) {
    if (host === apex || host.endsWith('.' + apex)) return true;
  }
  // Toàn bộ tên miền chính phủ (.gov.vn / .gov / chinhphu.vn) và giáo dục (.edu.vn / .edu)
  return /\.(?:gov|edu)(?:\.vn)?$/.test(host) || host.endsWith('.chinhphu.vn');
}

// Nhận diện tên miền cờ bạc/cá cược chỉ dựa vào hostname
export function isGamblingHost(hostname: string): boolean {
  const host = (hostname || '').toLowerCase();
  if (!host) return false;
  if (GAMBLING_TLDS.some(tld => host.endsWith(tld))) return true;
  if (PROHIBITED_GAMBLING_BETTING_DOMAINS.has(host)) return true;
  const registrable = parseDomain(host).domain || host;
  if (GAMBLING_EXACT_DOMAINS.has(registrable)) return true;
  if (AUDITED_GAMBLING_DOMAINS.has(registrable) || AUDITED_GAMBLING_DOMAINS.has(host)) return true;
  if (GAMBLING_BRAND_SUBSTRINGS.some(brand => registrable.includes(brand))) return true;
  if (GAMBLING_BLACKLIST_DOMAINS.some(d => host === d || host.endsWith('.' + d))) return true;
  const parts = host.split('.').flatMap(label => [label, ...label.split('-').slice(1)]);
  if (parts.some(part => GAMBLING_BRAND_TOKENS.some(brand => labelMatchesBrand(part, brand)))) return true;
  return GAMBLING_HOST_WORDS_ANYWHERE.test(host) || GAMBLING_HOST_WORDS_BOUNDED.test(host);
}

export function countGamblingContentHits(pageContent: string): number {
  const content = (pageContent || '').toLowerCase();
  return GAMBLING_KEYWORDS_CONTENT.filter(kw => content.includes(kw)).length;
}

// Helper kiểm tra mục tiêu có dấu hiệu cờ bạc/cá độ hay không (hostname, đường dẫn và nội dung trang)
export function isGamblingTarget(targetUrl: string, hostname: string, pageContent: string): boolean {
  const host = (hostname || '').toLowerCase();
  // Tên miền uy tín (báo chí, chính phủ...) có thể đưa tin về cờ bạc - không phải trang cờ bạc
  if (isTrustedHost(host)) return false;
  if (isGamblingHost(host)) return true;

  let pathname = '';
  try {
    pathname = decodeURIComponent(new URL(targetUrl).pathname).toLowerCase();
  } catch {
    pathname = '';
  }
  if (GAMBLING_PATH_REGEX.test(pathname)) return true;

  // Tên miền có chữ "bet" (betvn, xbet...) chỉ cần 1 cụm từ cờ bạc trong nội dung; còn lại cần >= 2 cụm khác nhau
  const hits = countGamblingContentHits(pageContent);
  const label = parseDomain(host).domainWithoutSuffix || host;
  return hits >= GAMBLING_CONTENT_MIN_HITS || (hits >= 1 && label.includes('bet'));
}

// Khuôn shop giả hàng loạt: tiêu đề chỉ là chính tên miền, kèm câu miễn phí vận chuyển theo ngưỡng đơn hàng
const FREE_SHIPPING_THRESHOLD = /free shipping on (?:all )?orders? over|kostenloser versand ab|livraison gratuite d[eè]s|spedizione gratuita per ordini superiori|env[ií]o gratis (?:en pedidos )?(?:a partir de|desde)/i;

export function isFakeShopTemplate(title: string, text: string, ownerDomain: string): boolean {
  const compact = (v: string) => v.toLowerCase().replace(/[^a-z0-9]/g, '');
  const parts = parseDomain(ownerDomain);
  const label = compact(parts.domainWithoutSuffix || ownerDomain);
  const shownTitle = compact(title);
  if (!label || (shownTitle !== label && shownTitle !== compact(ownerDomain))) return false;
  return FREE_SHIPPING_THRESHOLD.test(text.slice(0, 400));
}

// Shop không minh bạch: tiêu đề chào giảm giá/outlet hoặc chỉ là tên miền, mà trang chủ không có liên hệ hay thông tin doanh nghiệp
const SALE_TITLE = /\b(?:sale|outlet|angebote?|rabatte?|g[üu]nstig\w*|kaufen sie|ofertas?|descuentos?|offres?|promo(?:tions?)?)\b|\bbis zu\b|\d{2}\s?%/i;
const SHOP_WORDS = /add to cart|shop now|track your order|warenkorb|kaufen|in den korb|panier|carrito|giỏ hàng|\bcart\b|\bshop\b/i;

export function isOpaqueShop(html: { title: string; text: string; contactInfo: boolean; taxId: boolean; moitBadge: boolean }, ownerDomain: string): boolean {
  if (html.contactInfo || html.taxId || html.moitBadge) return false;
  if (!SHOP_WORDS.test(`${html.title} ${html.text.slice(0, 1500)}`)) return false;
  const compact = (v: string) => v.toLowerCase().replace(/[^a-z0-9]/g, '');
  const label = compact(parseDomain(ownerDomain).domainWithoutSuffix || ownerDomain);
  return SALE_TITLE.test(html.title) || (!!label && compact(html.title) === label);
}

// Rao bán hàng cấm: chỉ khớp cụm từ mua bán trực tiếp, không khớp bài báo chỉ nhắc tới các mặt hàng này
const PROHIBITED_GOODS: Array<[string, RegExp]> = [
  ['súng/đạn', /\bbuy\b[^.\n]{0,40}\b(?:guns?|firearms?|handguns?|pistols?|rifles?|ammo|ammunition)\b[^.\n]{0,20}\bonline\b/i],
  ['cần sa', /\b(?:buy|order)\b[^.\n]{0,30}\b(?:weed|cannabis|marijuana)\b[^.\n]{0,25}\bonline\b|\bcannabis dispensary that ships\b|\bmail order (?:weed|marijuana)\b/i],
  ['bằng cấp/giấy tờ giả', /làm (?:bằng|giấy tờ|chứng chỉ)[^.\n]{0,25}giả[^.\n]{0,40}(?:giá|bao nhiêu|uy tín|liên hệ|dịch vụ|zalo)|\bbuy (?:a )?fake (?:diploma|degree|passport|id)\b|\bfake (?:diplomas?|passports?) for sale\b/i],
];

export function detectProhibitedGoods(title: string, text: string): string | null {
  const content = `${title}\n${text.slice(0, 2000)}`;
  return PROHIBITED_GOODS.find(([, re]) => re.test(content))?.[0] ?? null;
}

// Brands frequently targeted by typosquatting, deceptive subdomains, and credential theft
export const TARGETED_BRAND_NAMES = [
  'vietcombank', 'techcombank', 'bidv', 'agribank', 'mbbank', 'vpbank', 'sacombank',
  'shopee', 'lazada', 'tiki', 'vneid', 'dichvucong', 'momo', 'vnpay', 'zalopay',
  'facebook', 'google', 'apple', 'paypal', 'binance', 'netflix', 'microsoft',
  // Thương hiệu quốc tế bị giả mạo nhiều nhất trong các feed phishing (OpenPhish, PhishTank)
  'roblox', 'instagram', 'amazon', 'spotify', 'xfinity', 'whatsapp', 'telegram', 'discord', 'coinbase',
  'metamask', 'docusign', 'linkedin', 'tiktok', 'steamcommunity', 'wellsfargo', 'bankofamerica', 'usps', 'fedex'
];

// High-Risk TLDs frequently registered anonymously for phishing campaigns
// Danh sách dựa trên thống kê TLD bị lạm dụng nhiều nhất (Spamhaus / Interisle Phishing Landscape)
export const HIGH_RISK_TLDS = [
  '.xyz', '.top', '.vip', '.tk', '.cf', '.gq', '.ml', '.ga', '.cc', '.work', '.click', '.loan', '.fit', '.buzz',
  '.rest', '.bar', '.sbs', '.cyou', '.cfd', '.bond', '.icu', '.lat', '.monster', '.quest', '.autos', '.boats',
  '.hair', '.beauty', '.mom', '.skin', '.makeup', '.yachts', '.homes', '.zip', '.mov',
];

// High-risk keywords in HOSTNAME (not path) indicating credential harvesting or scams
export const PHISHING_HOST_KEYWORDS = [
  'xac-thuc', 'xacthuc', 'bank-otp', 'nhan-thuong', 'giam-gia-soc', '99k', 'dong-gia',
  'free-fire', 'nap-the', 'login-secure', 'verify-account', 'account-update', 'chuyen-khoan',
  'quatang', 'trung-thuong', 'tri-an', 'bao-mat-2fa',
  // Lừa đảo tiền mã hoá / "hỗ trợ khách hàng" giả
  'usdt', 'airdrop', 'walletconnect', 'wallet-connect', 'giveaway', 'claim-reward', 'recovery-phrase', 'kyc-verify',
];

/**
 * Tìm thương hiệu bị mạo danh trong hostname (không áp dụng cho tên miền uy tín).
 * So khớp theo từng nhãn/từ (tách bởi "." và "-") thay vì chuỗi con, tránh báo nhầm "pineapple" chứa "apple":
 * - Thương hiệu dài (>= 7 ký tự, vd vietcombank): xuất hiện ở bất kỳ đâu trong nhãn (myvietcombank)
 * - Thương hiệu ngắn (<= 4 ký tự, vd tiki, momo, bidv): nhãn phải đúng bằng tên (có thể kèm số)
 * - Còn lại: nhãn phải bắt đầu bằng tên thương hiệu (applestore, paypal-login)
 */
export function findImpersonatedBrand(hostname: string): string | undefined {
  const parts = (hostname || '').toLowerCase().split(/[.-]/).filter(Boolean);
  return TARGETED_BRAND_NAMES.find(brand => parts.some(part => {
    if (brand.length >= 7) return part.includes(brand);
    if (brand.length <= 4) return part === brand || new RegExp(`^${brand}\\d+$`).test(part);
    return part.startsWith(brand);
  }));
}

// ============================================================================
// PHÂN TÍCH CẤU TRÚC TÊN MIỀN (dùng cho chấm điểm theo bằng chứng)
// ============================================================================

// Nền tảng hosting/tên miền miễn phí nơi ai cũng tạo được subdomain ẩn danh trong vài giây.
// Phần lớn đã có trong mục "private" của Public Suffix List (vercel.app, pages.dev, github.io...);
// danh sách dưới đây bổ sung các nền tảng chưa có trong PSL.
const EXTRA_FREE_HOSTING_DOMAINS = [
  'kesug.com', 'rf.gd', 'epizy.com', 'infinityfreeapp.com', '42web.io', 'free.nf', 'staged-website.com',
  'meusitehostgator.com.br', 'mybluehost.me', 'hostingersite.com', 'weebly.com', 'weeblysite.com',
  'wixsite.com', 'godaddysites.com', 'square.site', 'mystrikingly.com', 'jimdosite.com', 'webcindario.com',
  '000webhostapp.com', 'yolasite.com', 'site123.me', 'webnode.page', 'tilda.ws', 'carrd.co', 'framer.website',
  'framer.app', 'typedream.app', 'notion.site', 'glitch.me', 'replit.app', 'repl.co', 'surge.sh',
  'ngrok-free.app', 'ngrok.io', 'ngrok.app', 'trycloudflare.com', 'workers.dev', 'r2.dev', 'ipfs.io',
  'dweb.link', 'w3s.link', 'fleek.co', '4everland.app', 'duckdns.org', 'ddns.net', 'hopto.org', 'zapto.org',
  'loca.lt', 'azurewebsites.net', 'onrender.com', 'fly.dev', 'railway.app', 'wordpress.com', 'plesk.page',
  'jimdofree.com', 'jimdo.com', 'edgeone.dev', 'edgeone.app', 'csb.app', 'codesandbox.io', 'stackblitz.io',
  'webflow.io', 'wixstudio.io', 'canva.site', 'business.site', 'gitbook.io', 'tiiny.site', 'neocities.org',
  'bitbucket.io', 'strikingly.com', 'webador.com', 'simplesite.com', 'zohosites.com', 'wuaze.com', 'ct.ws',
  'great-site.net', 'lovestoblog.com', 'unaux.com', 'ezyro.com', 'iceiy.com', 'gt.tc', 'page.gd', 'infy.uk',
  'myshopify.com', 'teachable.com', 'beehiiv.com', 'substack.com', 'blogspot.com', 'web.app', 'firebaseapp.com',
];

// Nền tảng mà tên tài khoản được xác thực theo tổ chức (GitHub/GitLab Pages):
// google.github.io thuộc đúng tổ chức "google" trên GitHub
const VERIFIED_ACCOUNT_PLATFORMS = ['github.io', 'gitlab.io'];

export interface DomainParts {
  host: string;
  /** Tên miền đăng ký theo ICANN, vd vercel.app, roblox.com.bi */
  icannDomain: string;
  /** Tên miền "thực sự" của chủ sở hữu, tính cả hậu tố private: omis-gules.vercel.app */
  ownerDomain: string;
  /** Nhãn chính của chủ sở hữu, vd "omis-gules", "roblox" */
  ownerLabel: string;
  publicSuffix: string;
  isFreeHosting: boolean;
  /** Trang trên GitHub/GitLab Pages (tên tài khoản do nền tảng xác thực) */
  onVerifiedAccountPlatform: boolean;
  /** Trang của tổ chức chính chủ trên nền tảng xác thực tài khoản, vd google.github.io, mozilla.github.io */
  isVerifiedBrandAccount: boolean;
  isIp: boolean;
  isIdn: boolean;
}

export function getDomainParts(hostname: string): DomainParts {
  const host = (hostname || '').toLowerCase().replace(/\.$/, '');
  const icann = parseDomain(host);
  const priv = parseDomain(host, { allowPrivateDomains: true });
  const icannDomain = icann.domain || host;
  const extraPlatform = EXTRA_FREE_HOSTING_DOMAINS.find(d => host.endsWith('.' + d));
  let ownerDomain = priv.domain || icannDomain;
  let ownerLabel = priv.domainWithoutSuffix || icann.domainWithoutSuffix || host;
  if (extraPlatform) {
    const sub = host.slice(0, -(extraPlatform.length + 1)).split('.').filter(l => l !== 'www');
    ownerLabel = sub[sub.length - 1] || ownerLabel;
    ownerDomain = `${ownerLabel}.${extraPlatform}`;
  }
  return {
    host,
    icannDomain,
    ownerDomain,
    ownerLabel,
    publicSuffix: priv.publicSuffix || icann.publicSuffix || '',
    isFreeHosting: (priv.isPrivate === true && !!priv.domainWithoutSuffix) || !!extraPlatform,
    onVerifiedAccountPlatform: VERIFIED_ACCOUNT_PLATFORMS.includes(priv.publicSuffix || ''),
    isVerifiedBrandAccount: VERIFIED_ACCOUNT_PLATFORMS.includes(priv.publicSuffix || '') && PROTECTED_LABEL_SET.has(ownerLabel),
    isIp: !!icann.isIp,
    isIdn: host.split('.').some(label => label.startsWith('xn--')),
  };
}

// Đổi các ký tự hay dùng để giả mạo về dạng gốc: vietc0mbank, paypa1, rnicrosoft -> microsoft
function normalizeHomoglyphs(label: string): string {
  return label
    .replace(/rn/g, 'm')
    .replace(/vv/g, 'w')
    .replace(/0/g, 'o')
    .replace(/[1!|]/g, 'l')
    .replace(/3/g, 'e')
    .replace(/4/g, 'a')
    .replace(/5/g, 's')
    .replace(/7/g, 't')
    .replace(/-/g, '');
}

function levenshtein(a: string, b: string, max: number): number {
  if (Math.abs(a.length - b.length) > max) return max + 1;
  let prev = Array.from({ length: b.length + 1 }, (_, i) => i);
  for (let i = 1; i <= a.length; i++) {
    const cur = [i];
    let rowMin = i;
    for (let j = 1; j <= b.length; j++) {
      cur[j] = Math.min(prev[j] + 1, cur[j - 1] + 1, prev[j - 1] + (a[i - 1] === b[j - 1] ? 0 : 1));
      rowMin = Math.min(rowMin, cur[j]);
    }
    if (rowMin > max) return max + 1;
    prev = cur;
  }
  return prev[b.length];
}

// Nhãn chính của các tên miền cần bảo vệ (thương hiệu + danh sách tin cậy), chỉ lấy nhãn >= 5 ký tự
const PROTECTED_LABELS = [...new Set([
  ...TARGETED_BRAND_NAMES,
  ...[...TRUSTED_APEX_DOMAINS].map(d => parseDomain(d).domainWithoutSuffix || ''),
])].filter(label => label.length >= 5 && !label.includes('.'));
const PROTECTED_LABEL_SET = new Set(PROTECTED_LABELS);

/**
 * Phát hiện typosquatting: nhãn tên miền gần giống một thương hiệu được bảo vệ nhưng không trùng khớp.
 * vd vietcornbank.com, faceb00k.net, shopeee.vn, robloxc.com.es
 */
export function findTyposquatTarget(ownerLabel: string): string | undefined {
  const label = ownerLabel.toLowerCase();
  if (label.length < 4) return undefined;
  if (PROTECTED_LABELS.includes(label)) return undefined;
  const normalized = normalizeHomoglyphs(label);
  for (const brand of PROTECTED_LABELS) {
    if (normalized === brand) return brand;
    const maxDist = brand.length >= 9 ? 2 : 1;
    if (Math.abs(label.length - brand.length) <= maxDist && levenshtein(normalized, brand, maxDist) <= maxDist) {
      return brand;
    }
  }
  return undefined;
}

export interface LabelShape {
  hyphens: number;
  digits: number;
  allDigits: boolean;
  length: number;
  longestConsonantRun: number;
  /** Số lần chuyển qua lại giữa chữ và số, vd "ra78utdo" = 2 */
  letterDigitSwitches: number;
  /** Nhãn trông như sinh tự động (nhiều gạch nối/chữ số đan xen/cụm phụ âm dài) */
  looksRandom: boolean;
}

export function analyzeLabelShape(label: string): LabelShape {
  const l = label.toLowerCase();
  const hyphens = (l.match(/-/g) || []).length;
  const digits = (l.match(/\d/g) || []).length;
  const letters = (l.match(/[a-z]/g) || []).length;
  const allDigits = /^\d+$/.test(l.replace(/-/g, ''));
  const longestConsonantRun = Math.max(0, ...(l.match(/[bcdfghjklmnpqrstvwxz]+/g) || []).map(run => run.length));
  const letterDigitSwitches = (l.replace(/-/g, '').match(/[a-z](?=\d)|\d(?=[a-z])/g) || []).length;
  const looksRandom =
    hyphens >= 3 ||
    (letterDigitSwitches >= 2 && l.length >= 6) ||
    (digits >= 4 && letters > 0) ||
    (digits >= 2 && letters > 0 && hyphens >= 2) ||
    longestConsonantRun >= 6;
  return { hyphens, digits, allDigits, length: l.length, longestConsonantRun, letterDigitSwitches, looksRandom };
}
