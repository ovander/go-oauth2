// Shared Playwright harness for the local e2e run: launches Chromium, records
// console errors, CSP violations, failed/5xx requests per page, and takes
// screenshots into shots/.
const path = require('path');
const fs = require('fs');
const { chromium } = require('/home/user/oauth2-admin/node_modules/@playwright/test');

const E = __dirname;
const SHOTS = path.join(E, 'shots');
fs.mkdirSync(SHOTS, { recursive: true });

const issues = [];
function note(kind, msg) {
  issues.push({ kind, msg });
  console.log(`  [${kind}] ${msg}`);
}

async function launch() {
  const browser = await chromium.launch({ executablePath: '/opt/pw-browsers/chromium' });
  return browser;
}

function watch(page, label) {
  page.on('console', (m) => {
    if (m.type() === 'error' || m.type() === 'warning') note(`${label}:console.${m.type()}`, m.text().slice(0, 300));
  });
  page.on('pageerror', (e) => note(`${label}:pageerror`, String(e).slice(0, 300)));
  page.on('requestfailed', (r) => {
    const f = r.failure();
    if (f && !/ERR_ABORTED/.test(f.errorText)) note(`${label}:requestfailed`, `${r.method()} ${r.url()} ${f.errorText}`);
  });
  page.on('response', (r) => {
    if (r.status() >= 400) note(`${label}:http${r.status()}`, `${r.request().method()} ${r.url().replace(/(code|state|code_challenge|token)=[^&]+/g, '$1=…')}`);
  });
}

async function shot(page, name) {
  const p = path.join(SHOTS, `${name}.png`);
  await page.screenshot({ path: p, fullPage: true });
  return p;
}

function secret(name) {
  return fs.readFileSync(path.join(E, name), 'utf8').trim();
}

// RFC 6238 TOTP (SHA-1, 6 digits, 30 s) for MFA enrolment/step-up.
function totp(base32, t = Date.now()) {
  const crypto = require('crypto');
  const alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
  let bits = '';
  for (const c of base32.replace(/=+$/, '').toUpperCase()) bits += alphabet.indexOf(c).toString(2).padStart(5, '0');
  const key = Buffer.from(bits.match(/.{8}/g).map((b) => parseInt(b, 2)));
  const ctr = Buffer.alloc(8);
  ctr.writeBigUInt64BE(BigInt(Math.floor(t / 1000 / 30)));
  const h = crypto.createHmac('sha1', key).update(ctr).digest();
  const o = h[h.length - 1] & 0xf;
  return String(((h.readUInt32BE(o) & 0x7fffffff) % 1e6)).padStart(6, '0');
}

// Full browser sign-in to a console through Socrate's hosted login (+consent).
// Every browser login reaches Socrate from Caddy (127.0.0.1), so all runs share
// one per-IP budget (login and consent submissions both count); on a 429 we
// wait the window out and start over.
async function signIn(page, origin, email, password, tries = 4) {
  const limited = async () => /too_many_requests|rate limit exceeded/i.test(await page.locator('body').innerText());
  await page.goto(origin + '/');
  await page.waitForLoadState('networkidle');
  await page.getByRole('button', { name: /sign in|log in|login/i }).first().click();
  await page.waitForURL(/auth\.localhost:9000/, { timeout: 15000 });
  if (!(await limited())) {
    await page.locator('input[name=email]').fill(email);
    await page.locator('input[name=password]').fill(password);
    await page.locator('button[type=submit]').first().click();
    await page.waitForLoadState('networkidle');
    if (/Authorize Access/.test(await page.locator('body').innerText())) {
      await page.getByRole('button', { name: /^Allow$/ }).click();
      await page.waitForLoadState('networkidle');
    }
  }
  if (await limited()) {
    if (tries <= 1) throw new Error('rate limited');
    await page.waitForTimeout(61000);
    return signIn(page, origin, email, password, tries - 1);
  }
  await page.waitForURL((u) => u.origin === origin, { timeout: 20000 });
  await page.waitForLoadState('networkidle');
}

module.exports = { signIn, launch, watch, shot, note, issues, secret, totp, E };
