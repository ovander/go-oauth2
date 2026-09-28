// Consent deny (first login of Carol to the demo app) and BFF auto-refresh
// after the 30 s access token expires.
const fs = require('fs');
const { launch, watch, shot, issues } = require('./harness.cjs');
const O = 'http://app.localhost:9003';
const carol = JSON.parse(fs.readFileSync(__dirname + '/carol.json', 'utf8'));

async function toLogin(page) {
  await page.goto(O + '/bff/login');
  await page.waitForURL(/auth\.localhost:9000/);
  await page.locator('input[name=email]').fill(carol.email);
  await page.locator('input[name=password]').fill(carol.password);
  await page.locator('button[type=submit]').first().click();
  await page.waitForLoadState('networkidle');
}
const call = (page, m, p, c) => page.evaluate(async ([m, p, c]) => {
  const r = await fetch(p, { method: m, credentials: 'include', headers: c ? { 'X-CSRF-Token': c } : {} });
  let b = await r.text(); try { b = JSON.parse(b); } catch {} return { status: r.status, body: b };
}, [m, p, c]);

(async () => {
  const browser = await launch();
  // 1. Consent: Deny.
  let ctx = await browser.newContext(); let page = await ctx.newPage(); watch(page, 'consent');
  await toLogin(page);
  const onConsent = /Authorize Access/.test(await page.locator('body').innerText());
  console.log('consent screen shown to a first-time user:', onConsent);
  if (onConsent) {
    await page.getByRole('button', { name: /^Deny$/ }).click();
    await page.waitForLoadState('networkidle');
    console.log('after Deny:', page.url().replace(/state=[^&]+/, 'state=…'), '|', (await page.locator('body').innerText()).slice(0, 160));
    const s = await call(page, 'GET', '/bff/session');
    console.log('session after deny:', JSON.stringify(s.body));
  }
  await ctx.close();

  // 2. Allow, then outlive the 30 s access token; the BFF must refresh on its own.
  ctx = await browser.newContext(); page = await ctx.newPage(); watch(page, 'refresh');
  await toLogin(page);
  if (/Authorize Access/.test(await page.locator('body').innerText())) await page.getByRole('button', { name: /^Allow$/ }).click();
  await page.waitForURL((u) => u.origin === O);
  console.log('me (fresh):', JSON.stringify(await call(page, 'GET', '/api/me')));
  console.log('waiting 35 s for the access token to expire…');
  await page.waitForTimeout(35000);
  console.log('me (after expiry, BFF should refresh):', JSON.stringify(await call(page, 'GET', '/api/me')));
  // Second login in the same browser: consent remembered?
  const c2 = await browser.newContext(); const p2 = await c2.newPage();
  await toLogin(p2);
  console.log('consent asked again on second login:', /Authorize Access/.test(await p2.locator('body').innerText()));
  await browser.close();
  console.log('issues:', issues.length);
})();
