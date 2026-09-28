// Demo app (backendkit): login, API, policy, service call, logout — as Alice
// (member) and as root (superadmin, not a member of this app).
const { launch, watch, shot, issues, secret } = require('./harness.cjs');
const O = 'http://app.localhost:9003';

async function login(page, email, pw) {
  await page.goto(O + '/bff/login');
  await page.waitForURL(/auth\.localhost:9000/);
  await page.locator('input[name=email]').fill(email);
  await page.locator('input[name=password]').fill(pw);
  await page.locator('button[type=submit]').first().click();
  await page.waitForLoadState('networkidle');
  if (/Authorize Access/.test(await page.locator('body').innerText())) await page.getByRole('button', { name: /^Allow$/ }).click();
  await page.waitForLoadState('networkidle');
}

async function call(page, method, path, csrf) {
  return page.evaluate(async ([m, p, c]) => {
    const r = await fetch(p, { method: m, credentials: 'include', headers: c ? { 'X-CSRF-Token': c } : {} });
    let body = await r.text(); try { body = JSON.parse(body); } catch {}
    return { status: r.status, body };
  }, [method, path, csrf]);
}

(async () => {
  const browser = await launch();
  for (const [who, email, pw] of [['alice', 'alice@e2e.test', secret('alice-pw.txt')], ['root', 'root@e2e.test', secret('root-pw.txt')]]) {
    console.log(`\n=== ${who}`);
    const ctx = await browser.newContext();
    const page = await ctx.newPage();
    watch(page, 'demo-' + who);
    await login(page, email, pw);
    console.log('after login:', page.url(), '|', (await page.locator('body').innerText()).replace(/\s+/g, ' ').slice(0, 120));
    await shot(page, `80-demo-${who}`);
    const sess = await call(page, 'GET', '/bff/session');
    console.log('session:', JSON.stringify(sess.body).replace(/"csrf":"[^"]+"/, '"csrf":"…"'));
    if (!sess.body.authenticated) { await ctx.close(); continue; }
    const csrf = sess.body.csrf;
    console.log('GET /api/me:', JSON.stringify(await call(page, 'GET', '/api/me')));
    console.log('POST approve (no CSRF):', JSON.stringify(await call(page, 'POST', '/api/invoices/inv-42/approve')));
    console.log('POST approve (CSRF):', JSON.stringify(await call(page, 'POST', '/api/invoices/inv-42/approve', csrf)));
    console.log('POST nightly job (app decides):', JSON.stringify(await call(page, 'POST', '/api/jobs/nightly', csrf)));
    console.log('GET service/whoami (client_credentials):', JSON.stringify(await call(page, 'GET', '/api/service/whoami')).slice(0, 200));
    console.log('logout:', JSON.stringify(await call(page, 'POST', '/bff/logout', csrf)));
    console.log('GET /api/me after logout:', JSON.stringify(await call(page, 'GET', '/api/me')));
    await ctx.close();
  }
  await browser.close();
  console.log('issues:', issues.length);
})();
