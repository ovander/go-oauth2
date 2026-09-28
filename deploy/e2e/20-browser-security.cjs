// Browser-side security: headers, cookies, CSP, stored XSS rendering,
// clickjacking, session fixation, and submit-time /oauth/authorize validation.
const fs = require('fs');
const { launch, shot, signIn, secret } = require('./harness.cjs');
const results = [];
const check = (n, ok, d = '') => { results.push([n, !!ok]); console.log(`${ok ? 'PASS' : 'FAIL'}  ${n}  ${d}`); };
const env = Object.fromEntries(fs.readFileSync(__dirname + '/demoapp.env', 'utf8').trim().split('\n').map((l) => l.split(/=(.*)/s).slice(0, 2)));

(async () => {
  const browser = await launch();

  // 1. Security headers per origin.
  const ctx0 = await browser.newContext(); const p0 = await ctx0.newPage();
  for (const [name, url] of [['auth (hosted login)', 'http://auth.localhost:9000/auth/login'], ['admin SPA', 'http://admin.localhost:9001/'], ['monitoring SPA', 'http://monitoring.localhost:9002/'], ['demo app', 'http://app.localhost:9003/']]) {
    const r = await p0.goto(url); const h = r.headers();
    const csp = h['content-security-policy'] || '';
    console.log(`   ${name}: CSP=${csp ? 'yes' : 'NO'} frame=${/frame-ancestors/.test(csp) ? 'csp' : (h['x-frame-options'] || 'NONE')} nosniff=${h['x-content-type-options'] || 'NONE'} referrer=${h['referrer-policy'] || 'NONE'} server=${h['server'] || '-'}`);
    check(`${name}: clickjacking protection`, /frame-ancestors\s+'none'|frame-ancestors\s+'self'/.test(csp) || /DENY|SAMEORIGIN/i.test(h['x-frame-options'] || ''));
    check(`${name}: nosniff`, h['x-content-type-options'] === 'nosniff');
  }
  await ctx0.close();

  // 2. Cookies after login (flags) + session fixation.
  const ctx = await browser.newContext(); const page = await ctx.newPage();
  await ctx.addCookies([{ name: 'admin_session', value: 'attacker-chosen-session-id', domain: 'admin.localhost', path: '/' }]);
  await signIn(page, 'http://admin.localhost:9001', 'root@e2e.test', secret('root-pw.txt'));
  const cookies = await ctx.cookies();
  for (const c of cookies) console.log(`   cookie ${c.domain} ${c.name}: httpOnly=${c.httpOnly} sameSite=${c.sameSite} secure=${c.secure} path=${c.path}`);
  const sess = cookies.find((c) => c.name === 'admin_session');
  check('admin session cookie HttpOnly + SameSite=Strict', sess && sess.httpOnly && sess.sameSite === 'Strict');
  check('session fixation: pre-set session id replaced at login', sess && sess.value !== 'attacker-chosen-session-id', `value changed=${sess && sess.value !== 'attacker-chosen-session-id'}`);
  const jsSees = await page.evaluate(() => document.cookie);
  check('no session material readable by JS', !/session/.test(jsSees), `document.cookie="${jsSees}"`);
  const stored = await page.evaluate(() => JSON.stringify({ ls: Object.keys(localStorage), ss: Object.keys(sessionStorage) }));
  check('no tokens in web storage', !/eyJ/.test(await page.evaluate(() => JSON.stringify(localStorage) + JSON.stringify(sessionStorage))), stored);

  // 3. Stored XSS: an app name and a user name with payloads, rendered by the consoles.
  const csrf = await page.evaluate(async () => (await (await fetch('/bff/session')).json()).csrf);
  const payload = `<img src=x onerror="window.__xss=1">"><script>window.__xss=2</script>`;
  const mk = await page.evaluate(async ([c, n]) => (await fetch('/api/admin/apps', { method: 'POST', headers: { 'Content-Type': 'application/json', 'X-CSRF-Token': c }, body: JSON.stringify({ name: n, redirect_uris: ['http://xss.localhost/cb'], is_public: false }) })).json(), [csrf, payload]);
  await page.goto('http://admin.localhost:9001/apps'); await page.waitForLoadState('networkidle'); await page.waitForTimeout(800);
  await page.goto(`http://admin.localhost:9001/apps/${mk.id}`); await page.waitForLoadState('networkidle'); await page.waitForTimeout(800);
  check('admin console: stored XSS in app name not executed', await page.evaluate(() => window.__xss === undefined));
  const mon = await browser.newContext(); const mp = await mon.newPage();
  await signIn(mp, 'http://monitoring.localhost:9002', 'root@e2e.test', secret('root-pw.txt'));
  for (const p of ['/events', '/audit-logs', '/']) { await mp.goto('http://monitoring.localhost:9002' + p); await mp.waitForLoadState('networkidle').catch(() => {}); await mp.waitForTimeout(600); }
  await mp.locator('main tbody tr').first().click().catch(() => {}); await mp.waitForTimeout(600);
  check('monitoring console: stored XSS via event details not executed', await mp.evaluate(() => window.__xss === undefined));
  await page.evaluate(async ([c, id]) => fetch(`/api/admin/apps/${id}`, { method: 'DELETE', headers: { 'X-CSRF-Token': c } }), [csrf, mk.id]);

  // 4. CSP actually enforced: inject an inline script from the page context.
  const blocked = await page.evaluate(() => new Promise((res) => {
    let v = false; document.addEventListener('securitypolicyviolation', () => { v = true; });
    const s = document.createElement('script'); s.textContent = 'window.__inline=1'; document.body.appendChild(s);
    setTimeout(() => res({ ran: window.__inline === 1, violation: v }), 300);
  }));
  check('admin CSP blocks injected inline script', !blocked.ran && blocked.violation, JSON.stringify(blocked));

  // 5. /oauth/authorize invalid requests: rejected at submit time?
  const bad = [['PKCE plain', { code_challenge: 'abc', code_challenge_method: 'plain' }], ['no PKCE', {}], ['response_type=token', { response_type: 'token' }]];
  for (const [label, extra] of bad) {
    const c2 = await browser.newContext(); const p2 = await c2.newPage();
    const q = new URLSearchParams({ response_type: 'code', client_id: env.SOCRATE_CLIENT_ID, redirect_uri: 'http://app.localhost:9003/bff/callback', scope: 'openid', state: 's1', ...extra });
    await p2.goto('http://auth.localhost:9000/oauth/authorize?' + q.toString());
    await p2.locator('input[name=email]').fill('alice@e2e.test'); await p2.locator('input[name=password]').fill(secret('alice-pw.txt'));
    await p2.locator('button[type=submit]').first().click(); await p2.waitForLoadState('networkidle');
    if (/Authorize Access/.test(await p2.locator('body').innerText())) { await p2.getByRole('button', { name: /^Allow$/ }).click().catch(() => {}); await p2.waitForLoadState('networkidle'); }
    const u = p2.url();
    const gotCode = /[?&]code=/.test(u);
    check(`authorize ${label}: no code issued`, !gotCode, u.replace(/code=[^&]+/, 'code=…').slice(0, 140));
    await c2.close();
  }
  await browser.close();
  console.log(`\n${results.filter(([, ok]) => ok).length}/${results.length} passed`);
})();
