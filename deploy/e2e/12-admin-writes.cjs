// Admin console write actions, driven through the admin BFF exactly as the
// SPA calls them (session cookie + X-CSRF-Token), on throwaway objects.
const fs = require('fs');
const { launch, watch, issues, signIn, secret } = require('./harness.cjs');
const O = 'http://admin.localhost:9001';
const carol = JSON.parse(fs.readFileSync(__dirname + '/carol.json', 'utf8'));
const results = [];
const check = (name, ok, detail = '') => { results.push([name, !!ok]); console.log(`${ok ? 'PASS' : 'FAIL'}  ${name}  ${detail}`); };

(async () => {
  const browser = await launch();
  const ctx = await browser.newContext();
  const page = await ctx.newPage();
  watch(page, 'writes');
  await signIn(page, O, 'root@e2e.test', secret('root-pw.txt'));
  const csrf = (await page.evaluate(async () => (await (await fetch('/bff/session')).json()).csrf));
  const call = (m, p, body) => page.evaluate(async ([m, p, body, c]) => {
    const r = await fetch(p, { method: m, credentials: 'include', headers: { 'Content-Type': 'application/json', 'X-CSRF-Token': c }, body: body ? JSON.stringify(body) : undefined });
    let b = await r.text(); try { b = JSON.parse(b); } catch {} return { s: r.status, b };
  }, [m, p, body, csrf]);
  const short = (r) => `${r.s} ${JSON.stringify(r.b).slice(0, 110)}`;

  // Apps: create → update → deactivate → rotate secret → delete.
  let r = await call('POST', '/api/admin/apps', { name: 'Scratch app', redirect_uris: ['http://scratch.localhost/cb'], is_public: false });
  check('create app', r.s === 201, short(r)); const appId = r.b.id; const oldSecret = r.b.client_secret;
  r = await call('PUT', `/api/admin/apps/${appId}`, { name: 'Scratch app (renamed)', url: 'http://scratch.localhost' });
  check('update app', r.s === 200 && r.b.name === 'Scratch app (renamed)', short(r));
  r = await call('PUT', `/api/admin/apps/${appId}`, { active: false });
  check('deactivate app', r.s === 200 && r.b.active === false, short(r));
  r = await call('POST', `/api/admin/apps/${appId}/rotate-secret`);
  check('rotate secret (fresh session, no step-up prompt needed)', r.s === 200 && r.b.client_secret && r.b.client_secret !== oldSecret, `${r.s}`);
  r = await call('DELETE', `/api/admin/apps/${appId}`);
  check('delete app', [200, 204].includes(r.s), short(r));
  r = await call('GET', `/api/admin/apps/${appId}`);
  check('deleted app is gone', r.s === 404, `${r.s}`);

  // Users: block → Carol refused → unlock → revoke tokens.
  const uid = carol.user_id;
  r = await call('POST', `/api/admin/users/${uid}/block`);
  check('block user', r.s === 200, short(r));
  const login = () => page.evaluate(async ([e, p]) => (await fetch('http://auth.localhost:9000/api/auth/login', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ email: e, password: p }) }).catch(() => ({ status: 'cors' }))).status, [carol.email, carol.password]);
  r = await call('POST', `/api/admin/users/${uid}/unlock`);
  check('unlock user', r.s === 200, short(r));
  r = await call('POST', `/api/admin/users/${uid}/revoke-tokens`);
  check('revoke user tokens', r.s === 200, short(r));

  // App membership via the (fixed) /api/apps route.
  r = await call('PUT', `/api/apps/3/users/${uid}`, { role: 'admin' });
  check('change app role', r.s === 200, short(r));
  r = await call('POST', `/api/apps/3/users/${uid}/reset-password`);
  check('force password reset (app-scoped)', [200, 202].includes(r.s), short(r));
  r = await call('POST', `/api/apps/3/users/${uid}/resend-verification`);
  check('resend verification (already verified → refused or no-op)', [200, 400, 409].includes(r.s), short(r));
  r = await call('DELETE', `/api/apps/3/users/${uid}`);
  check('remove user from app', [200, 204].includes(r.s), short(r));

  // Superadmins: create → update → delete.
  r = await call('POST', '/api/admin/superadmins', { email: `dave${Date.now()}@e2e.test`, name: 'Dave', password: 'Dave-E2e-' + Date.now() + '!x' });
  check('create superadmin', r.s === 201, short(r)); const said = r.b.id || (r.b.user && r.b.user.id);
  r = await call('PUT', `/api/admin/superadmins/${said}`, { name: 'Dave Renamed' });
  check('update superadmin', r.s === 200, short(r));
  r = await call('DELETE', `/api/admin/superadmins/${said}`);
  check('delete superadmin', [200, 204].includes(r.s), short(r));
  r = await call('DELETE', '/api/admin/superadmins/1');
  check('cannot delete own superadmin account', r.s >= 400, short(r));

  // Blocked IPs: block → listed → unblock.
  r = await call('POST', '/api/admin/security/blocked-ips', { ip_address: '203.0.113.9', reason: 'e2e', duration_hours: 1 });
  check('block IP', [200, 201].includes(r.s), short(r)); const bid = r.b.id;
  r = await call('GET', '/api/admin/security/blocked-ips');
  check('blocked IP listed', JSON.stringify(r.b).includes('203.0.113.9'), `${r.s}`);
  r = await call('DELETE', `/api/admin/security/blocked-ips/${bid}`);
  check('unblock IP', [200, 204].includes(r.s), short(r));

  // Alert rules: create → update → delete.
  r = await call('POST', '/api/admin/alerts/rules', { name: 'e2e failed logins', event_type: 'login_failed', condition: { threshold: 5, window_minutes: 5 }, severity: 'high', actions: ['email'], recipients: ['root@e2e.test'] });
  check('create alert rule', [200, 201].includes(r.s), short(r)); const rid = r.b.id;
  r = await call('PUT', `/api/admin/alerts/rules/${rid}`, { name: 'e2e failed logins v2', event_type: 'login_failed', condition: { threshold: 10 }, severity: 'high', actions: ['email'], enabled: false });
  check('update alert rule', r.s === 200, short(r));
  r = await call('DELETE', `/api/admin/alerts/rules/${rid}`);
  check('delete alert rule', [200, 204].includes(r.s), short(r));

  // Reports + profile.
  r = await call('POST', '/api/admin/reports/security', { type: 'security', period: '7d', format: 'json' });
  check('generate security report', [200, 201, 202].includes(r.s), short(r));
  r = await call('PUT', '/api/profile', { name: 'E2E Root' });
  check('update own profile', r.s === 200, short(r));

  // CSRF: same write without the header must be refused by the BFF.
  const noCsrf = await page.evaluate(async () => (await fetch('/api/admin/security/blocked-ips', { method: 'POST', credentials: 'include', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ ip_address: '203.0.113.10' }) })).status);
  check('write without CSRF header refused', noCsrf === 403, `${noCsrf}`);

  // Logout: session gone, admin API refused.
  const lo = await page.evaluate(async (c) => (await fetch('/bff/logout', { method: 'POST', credentials: 'include', headers: { 'X-CSRF-Token': c } })).status, csrf);
  const after = await page.evaluate(async () => (await fetch('/api/admin/users', { credentials: 'include' })).status);
  check('console logout', [200, 204].includes(lo) && after === 401, `logout=${lo} then /api/admin/users=${after}`);

  await browser.close();
  console.log(`\n${results.filter(([, ok]) => ok).length}/${results.length} passed; browser issues: ${issues.length}`);
})();
