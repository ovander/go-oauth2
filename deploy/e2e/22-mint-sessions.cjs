// Mint real BFF sessions (admin console + demo app) for the load tests.
const fs = require('fs');
const { launch, signIn, secret } = require('./harness.cjs');
(async () => {
  const b = await launch(); const out = {};
  for (const [name, origin, email, pw] of [['admin', 'http://admin.localhost:9001', 'root@e2e.test', secret('root-pw.txt')], ['demo', 'http://app.localhost:9003', 'alice@e2e.test', secret('alice-pw.txt')]]) {
    const c = await b.newContext(); const p = await c.newPage();
    if (name === 'demo') {
      await p.goto(origin + '/bff/login'); await p.waitForURL(/auth\.localhost/);
      await p.locator('input[name=email]').fill(email); await p.locator('input[name=password]').fill(pw); await p.locator('button[type=submit]').first().click(); await p.waitForLoadState('networkidle');
      if (/Authorize Access/.test(await p.locator('body').innerText())) await p.getByRole('button', { name: /^Allow$/ }).click();
      await p.waitForURL((u) => u.origin === origin);
    } else { await signIn(p, origin, email, pw); }
    const ck = (await c.cookies()).filter((x) => x.domain.startsWith(name === 'admin' ? 'admin' : 'app'));
    const csrf = await p.evaluate(async () => (await (await fetch('/bff/session')).json()).csrf);
    out[name] = { cookie: ck.map((x) => `${x.name}=${x.value}`).join('; '), csrf };
  }
  fs.writeFileSync(__dirname + '/sessions.json', JSON.stringify(out)); console.log('sessions:', Object.keys(out).map((k) => `${k}: ${out[k].cookie.split('=')[0]}`)); await b.close();
})();
