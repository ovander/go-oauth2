// Monitoring console: sign in through Socrate, then visit every page.
const { launch, watch, shot, secret, issues } = require('./harness.cjs');

async function signIn(page, origin, email, password) {
  await page.goto(origin + '/');
  await page.waitForLoadState('networkidle');
  console.log('landing:', page.url());
  const btn = page.getByRole('button', { name: /sign in|log in|login/i }).first();
  await btn.click();
  await page.waitForURL(/auth\.localhost:9000/, { timeout: 15000 });
  await page.locator('input[name=email]').fill(email);
  await page.locator('input[name=password]').fill(password);
  await page.locator('button[type=submit]').first().click();
  await page.waitForLoadState('networkidle');
  if (/Authorize Access/.test(await page.locator('body').innerText())) {
    await page.getByRole('button', { name: /^Allow$/ }).click();
  }
  await page.waitForURL((u) => u.origin === origin, { timeout: 20000 });
  await page.waitForLoadState('networkidle');
}

(async () => {
  const O = 'http://monitoring.localhost:9002';
  const browser = await launch();
  const ctx = await browser.newContext();
  const page = await ctx.newPage();
  watch(page, 'mon');
  const api = [];
  page.on('response', (r) => { if (/\/(api|bff)\//.test(r.url())) api.push(`${r.status()} ${r.request().method()} ${new URL(r.url()).pathname}`); });

  await signIn(page, O, 'root@e2e.test', secret('root-pw.txt'));
  console.log('signed in at:', page.url());
  await shot(page, '20-mon-home');
  const nav = await page.locator('nav a, aside a, header a').evaluateAll((els) => [...new Set(els.map((e) => e.getAttribute('href')).filter((h) => h && h.startsWith('/')))]);
  console.log('nav:', nav);
  await ctx.storageState({ path: __dirname + '/mon-state.json' });

  for (const p of nav) {
    const before = issues.length; api.length = 0;
    await page.goto(O + p);
    await page.waitForLoadState('networkidle').catch(() => {});
    await page.waitForTimeout(700);
    await shot(page, 'mon' + (p === '/' ? '-home' : p.replace(/\//g, '-')));
    const h = (await page.locator('h1, h2').first().innerText().catch(() => '?')).trim();
    console.log(`${p.padEnd(24)} h="${h}" api=[${[...new Set(api)].filter((a) => !/version|session|profile/.test(a)).join(', ')}] newIssues=${issues.length - before}`);
  }
  await browser.close();
  console.log('total issues:', issues.length);
})();
