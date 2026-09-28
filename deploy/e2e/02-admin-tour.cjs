// Visit every admin-console page with the saved session; record issues.
const { launch, watch, shot, issues } = require('./harness.cjs');

const PAGES = ['/', '/apps', '/users', '/security', '/security/events', '/security/sessions',
  '/security/blocked-ips', '/security/alerts', '/security/reports', '/security/policy', '/logs', '/settings'];

(async () => {
  const browser = await launch();
  const ctx = await browser.newContext({ storageState: __dirname + '/admin-state.json' });
  const page = await ctx.newPage();
  watch(page, 'admin');
  const apiCalls = [];
  page.on('response', (r) => { if (/\/(api|bff)\//.test(r.url())) apiCalls.push(`${r.status()} ${r.request().method()} ${new URL(r.url()).pathname}`); });

  for (const p of PAGES) {
    const before = issues.length;
    apiCalls.length = 0;
    await page.goto('http://admin.localhost:9001' + p);
    await page.waitForLoadState('networkidle');
    await page.waitForTimeout(500);
    const name = 'tour' + (p === '/' ? '-dashboard' : p.replace(/\//g, '-'));
    await shot(page, name);
    const h = (await page.locator('h1, h2').first().innerText().catch(() => '?')).trim();
    const errText = (await page.locator('body').innerText()).match(/(error|failed|unable|forbidden|not found)[^\n]{0,80}/i);
    console.log(`${p.padEnd(22)} url=${new URL(page.url()).pathname.padEnd(22)} h="${h}" api=[${[...new Set(apiCalls)].join(', ')}] ${errText ? 'TEXT:"' + errText[0] + '"' : ''} newIssues=${issues.length - before}`);
  }
  await browser.close();
  console.log('total issues:', issues.length);
})();
