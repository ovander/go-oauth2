// Inventory the interactive controls of every monitoring page.
const { launch, issues, signIn, secret } = require('./harness.cjs');
const O = 'http://monitoring.localhost:9002';
const PAGES = ['/', '/events', '/threats', '/geo', '/sessions', '/tokens', '/alerts', '/blocked-ips', '/policy-decisions', '/audit-logs', '/reports', '/settings'];

(async () => {
  const browser = await launch();
  const ctx = await browser.newContext();
  const page = await ctx.newPage();
  await signIn(page, O, 'root@e2e.test', secret('root-pw.txt'));
  await ctx.storageState({ path: __dirname + '/mon-state.json' });
  for (const p of PAGES) {
    await page.goto(O + p); await page.waitForLoadState('networkidle').catch(() => {}); await page.waitForTimeout(600);
    const inv = await page.locator('main').evaluate((m) => {
      const vis = (e) => e.offsetParent !== null;
      const txt = (e) => (e.innerText || e.getAttribute('aria-label') || e.title || e.placeholder || e.name || '').trim().replace(/\s+/g, ' ').slice(0, 30);
      return {
        buttons: [...new Set([...m.querySelectorAll('button')].filter(vis).map(txt).filter(Boolean))].slice(0, 25),
        inputs: [...m.querySelectorAll('input,select,textarea')].filter(vis).map((e) => `${e.tagName.toLowerCase()}:${txt(e)}`).slice(0, 15),
        rows: m.querySelectorAll('tbody tr').length,
      };
    }).catch((e) => ({ err: String(e) }));
    console.log(`${p}\n   buttons: ${JSON.stringify(inv.buttons)}\n   inputs: ${JSON.stringify(inv.inputs)}  rows=${inv.rows}`);
  }
  await browser.close();
})();
