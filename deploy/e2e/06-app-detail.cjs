// Admin console → Applications → app detail: which tabs work?
const { launch, watch, shot, issues } = require('./harness.cjs');

(async () => {
  const browser = await launch();
  const ctx = await browser.newContext({ storageState: __dirname + '/admin-state.json' });
  const page = await ctx.newPage();
  watch(page, 'admin');
  const api = [];
  page.on('response', (r) => { if (/\/api\//.test(r.url()) && !/version|profile/.test(r.url())) api.push(`${r.status()} ${r.request().method()} ${new URL(r.url()).pathname}`); });

  await page.goto('http://admin.localhost:9001/apps/2');
  await page.waitForLoadState('networkidle');
  await page.waitForTimeout(600);
  await shot(page, '40-app-detail');
  const tabs = (await page.locator('[role=tab], main nav button, main nav a').allInnerTexts()).map((t) => t.trim()).filter(Boolean);
  console.log('url:', page.url(), 'tabs:', tabs);
  console.log('api:', [...new Set(api)]);
  for (const t of tabs) {
    api.length = 0;
    await page.getByRole('tab', { name: t }).or(page.locator('main nav').getByText(t, { exact: true })).first().click().catch(() => {});
    await page.waitForLoadState('networkidle'); await page.waitForTimeout(500);
    const err = (await page.locator('main').innerText()).match(/(fail|error|unable|could not)[^\n]{0,80}/i);
    console.log(`tab ${t.padEnd(14)} api=[${[...new Set(api)].join(', ')}] ${err ? 'ERR:"' + err[0] + '"' : ''}`);
    await shot(page, '41-app-tab-' + t.toLowerCase().replace(/\W+/g, '-'));
  }
  await browser.close();
  console.log('issues:', issues.length);
})();
