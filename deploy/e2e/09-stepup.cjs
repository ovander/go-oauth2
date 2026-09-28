// Step-up: with a 20 s freshness window, restore policy v1 after the window
// has passed — the console must ask for re-authentication, then succeed.
const { launch, watch, shot, issues, signIn, secret } = require('./harness.cjs');

(async () => {
  const browser = await launch();
  const ctx = await browser.newContext();
  const page = await ctx.newPage();
  watch(page, 'stepup');
  const api = [];
  page.on('response', async (r) => {
    if (/\/(api|bff)\//.test(r.url()) && r.request().method() !== 'GET') {
      let b = ''; try { b = (await r.text()).slice(0, 160); } catch {}
      api.push(`${r.status()} ${r.request().method()} ${new URL(r.url()).pathname} ${b}`);
    }
  });
  await signIn(page, 'http://admin.localhost:9001', 'root@e2e.test', secret('root-pw.txt'));
  await page.goto('http://admin.localhost:9001/security/policy');
  await page.waitForLoadState('networkidle');
  console.log('waiting 25 s for the freshness window to lapse…');
  await page.waitForTimeout(25000);

  // Restore v1 from History (row action).
  const row = page.locator('tr', { hasText: 'baseline' });
  const rowButtons = await row.locator('button').evaluateAll((els) => els.map((e) => e.getAttribute('aria-label') || e.title || e.innerText));
  console.log('v1 row buttons:', rowButtons);
  await row.locator('button').nth(1).click();
  await page.waitForTimeout(800);
  await shot(page, '70-restore-click');
  const findDialog = async () => ((await page.locator('[role=dialog]').count()) ? (await page.locator('[role=dialog]').last().innerText()).replace(/\s+/g, ' ').slice(0, 300) : '(none)');
  console.log('dialog 1:', await findDialog());
  const restoreBtn = page.getByRole('button', { name: /restore/i }).last();
  if (await restoreBtn.count()) { await restoreBtn.click(); await page.waitForTimeout(1500); }
  await shot(page, '71a-after-confirm');
  const d2 = await findDialog();
  console.log('dialog after confirm:', d2);
  // Step-up: re-enter the password if the console asks for it.
  const pw = page.locator('[role=dialog] input[type=password]');
  if (await pw.count()) {
    await pw.fill(secret('root-pw.txt'));
    await page.locator('[role=dialog]').getByRole('button', { name: /confirm|verify|continue|re-?auth|submit/i }).last().click();
    await page.waitForTimeout(2000);
  }
  await shot(page, '71-after-restore');
  console.log('dialog 2:', await findDialog());
  console.log('api:', api);
  await browser.close();
  console.log('issues:', issues.length);
})();
