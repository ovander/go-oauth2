// Targeted probes of monitoring behaviours the click-through could not prove.
const { launch, shot, signIn, secret } = require('./harness.cjs');
const O = 'http://monitoring.localhost:9002';

(async () => {
  const browser = await launch();
  const ctx = await browser.newContext();
  const page = await ctx.newPage();
  let api = [];
  page.on('request', (r) => { if (/\/api\/admin\//.test(r.url()) && !/stream/.test(r.url())) api.push(`${r.method()} ${new URL(r.url()).pathname}${decodeURIComponent(new URL(r.url()).search)}`); });
  const go = async (p) => { await page.goto(O + p); await page.waitForLoadState('networkidle').catch(() => {}); await page.waitForTimeout(600); };
  const firstRow = async () => (await page.locator('main tbody tr').first().innerText().catch(() => '')).replace(/\s+/g, ' ').slice(0, 70);
  await signIn(page, O, 'root@e2e.test', secret('root-pw.txt'));

  console.log('== 5. reports');
  await go('/reports'); api = [];
  await page.getByRole('button', { name: 'Last 7 Days Summary' }).click(); await page.waitForTimeout(1500);
  console.log('  after "Last 7 Days Summary": requests=', api, 'dialog=', (await page.locator('[role=dialog]').count()) ? (await page.locator('[role=dialog]').last().innerText()).replace(/\s+/g, ' ').slice(0, 200) : 'none');
  await shot(page, '90-mon-reports-quick');
  api = [];
  await page.getByRole('dialog').getByLabel('Generate Report').click(); await page.waitForTimeout(2500);
  console.log('  after dialog "Generate Report": requests=', api, '| page:', (await page.locator('main').innerText()).replace(/\s+/g, ' ').slice(150, 420), '| dialog=', (await page.locator('[role=dialog]').count()) ? (await page.locator('[role=dialog]').last().innerText()).replace(/\s+/g, ' ').slice(0, 200) : 'none');
  await shot(page, '91-mon-reports-generate');

  console.log('== 6. alert rule create (with event type)');
  await go('/alerts'); await page.getByRole('button', { name: 'New Rule' }).click(); await page.waitForTimeout(500);
  const d = page.locator('[role=dialog]').last();
  await d.locator('input').first().fill('e2e brute force');
  await d.getByText('Select event type').click(); await page.waitForTimeout(300);
  const opts = (await page.getByRole('option').allInnerTexts()).map((t) => t.trim());
  console.log('  event type options:', opts.slice(0, 20));
  await page.getByRole('option').filter({ hasText: /fail/i }).first().click();
  api = [];
  await d.getByRole('button', { name: /^Create$/ }).click(); await page.waitForTimeout(1200);
  console.log('  requests:', api, 'rules rows:', await page.locator('main tbody tr').count());
  await shot(page, '92-mon-alert-created');
  await browser.close();
})();
