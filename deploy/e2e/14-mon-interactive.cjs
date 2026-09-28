// Monitoring console: click through every interactive feature.
const { launch, watch, shot, issues, signIn, secret } = require('./harness.cjs');
const O = 'http://monitoring.localhost:9002';
const results = [];

(async () => {
  const browser = await launch();
  const ctx = await browser.newContext({ acceptDownloads: true });
  const page = await ctx.newPage();
  watch(page, 'mon');
  let api = [];
  page.on('response', (r) => { if (/\/(api|bff)\//.test(r.url()) && !/version|events\/stream|\/bff\/session/.test(r.url())) api.push(`${r.status()} ${r.request().method()} ${new URL(r.url()).pathname}${new URL(r.url()).search.slice(0, 60)}`); });
  const step = async (name, fn) => {
    api = [];
    let ok = true, note = '';
    try { note = (await fn()) || ''; } catch (e) { ok = false; note = String(e).split('\n')[0].slice(0, 160); }
    const bad = api.filter((a) => /^[45]\d\d/.test(a));
    if (bad.length) ok = false;
    results.push([name, ok]);
    console.log(`${ok ? 'PASS' : 'FAIL'}  ${name}  ${note}  api=[${[...new Set(api)].join(', ')}]`);
    await shot(page, 'mon-i-' + name.toLowerCase().replace(/\W+/g, '-').slice(0, 40));
  };
  const go = async (p) => { await page.goto(O + p); await page.waitForLoadState('networkidle').catch(() => {}); await page.waitForTimeout(500); };
  const dialogText = async () => (await page.locator('[role=dialog]').count()) ? (await page.locator('[role=dialog]').last().innerText()).replace(/\s+/g, ' ').slice(0, 120) : '(no dialog)';

  await signIn(page, O, 'root@e2e.test', secret('root-pw.txt'));

  // Events: filter by severity, paginate, open a row's details, pivot to policy decisions.
  await step('events: next page', async () => { await go('/events'); await page.getByRole('button', { name: 'Next Page' }).click(); await page.waitForLoadState('networkidle'); });
  await step('events: filter by IP + apply', async () => {
    await go('/events'); await page.getByPlaceholder('Filter by IP').fill('127.0.0.1');
    await page.getByRole('button', { name: 'Apply Filters' }).click(); await page.waitForLoadState('networkidle');
    return `rows=${await page.locator('main tbody tr').count()}`;
  });
  await step('events: open details', async () => {
    await go('/events'); await page.locator('main tbody tr').first().click(); await page.waitForTimeout(600);
    return await dialogText();
  });
  await step('events: pivot to policy decisions', async () => {
    const link = page.locator('[role=dialog]').getByText(/policy decision/i).first();
    if (!(await link.count())) return 'no pivot link on this event';
    await link.click(); await page.waitForLoadState('networkidle');
    return page.url().replace(O, '');
  });

  // Threats: block the top IP (a test IP) → blocked IPs; then unblock.
  await step('blocked IPs: block an IP', async () => {
    await go('/blocked-ips'); await page.getByRole('button', { name: 'Block IP' }).click(); await page.waitForTimeout(500);
    const d = page.locator('[role=dialog]').last();
    const ip = d.locator('input').first(); await ip.fill('198.51.100.7');
    const reason = d.locator('input, textarea').nth(1); if (await reason.count()) await reason.fill('e2e from monitoring');
    await d.getByRole('button', { name: /block/i }).last().click(); await page.waitForLoadState('networkidle'); await page.waitForTimeout(500);
    return `listed=${(await page.locator('main').innerText()).includes('198.51.100.7')}`;
  });
  await step('blocked IPs: unblock', async () => {
    const row = page.locator('main tbody tr', { hasText: '198.51.100.7' });
    await row.getByRole('button').last().click(); await page.waitForTimeout(400);
    const confirm = page.locator('[role=dialog], [role=alertdialog]').getByRole('button', { name: /unblock|confirm|yes|remove/i });
    if (await confirm.count()) await confirm.last().click();
    await page.waitForLoadState('networkidle'); await page.waitForTimeout(500);
    return `still listed=${(await page.locator('main').innerText()).includes('198.51.100.7')}`;
  });
  await step('threats: block IP button opens a dialog', async () => {
    await go('/threats'); await page.getByRole('button', { name: 'Block IP' }).first().click(); await page.waitForTimeout(500);
    const t = await dialogText(); await page.keyboard.press('Escape'); return t;
  });

  // Alerts: create a rule, view history.
  await step('alerts: create rule', async () => {
    await go('/alerts'); await page.getByRole('button', { name: 'New Rule' }).click(); await page.waitForTimeout(500);
    const d = page.locator('[role=dialog]').last();
    const fields = await d.locator('input, textarea, select').evaluateAll((els) => els.map((e) => `${e.tagName.toLowerCase()}:${e.name || e.placeholder || e.id}`));
    await d.locator('input').first().fill('e2e brute force');
    await d.getByRole('button', { name: /create|save/i }).last().click(); await page.waitForLoadState('networkidle'); await page.waitForTimeout(500);
    return `fields=${JSON.stringify(fields).slice(0, 150)} | after: ${await dialogText()}`;
  });
  await step('alerts: history tab', async () => { await go('/alerts'); await page.getByRole('button', { name: 'ALERT HISTORY' }).click(); await page.waitForLoadState('networkidle'); return `rows=${await page.locator('main tbody tr').count()}`; });

  // Policy decisions: filter, details, pivot.
  await step('policy decisions: divergences only + apply', async () => {
    await go('/policy-decisions'); await page.getByText('Divergences only').click(); await page.getByRole('button', { name: 'Apply' }).click();
    await page.waitForLoadState('networkidle'); return `rows=${await page.locator('main tbody tr').count()}`;
  });
  await step('policy decisions: details + request pivot', async () => {
    await go('/policy-decisions'); await page.locator('main tbody tr').first().getByRole('button').last().click(); await page.waitForTimeout(500);
    const t = await dialogText();
    const piv = page.locator('[role=dialog]').getByText(/All decisions for this request/i);
    if (await piv.count()) { await piv.click(); await page.waitForLoadState('networkidle'); }
    return `${t} → ${page.url().replace(O, '')}`;
  });

  // Audit trail: filter + CSV export.
  await step('audit trail: filter', async () => {
    await go('/audit-logs'); await page.getByPlaceholder('e.g. unlock_user').fill('unlock_user');
    await page.getByRole('button', { name: 'Apply Filters' }).click(); await page.waitForLoadState('networkidle');
    return `rows=${await page.locator('main tbody tr').count()}`;
  });
  await step('audit trail: export CSV', async () => {
    const [dl] = await Promise.all([page.waitForEvent('download', { timeout: 10000 }), page.getByRole('button', { name: 'Export CSV' }).click()]);
    const p = await dl.path(); const txt = require('fs').readFileSync(p, 'utf8');
    return `file=${dl.suggestedFilename()} lines=${txt.split('\n').length} header=${txt.split('\n')[0].slice(0, 80)}`;
  });

  // Reports.
  await step('reports: last 7 days summary', async () => {
    await go('/reports'); await page.getByRole('button', { name: 'Last 7 Days Summary' }).click();
    await page.waitForLoadState('networkidle'); await page.waitForTimeout(1500);
    return (await page.locator('main').innerText()).replace(/\s+/g, ' ').slice(0, 160);
  });

  // Sign out.
  await step('settings: sign out', async () => {
    await go('/settings'); await page.getByRole('button', { name: 'Sign Out' }).click(); await page.waitForLoadState('networkidle'); await page.waitForTimeout(800);
    const s = await page.evaluate(async () => (await (await fetch('/bff/session')).json()).authenticated);
    return `url=${page.url().replace(O, '')} authenticated=${s}`;
  });

  await browser.close();
  console.log(`\n${results.filter(([, ok]) => ok).length}/${results.length} passed; browser issues: ${issues.length}`);
})();
