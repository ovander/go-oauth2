// Admin console: click through the interactive controls not covered by the
// write-API run (which drove the same endpoints without the UI).
const fs = require('fs');
const { launch, watch, shot, issues, signIn, secret } = require('./harness.cjs');
const O = 'http://admin.localhost:9001';
const erin = JSON.parse(fs.readFileSync(__dirname + '/erin.json', 'utf8'));
const results = [];

(async () => {
  const browser = await launch();
  const ctx = await browser.newContext({ acceptDownloads: true });
  const page = await ctx.newPage();
  watch(page, 'adm');
  let api = [];
  page.on('response', (r) => { if (/\/(api|bff)\//.test(r.url()) && !/version|\/bff\/session|\/api\/admin\/profile$/.test(r.url())) api.push(`${r.status()} ${r.request().method()} ${new URL(r.url()).pathname}${decodeURIComponent(new URL(r.url()).search).slice(0, 50)}`); });
  const go = async (p) => { await page.goto(O + p); await page.waitForLoadState('networkidle').catch(() => {}); await page.waitForTimeout(500); };
  const confirmDialog = async () => {
    await page.waitForTimeout(400);
    const dlg = page.locator('[role=dialog], [role=alertdialog]').last();
    if (!(await dlg.count())) return '(no confirm)';
    const t = (await dlg.innerText()).replace(/\s+/g, ' ').slice(0, 90);
    const pw = dlg.locator('input[type=password]');
    if (await pw.count()) { await pw.fill(secret('root-pw.txt')); }
    const b = dlg.getByRole('button').filter({ hasNotText: /cancel|close|no$/i }).last();
    await b.click(); await page.waitForLoadState('networkidle').catch(() => {}); await page.waitForTimeout(700);
    return t;
  };
  const step = async (name, fn) => {
    api = []; let ok = true, note = '';
    try { note = (await fn()) || ''; } catch (e) { ok = false; note = String(e).split('\n')[0].slice(0, 160); }
    if (api.some((a) => /^5\d\d/.test(a))) ok = false;
    results.push([name, ok]);
    console.log(`${ok ? 'PASS' : 'FAIL'}  ${name}  ${note}  api=[${[...new Set(api)].join(', ')}]`);
    await shot(page, 'adm-i-' + name.toLowerCase().replace(/\W+/g, '-').slice(0, 40));
  };

  await signIn(page, O, 'root@e2e.test', secret('root-pw.txt'));

  await step('dashboard: 30d trend', async () => { await go('/'); await page.getByRole('button', { name: '30d' }).click(); await page.waitForLoadState('networkidle'); });
  await step('dashboard: refresh health', async () => { await page.getByRole('button', { name: 'Refresh Health' }).click(); await page.waitForLoadState('networkidle'); });
  await step('apps: search', async () => {
    await go('/apps'); await page.getByPlaceholder('Search applications...').fill('demo'); await page.waitForTimeout(600);
    const t = await page.locator('main').innerText(); return `shows demo=${/E2E demo app/.test(t)} hides monitoring=${!/Monitoring console/.test(t)}`;
  });
  await step('app settings: add redirect URI + save', async () => {
    await go('/apps/3'); await page.getByRole('button', { name: 'Add URI' }).click();
    const inputs = page.locator('main input[placeholder*="callback"]'); await inputs.last().fill('http://app.localhost:9003/bff/callback2');
    await page.getByRole('button', { name: 'Save Changes' }).click(); await page.waitForLoadState('networkidle'); await page.waitForTimeout(500);
    return (await page.locator('body').innerText()).match(/(saved|updated|success|error|fail)[^\n]{0,60}/i)?.[0] || '';
  });
  await step('app settings: remove the extra URI + save', async () => {
    await go('/apps/3');
    const row = page.locator('main input[placeholder*="callback"]').last();
    await row.locator('xpath=ancestor::div[1]').getByRole('button').click();
    await page.getByRole('button', { name: 'Save Changes' }).click(); await page.waitForLoadState('networkidle'); await page.waitForTimeout(500);
  });
  await step('user detail: revoke all tokens', async () => { await go(`/users/${erin.user_id}`); await page.getByRole('button', { name: 'Revoke All Tokens' }).click(); return await confirmDialog(); });
  await step('user detail: block', async () => { await go(`/users/${erin.user_id}`); await page.getByRole('button', { name: 'Block User' }).click(); return await confirmDialog(); });
  await step('user detail: unlock', async () => { await go(`/users/${erin.user_id}`); await page.getByRole('button', { name: 'Unlock Account' }).click(); return await confirmDialog(); });
  await step('user detail: delete', async () => {
    await go(`/users/${erin.user_id}`); await page.getByRole('button', { name: 'Delete User' }).click(); const t = await confirmDialog();
    return `${t} → url=${page.url().replace(O, '')}`;
  });
  await step('security: go live', async () => { await go('/security'); await page.getByRole('button', { name: 'Go live' }).click(); await page.waitForTimeout(3000); return (await page.locator('main').innerText()).match(/(live|connected|paused|offline)[^\n]{0,40}/i)?.[0]; });
  await step('events: IP filter', async () => {
    await go('/security/events'); await page.getByPlaceholder('IP Address').fill('10.9.9.9'); await page.keyboard.press('Enter');
    await page.waitForLoadState('networkidle'); await page.waitForTimeout(800); return `rows=${await page.locator('main tbody tr').count()}`;
  });
  await step('sessions: filter by user', async () => {
    await go('/security/sessions'); await page.getByPlaceholder('User ID').fill('1'); await page.getByRole('button', { name: 'Apply' }).click();
    await page.waitForLoadState('networkidle'); return `rows=${await page.locator('main tbody tr').count()}`;
  });
  await step('blocked IPs: check an IP', async () => {
    await go('/security/blocked-ips'); await page.getByPlaceholder('e.g. 203.0.113.42').fill('203.0.113.42'); await page.getByRole('button', { name: 'Check' }).click();
    await page.waitForLoadState('networkidle'); await page.waitForTimeout(500);
    return (await page.locator('main').innerText()).match(/(not blocked|is blocked|blocked|clean|reputation)[^\n]{0,60}/i)?.[0];
  });
  await step('reports: generate', async () => {
    await go('/security/reports'); await page.getByRole('button', { name: 'Generate' }).click(); await page.waitForLoadState('networkidle'); await page.waitForTimeout(1500);
    return `rows=${await page.locator('main tbody tr').count()}`;
  });
  await step('logs: export', async () => {
    await go('/logs');
    const [dl] = await Promise.all([page.waitForEvent('download', { timeout: 10000 }), page.getByRole('button', { name: 'Export' }).click()]);
    const txt = fs.readFileSync(await dl.path(), 'utf8'); return `file=${dl.suggestedFilename()} lines=${txt.split('\n').length}`;
  });
  await step('settings: test connections', async () => { await go('/settings'); await page.getByRole('button', { name: 'Test Connections' }).click(); await page.waitForLoadState('networkidle'); await page.waitForTimeout(600); });
  await step('profile page', async () => { await go('/settings/profile'); return (await page.locator('main').innerText()).replace(/\s+/g, ' ').slice(0, 120); });
  await step('app detail: rotate secret (UI)', async () => {
    await go('/apps/3'); await page.getByRole('button', { name: 'Rotate Secret' }).click(); const t = await confirmDialog();
    const shown = (await page.locator('body').innerText()).match(/(secret|rotated)[^\n]{0,60}/gi); return `${t} | ${shown && shown.slice(-2).join(' / ')}`;
  });
  await browser.close();
  console.log(`\n${results.filter(([, ok]) => ok).length}/${results.length} passed; browser issues: ${issues.length}`);
})();
