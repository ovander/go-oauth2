// Admin console → Users: discover and run the create/invite flow.
const fs = require('fs');
const { launch, watch, shot, issues, signIn, secret } = require('./harness.cjs');

(async () => {
  const browser = await launch();
  const ctx = await browser.newContext();
  const page = await ctx.newPage();
  watch(page, 'admin');
  const api = [];
  page.on('response', async (r) => {
    if (/\/api\//.test(r.url()) && r.request().method() !== 'GET') {
      let b = ''; try { b = (await r.text()).slice(0, 300); } catch {}
      api.push(`${r.status()} ${r.request().method()} ${new URL(r.url()).pathname} ${b}`);
    }
  });

  await signIn(page, 'http://admin.localhost:9001', 'root@e2e.test', secret('root-pw.txt'));
  await ctx.storageState({ path: __dirname + '/admin-state.json' });
  await page.goto('http://admin.localhost:9001/users');
  await page.waitForLoadState('networkidle');
  const actions = (await page.locator('main button, main a').allInnerTexts()).map((s) => s.trim()).filter(Boolean);
  console.log('users actions:', actions.slice(0, 20));
  const create = page.locator('main').getByRole('button', { name: /invite|create|add|new/i }).first();
  console.log('clicking:', await create.innerText());
  await create.click();
  await page.waitForTimeout(800);
  await shot(page, '30-user-create');
  const fields = await page.locator('input, select, textarea').evaluateAll((els) => els.filter((e) => e.offsetParent !== null)
    .map((e) => `${e.tagName.toLowerCase()}:${e.type || ''}:${e.name || e.id || ''}:${e.placeholder || ''}:${e.labels?.[0]?.innerText?.trim() || ''}`));
  console.log('fields:', fields);
  const selects = await page.locator('select').evaluateAll((els) => els.filter((e) => e.offsetParent !== null).map((e) => [...e.options].map((o) => o.value)));
  console.log('select options:', JSON.stringify(selects));
  const dialogButtons = (await page.locator('[role=dialog] button, form button').allInnerTexts()).map((s) => s.trim()).filter(Boolean);
  console.log('dialog buttons:', dialogButtons);
  await page.getByPlaceholder('user@example.com').fill('alice@e2e.test');
  await page.getByPlaceholder('Full name').fill('Alice Example');
  await page.getByText('Select an application...').click();
  await page.waitForTimeout(300);
  const opts = (await page.getByRole('option').allInnerTexts().catch(() => [])).map((t) => t.trim());
  console.log('app options:', opts);
  await page.getByText('Monitoring console (BFF)', { exact: true }).last().click();
  await page.getByRole('button', { name: 'Send Invite' }).click();
  await page.waitForLoadState('networkidle');
  await page.waitForTimeout(1500);
  await shot(page, '31-user-invited');
  const toast = (await page.locator('body').innerText()).match(/(invit|sent|success|error|fail)[^\n]{0,100}/gi);
  console.log('page messages:', toast);
  await browser.close();
  console.log('api:', api, 'issues:', issues.length);
})();
