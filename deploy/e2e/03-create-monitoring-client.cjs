// Runbook §5.3: register the monitoring console's confidential client from the admin UI.
const fs = require('fs');
const { launch, watch, shot, issues } = require('./harness.cjs');

(async () => {
  const browser = await launch();
  const ctx = await browser.newContext({ storageState: __dirname + '/admin-state.json' });
  const page = await ctx.newPage();
  watch(page, 'admin');
  const api = [];
  page.on('response', async (r) => {
    if (/\/api\/admin\/apps/.test(r.url()) && r.request().method() !== 'GET') {
      let body = ''; try { body = await r.text(); } catch {}
      api.push({ status: r.status(), method: r.request().method(), path: new URL(r.url()).pathname, body });
    }
  });

  await page.goto('http://admin.localhost:9001/apps');
  await page.waitForLoadState('networkidle');
  const btns = await page.locator('button, a').allInnerTexts();
  console.log('apps page actions:', btns.map((b) => b.trim()).filter(Boolean).slice(0, 30));
  await page.getByRole('button', { name: /(new|create|add|register).*(app|application|client)|^(new|create|add)$/i }).first().click();
  await page.waitForTimeout(800);
  await shot(page, '10-create-app-form');
  const fields = await page.locator('input, textarea, select').evaluateAll((els) =>
    els.filter((e) => e.offsetParent !== null).map((e) => `${e.tagName.toLowerCase()}:${e.type || ''}:${e.name || e.id || e.placeholder || ''}:${e.closest('label')?.innerText?.trim()?.slice(0, 40) || e.labels?.[0]?.innerText?.trim()?.slice(0, 40) || ''}`));
  console.log('form fields:', fields);
  await page.getByLabel(/Application Name/).fill('Monitoring console (BFF)');
  await page.getByLabel(/Application URL/).fill('http://monitoring.localhost:9002');
  await page.getByPlaceholder('https://myapp.example.com/callback').fill('http://monitoring.localhost:9002/bff/callback');
  await page.getByRole('button', { name: /Create Application/ }).click();
  await page.waitForLoadState('networkidle');
  await page.waitForTimeout(800);
  await shot(page, '11-app-created');
  console.log('after create url:', page.url());
  console.log((await page.locator('main').innerText()).replace(/[A-Za-z0-9_-]{30,}/g, '<long-value>').slice(0, 700));
  for (const a of api) {
    console.log('API', a.status, a.method, a.path);
    if (a.status === 201) {
      const d = JSON.parse(a.body);
      fs.writeFileSync(__dirname + '/app-monitoring.json', a.body);
      console.log('created:', { id: d.id, client_id: d.client_id, is_public: d.is_public, require_pkce: d.require_pkce, redirect_uris: d.redirect_uris, secret_len: (d.client_secret || '').length });
    }
  }
  // Is the one-time secret shown on the page (it must be, the API won't return it again)?
  const created = api.find((a) => a.status === 201);
  if (created) {
    const sec = JSON.parse(created.body).client_secret;
    const html = await page.content();
    const inputs = await page.locator('input').evaluateAll((els) => els.map((e) => e.value));
    console.log('secret visible on page:', html.includes(sec) || inputs.includes(sec));
  }
  await browser.close();
  console.log('issues:', issues.length);
})();
