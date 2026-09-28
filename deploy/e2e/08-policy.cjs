// Admin console → Access policy: simulate, edit (step-up), save v2, restore v1.
const { launch, watch, shot, issues, signIn, secret } = require('./harness.cjs');

(async () => {
  const browser = await launch();
  const ctx = await browser.newContext();
  const page = await ctx.newPage();
  watch(page, 'policy');
  const api = [];
  page.on('response', async (r) => {
    if (/\/(api|bff)\//.test(r.url()) && r.request().method() !== 'GET') {
      let b = ''; try { b = (await r.text()).slice(0, 200); } catch {}
      api.push(`${r.status()} ${r.request().method()} ${new URL(r.url()).pathname} ${b}`);
    }
  });
  await signIn(page, 'http://admin.localhost:9001', 'root@e2e.test', secret('root-pw.txt'));
  await ctx.storageState({ path: __dirname + '/admin-state.json' });
  await page.goto('http://admin.localhost:9001/security/policy');
  await page.waitForLoadState('networkidle');

  // 1. Simulate the default request.
  await page.getByPlaceholder(/DELETE \/api\/admin\/apps/).first().fill('DELETE /api/admin/apps/{id}');
  await page.getByRole('button', { name: /^Simulate$/ }).click();
  await page.waitForTimeout(1000);
  const simText = (await page.locator('main').innerText()).match(/(Allow|Deny|allowed|denied)[^\n]{0,120}/g);
  console.log('simulate result:', simText && simText.slice(-3));
  await shot(page, '60-policy-simulate');

  // 2. Edit rules.
  await page.getByRole('button', { name: /Edit rules/ }).click();
  await page.waitForTimeout(800);
  await shot(page, '61-policy-edit');
  const editorBits = (await page.locator('main button').allInnerTexts()).map((t) => t.trim()).filter(Boolean);
  console.log('editor buttons:', editorBits);
  const ta = await page.locator('main textarea').evaluateAll((els) => els.map((e) => `${e.name || e.id || e.placeholder}:${e.value.length}`));
  console.log('textareas:', ta);
  // Change one rule's description (a harmless edit), validate, save as v2.
  const editor = page.locator('main textarea').first();
  const json = JSON.parse(await editor.inputValue());
  const rules = Array.isArray(json) ? json : json.rules;
  console.log('rule ids:', rules.map((r) => r.id || r.name));
  rules[0].description = (rules[0].description || '') + ' [e2e edit]';
  await editor.fill(JSON.stringify(json, null, 2));
  await page.getByRole('button', { name: /^Validate$/ }).click();
  await page.waitForTimeout(800);
  console.log('validate:', ((await page.locator('main').innerText()).match(/(valid|error|invalid)[^\n]{0,100}/gi) || []).slice(0, 3));
  await page.getByRole('button', { name: /Save as new version/ }).click();
  await page.waitForTimeout(1500);
  await shot(page, '62-policy-save');
  const dlg = page.locator('[role=dialog]');
  console.log('dialog after save:', (await dlg.count()) ? (await dlg.first().innerText()).replace(/\s+/g, ' ').slice(0, 300) : '(none)');
  console.log('api so far:', api);
  await browser.close();
  console.log('issues:', issues.length);
})();
