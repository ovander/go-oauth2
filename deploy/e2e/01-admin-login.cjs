// Exploratory: admin console → hosted login → back to the console.
const { launch, watch, shot, secret, issues } = require('./harness.cjs');

(async () => {
  const browser = await launch();
  const ctx = await browser.newContext();
  const page = await ctx.newPage();
  watch(page, 'admin');

  await page.goto('http://admin.localhost:9001/');
  await page.getByRole('button', { name: /Sign in with Socrate/i }).click();
  await page.waitForLoadState('networkidle');
  console.log('after click:', page.url().replace(/code_challenge=[^&]+/, 'code_challenge=…').replace(/state=[^&]+/, 'state=…'));
  await shot(page, '02-hosted-login');
  const inputs = await page.locator('input').evaluateAll((els) => els.map((e) => `${e.type}:${e.name || e.id}`));
  console.log('inputs:', inputs);
  console.log((await page.locator('body').innerText()).slice(0, 300));

  await page.locator('input[type=email], input[name=email]').first().fill('root@e2e.test');
  await page.locator('input[type=password]').first().fill(secret('root-pw.txt'));
  await Promise.all([
    page.waitForURL(/admin\.localhost:9001/, { timeout: 20000 }).catch(() => {}),
    page.locator('button[type=submit], input[type=submit]').first().click(),
  ]);
  await page.waitForLoadState('networkidle');
  console.log('after login:', page.url());
  if (/Authorize Access/.test(await page.locator('body').innerText())) {
    await shot(page, '03a-consent');
    await Promise.all([
      page.waitForURL(/admin\.localhost:9001/, { timeout: 20000 }),
      page.getByRole('button', { name: /^Allow$/ }).click(),
    ]);
    await page.waitForLoadState('networkidle');
    console.log('after consent:', page.url());
  }
  await shot(page, '03-after-login');
  console.log((await page.locator('body').innerText()).slice(0, 600));
  const links = await page.locator('nav a, aside a').evaluateAll((els) => els.map((e) => `${e.innerText.trim()} -> ${e.getAttribute('href')}`));
  console.log('nav:', links);
  const cookies = await ctx.cookies();
  console.log('cookies:', cookies.map((c) => `${c.domain}:${c.name} httpOnly=${c.httpOnly} sameSite=${c.sameSite}`));
  await ctx.storageState({ path: __dirname + '/admin-state.json' });

  await browser.close();
  console.log('issues:', issues.length);
})();
