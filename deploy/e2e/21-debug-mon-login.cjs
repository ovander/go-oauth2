const { launch, shot, secret } = require('./harness.cjs');
(async () => {
  const b = await launch(); const c = await b.newContext(); const p = await c.newPage();
  await p.goto('http://monitoring.localhost:9002/'); await p.waitForLoadState('networkidle');
  await p.getByRole('button', { name: /sign in|log in|login/i }).first().click();
  await p.waitForURL(/auth\.localhost:9000/, { timeout: 15000 });
  await p.locator('input[name=email]').fill('root@e2e.test'); await p.locator('input[name=password]').fill(secret('root-pw.txt'));
  await p.locator('button[type=submit]').first().click(); await p.waitForLoadState('networkidle'); await p.waitForTimeout(1500);
  console.log('url:', p.url().replace(/(code|state)=[^&]+/g, '$1=…')); console.log((await p.locator('body').innerText()).replace(/\s+/g, ' ').slice(0, 300));
  await p.getByRole('button', { name: /^Allow$/ }).click(); await p.waitForLoadState('networkidle'); await p.waitForTimeout(1500);
  console.log('after allow:', p.url().replace(/(code|state)=[^&]+/g, '$1=…')); console.log((await p.locator('body').innerText()).replace(/\s+/g, ' ').slice(0, 300));
  await shot(p, '99-debug-mon-login'); await b.close();
})();
