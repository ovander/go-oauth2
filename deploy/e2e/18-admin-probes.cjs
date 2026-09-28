const { launch, signIn, secret } = require('./harness.cjs');
const O = 'http://admin.localhost:9001';
(async () => {
  const browser = await launch(); const ctx = await browser.newContext(); const page = await ctx.newPage();
  let api = []; page.on('request', (r) => { if (/\/api\/admin\//.test(r.url())) api.push(`${r.method()} ${new URL(r.url()).pathname}${decodeURIComponent(new URL(r.url()).search)}`); });
  await signIn(page, O, 'root@e2e.test', secret('root-pw.txt'));
  await page.goto(O + '/'); await page.waitForLoadState('networkidle'); await page.waitForTimeout(800); api = [];
  await page.getByRole('button', { name: '30d' }).click(); await page.waitForTimeout(1500);
  console.log('30d toggle →', api);
  api = []; await page.getByRole('button', { name: 'Refresh Health' }).click(); await page.waitForTimeout(1500);
  console.log('Refresh Health →', api);
  await page.goto(O + '/security/sessions'); await page.waitForLoadState('networkidle'); await page.waitForTimeout(800); api = [];
  await page.getByPlaceholder('User ID').fill('1'); await page.waitForTimeout(300);
  await page.getByRole('button', { name: 'Apply' }).click(); await page.waitForTimeout(1500);
  console.log('Sessions filter user_id=1 →', api);
  await page.getByPlaceholder('User ID').press('Enter'); await page.waitForTimeout(1500);
  console.log('…after Enter →', api);
  await browser.close();
})();
