// Alice: accept the emailed invite, set a password, then try both consoles.
const fs = require('fs');
const path = require('path');
const { launch, watch, shot, issues, signIn } = require('./harness.cjs');

const mailDir = path.join(__dirname, 'mail');
const inviteMail = fs.readdirSync(mailDir).map((f) => fs.readFileSync(path.join(mailDir, f), 'utf8')).find((m) => /To: alice@e2e\.test/.test(m) && /invited/i.test(m));
const link = inviteMail.match(/href="(http:\/\/auth\.localhost:9000\/auth\/invite\?token=[^"]+)"/)[1].replace(/&amp;/g, '&');
const ALICE_PW = 'Alice-E2e-' + Date.now().toString(36) + '!Qz';
fs.writeFileSync(path.join(__dirname, 'alice-pw.txt'), ALICE_PW);

(async () => {
  const browser = await launch();
  const ctx = await browser.newContext();
  const page = await ctx.newPage();
  watch(page, 'alice');

  await page.goto(link);
  await page.waitForLoadState('networkidle');
  await shot(page, '50-invite-page');
  const inputs = await page.locator('input').evaluateAll((els) => els.map((e) => `${e.type}:${e.name}`));
  console.log('invite page inputs:', inputs);
  for (const n of ['password', 'password_confirm', 'new_password', 'password_confirmation', 'confirm_password', 'confirm']) {
    const loc = page.locator(`input[name=${n}]`);
    if (await loc.count()) await loc.fill(ALICE_PW);
  }
  const name = page.locator('input[name=name]');
  if (await name.count() && !(await name.inputValue())) await name.fill('Alice Example');
  await page.locator('button[type=submit]').first().click();
  await page.waitForLoadState('networkidle');
  await shot(page, '51-invite-accepted');
  console.log('after accept:', page.url(), '|', (await page.locator('body').innerText()).replace(/\s+/g, ' ').slice(0, 200));

  for (const [label, origin] of [['monitoring', 'http://monitoring.localhost:9002'], ['admin', 'http://admin.localhost:9001']]) {
    const c = await browser.newContext();
    const p = await c.newPage();
    watch(p, 'alice-' + label);
    const apiStatus = [];
    p.on('response', (r) => { if (/\/(api|bff)\//.test(r.url())) apiStatus.push(`${r.status()} ${new URL(r.url()).pathname}`); });
    try {
      await signIn(p, origin, 'alice@e2e.test', ALICE_PW);
    } catch (e) {
      console.log(`${label}: sign-in did not return to the console: ${String(e).split('\n')[0]}`);
    }
    await p.waitForTimeout(800);
    await shot(p, `52-alice-${label}`);
    const text = (await p.locator('body').innerText()).replace(/\s+/g, ' ');
    console.log(`${label}: url=${p.url()} | ${text.slice(0, 220)}`);
    console.log(`${label}: api=${[...new Set(apiStatus)].join(', ')}`);
    // Direct probe of an admin API endpoint with Alice's session.
    await p.goto(origin + '/').catch(() => {});
    const st = await p.evaluate(async () => (await fetch('/api/admin/users', { credentials: 'include' })).status).catch((e) => 'err ' + e);
    console.log(`${label}: GET /api/admin/users from the page with Alice's cookies -> ${st}`);
    await c.close();
  }
  await browser.close();
  console.log('issues:', issues.length);
})();
