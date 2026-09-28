// What does the monitoring console show after the defences fired?
const fs = require('fs');
const { launch, shot, signIn, secret } = require('./harness.cjs');
const O = 'http://monitoring.localhost:9002';
const d = JSON.parse(fs.readFileSync(__dirname + '/defenses.json', 'utf8'));

(async () => {
  const browser = await launch();
  const ctx = await browser.newContext({ viewport: { width: 1440, height: 1000 } });
  const page = await ctx.newPage();
  await signIn(page, O, 'root@e2e.test', secret('root-pw.txt'));
  const see = async (p, name, needles) => {
    await page.goto(O + p); await page.waitForLoadState('networkidle').catch(() => {}); await page.waitForTimeout(1200);
    const t = await page.locator('main').innerText();
    await shot(page, 'def-' + name);
    console.log(`${p.padEnd(18)} ` + needles.map((n) => `${n}=${t.includes(n) || new RegExp(n, 'i').test(t) ? 'yes' : 'NO'}`).join('  '));
    return t;
  };
  let t = await see('/', 'dashboard', ['Locked', 'Blocked', 'Failed']);
  console.log('   dashboard numbers:', (t.match(/(\d+)\s*\n?\s*(Failed Logins|Locked|Blocked IPs|Active Threats|Security Events)[^\n]*/gi) || []).slice(0, 6));
  await see('/events', 'events', ['Account Locked', 'Auto', 'Invalid Token', 'Client Auth', d.attacker]);
  await see('/threats', 'threats', [d.attacker, 'Brute', 'Suspicious', 'integrity']);
  await see('/blocked-ips', 'blocked-ips', [d.attacker, 'Automatic block', 'failed_login_threshold']);
  await see('/geo', 'geo', [d.attacker, '203.0.113']);
  await see('/alerts', 'alerts', ['e2e brute force']);
  await page.getByRole('button', { name: 'ALERT HISTORY' }).click(); await page.waitForTimeout(800);
  console.log('   alert history text:', (await page.locator('main').innerText()).replace(/\s+/g, ' ').slice(0, 160));
  await shot(page, 'def-alert-history');
  await see('/policy-decisions', 'policy', ['enforce', 'Refused', 'invoice.approve']);
  await browser.close();
})();
