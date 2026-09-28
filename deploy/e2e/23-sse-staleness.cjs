// Prove the SSE feed goes stale: the stream polls id > lastEventID, but starts
// lastEventID at 0 and pages only 50 rows per 2s tick. With a large backlog,
// a NEW event never reaches the client within the stream's 15s WriteTimeout.
const { launch, signIn, secret } = require('./harness.cjs');
const { Client } = (() => { try { return require('/home/user/oauth2-monitoring/bff/node_modules/pg'); } catch { return {}; } })();
const O = 'http://monitoring.localhost:9002';

(async () => {
  const browser = await launch();
  const ctx = await browser.newContext();
  const page = await ctx.newPage();
  await signIn(page, O, 'root@e2e.test', secret('root-pw.txt'));
  // Consume the SSE stream in-page and record what event ids arrive.
  const got = await page.evaluate(async () => {
    const ids = []; const started = Date.now();
    const res = await fetch('/api/admin/events/stream', { headers: { Accept: 'text/event-stream' } });
    const reader = res.body.getReader(); const dec = new TextDecoder(); let buf = '';
    while (Date.now() - started < 14000) {
      const { done, value } = await reader.read(); if (done) break;
      buf += dec.decode(value, { stream: true });
      let i; while ((i = buf.indexOf('\n\n')) !== -1) {
        const chunk = buf.slice(0, i); buf = buf.slice(i + 2);
        const m = chunk.match(/"id":(\d+)/); if (m) ids.push(Number(m[1]));
      }
    }
    reader.cancel().catch(() => {});
    return { count: ids.length, min: Math.min(...ids), max: Math.max(...ids) };
  });
  console.log('stream delivered over ~14s:', JSON.stringify(got));
  console.log('interpretation: if max << current max audit id, the newest events never arrive within the stream lifetime.');
  await browser.close();
})();
