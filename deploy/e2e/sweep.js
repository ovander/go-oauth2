// Capacity sweep for paths the B6 baseline does not cover.
// SCN selects the scenario; RATE the offered arrival rate (req/s).
import http from 'k6/http';
import { check } from 'k6';
import encoding from 'k6/encoding';

const SCN = __ENV.SCN;
const RATE = Number(__ENV.RATE || 50);
const S = JSON.parse(open(__ENV.SESSIONS));
const DEMO = JSON.parse(open(__ENV.DEMO)); // {client_id, client_secret, app_id}

export const options = {
  scenarios: { s: { executor: 'constant-arrival-rate', rate: RATE, timeUnit: '1s', duration: __ENV.DURATION || '20s', preAllocatedVUs: 50, maxVUs: 400 } },
  summaryTrendStats: ['avg', 'p(50)', 'p(95)', 'p(99)', 'max'],
};

export function setup() {
  const out = {};
  if (SCN === 'userinfo') {
    const r = http.post('http://127.0.0.1:8080/api/auth/login', JSON.stringify({ email: 'perf@example.test', password: 'PerfBaseline!2026x', app_client_id: 'perf-public' }), { headers: { 'Content-Type': 'application/json' } });
    out.token = r.json('access_token');
  }
  if (SCN === 'decide') {
    const r = http.post('http://127.0.0.1:8080/oauth/token', { grant_type: 'client_credentials' }, { headers: { Authorization: 'Basic ' + encoding.b64encode(`${DEMO.client_id}:${DEMO.client_secret}`) } });
    out.token = r.json('access_token');
  }
  return out;
}

export default function (d) {
  let r;
  switch (SCN) {
    case 'userinfo':
      r = http.get('http://127.0.0.1:8080/oauth/userinfo', { headers: { Authorization: `Bearer ${d.token}` } });
      break;
    case 'decide':
      r = http.post(`http://127.0.0.1:8081/api/apps/${DEMO.app_id}/service/policy/decide`,
        JSON.stringify({ subject: { user_id: 2 }, action: 'invoice.approve', resource: { type: 'invoice', id: 'x', attributes: { amount: 10 } } }),
        { headers: { Authorization: `Bearer ${d.token}`, 'Content-Type': 'application/json' } });
      break;
    case 'admin_users': // Caddy → admin BFF → admin API (session → bearer, PEP in shadow)
      r = http.get('http://127.0.0.1:9001/api/admin/users?page=1&page_size=20', { headers: { Host: 'admin.localhost:9001', Cookie: S.admin.cookie } });
      break;
    case 'admin_dashboard':
      r = http.get('http://127.0.0.1:9001/api/admin/dashboard/stats', { headers: { Host: 'admin.localhost:9001', Cookie: S.admin.cookie } });
      break;
    case 'demo_me': // Caddy → demo BFF (backendkit bff) → demo API (jwtauth, JWKS cached)
      r = http.get('http://127.0.0.1:9003/api/me', { headers: { Host: 'app.localhost:9003', Cookie: S.demo.cookie } });
      break;
    case 'demo_approve': // … + pep → Socrate decide endpoint on every call
      r = http.post('http://127.0.0.1:9003/api/invoices/inv-1/approve', null, { headers: { Host: 'app.localhost:9003', Cookie: S.demo.cookie, 'X-CSRF-Token': S.demo.csrf } });
      break;
    case 'discovery':
      r = http.get('http://127.0.0.1:8080/.well-known/openid-configuration');
      break;
  }
  check(r, { ok: (x) => x.status === 200 });
}
