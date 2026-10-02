// Shared configuration for the Socrate k6 scenarios (B6).
//
// Everything is environment-driven so the same scripts run against a laptop, a
// CI runner and a real VPS without editing them — which matters, because a
// baseline is only useful if the numbers from different environments were
// produced by identical scripts.

export const BASE_URL = __ENV.BASE_URL || 'http://localhost:8080';

export const CLIENT_ID = __ENV.CLIENT_ID || 'perf-client';
export const CLIENT_SECRET = __ENV.CLIENT_SECRET || 'perf-client-secret-value-0123456789';

export const USER_EMAIL = __ENV.USER_EMAIL || 'perf@example.test';
export const USER_PASSWORD = __ENV.USER_PASSWORD || 'PerfBaseline!2026x';

export const SCOPE = __ENV.SCOPE || 'openid profile email offline_access';

// Load shape. The defaults are a smoke-sized run so `k6 run` is useful on a
// laptop; CI and a real baseline override them.
export const RATE = Number(__ENV.RATE || 50); // requests per second
export const DURATION = __ENV.DURATION || '30s';
export const VUS = Number(__ENV.VUS || 50);
// MAX_VUS is how many VUs an arrival-rate scenario may grow to when the server
// slows down (constantRate's maxVUs). A scenario that hands each VU its own
// state must size that state for MAX_VUS, not VUS.
export const MAX_VUS = VUS * 4;

export const form = { headers: { 'Content-Type': 'application/x-www-form-urlencoded' } };
export const json = { headers: { 'Content-Type': 'application/json' } };

// basicAuth builds the client's Authorization header for the endpoints that
// authenticate the client rather than the user.
export function basicAuth(id = CLIENT_ID, secret = CLIENT_SECRET) {
	return { headers: { Authorization: `Basic ${encoding.b64encode(`${id}:${secret}`)}` } };
}

import encoding from 'k6/encoding';

// thresholds returns the pass/fail gates for a scenario.
//
// The p95 budget is the number CI enforces; `failRate` is deliberately strict
// (any non-2xx is a failure) because a perf run that quietly returns 429 or 500
// would otherwise look fast while measuring nothing.
export function thresholds(p95Ms, failRate = 0.01) {
	return {
		http_req_failed: [`rate<${failRate}`],
		http_req_duration: [`p(95)<${p95Ms}`],
		checks: ['rate>0.99'],
	};
}

// constantRate builds an arrival-rate scenario: k6 holds the request rate
// regardless of how slow the server gets, which is what you want for a latency
// baseline. A VU-loop would silently reduce load as latency rose and report a
// flattering number.
export function constantRate(rate = RATE, duration = DURATION, vus = VUS, maxVUs = MAX_VUS) {
	return {
		executor: 'constant-arrival-rate',
		rate,
		timeUnit: '1s',
		duration,
		preAllocatedVUs: vus,
		maxVUs,
	};
}
