// login: the password path. Deliberately measured separately because it is
// bcrypt-bound, not I/O-bound — its latency is a cost parameter you chose, and
// it should be read against a different budget than the token endpoints.
// A p95 in the hundreds of milliseconds here is the bcrypt cost factor working
// as intended, not a regression.
import http from 'k6/http';
import { check } from 'k6';
import { BASE_URL, CLIENT_ID, USER_EMAIL, USER_PASSWORD, json, thresholds, constantRate } from './lib/config.js';

export const options = {
	// Login is intentionally expensive, so the default arrival rate is lower;
	// driving it at token-endpoint rates measures the bcrypt queue, not the server.
	scenarios: { login: constantRate(Number(__ENV.RATE || 10)) },
	thresholds: thresholds(Number(__ENV.P95_MS || 600)),
};

export default function () {
	const res = http.post(
		`${BASE_URL}/api/auth/login`,
		JSON.stringify({ email: USER_EMAIL, password: USER_PASSWORD, app_client_id: CLIENT_ID }),
		json,
	);
	check(res, {
		'status 200': (r) => r.status === 200,
		'has access_token': (r) => !!r.json('access_token'),
	});
}
