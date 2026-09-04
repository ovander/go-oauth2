// introspect (RFC 7662): the hot path for resource servers that do not validate
// JWTs locally. It authenticates the client and verifies the presented token,
// so it is the read path most sensitive to database latency.
import http from 'k6/http';
import { check } from 'k6';
import { BASE_URL, CLIENT_ID, CLIENT_SECRET, form, thresholds, constantRate } from './lib/config.js';

export function setup() {
	const res = http.post(
		`${BASE_URL}/oauth/token`,
		{ grant_type: 'client_credentials', client_id: CLIENT_ID, client_secret: CLIENT_SECRET, scope: 'api' },
		form,
	);
	if (res.status !== 200) {
		throw new Error(`setup: could not mint a token to introspect (status ${res.status})`);
	}
	return { token: res.json('access_token') };
}

export const options = {
	scenarios: { introspect: constantRate() },
	thresholds: thresholds(Number(__ENV.P95_MS || 100)),
};

export default function (data) {
	const res = http.post(
		`${BASE_URL}/oauth/introspect`,
		{ token: data.token, client_id: CLIENT_ID, client_secret: CLIENT_SECRET },
		form,
	);
	check(res, {
		'status 200': (r) => r.status === 200,
		'token is active': (r) => r.json('active') === true,
	});
}
