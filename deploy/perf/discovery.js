// discovery + JWKS: served on every resource server's cold start and on every
// key-cache refresh. Cached and signature-free, so this is the framework floor
// — the number every other scenario is measured against.
import http from 'k6/http';
import { check } from 'k6';
import { BASE_URL, thresholds, constantRate } from './lib/config.js';

export const options = {
	scenarios: { discovery: constantRate() },
	thresholds: thresholds(Number(__ENV.P95_MS || 50)),
};

export default function () {
	const disco = http.get(`${BASE_URL}/.well-known/openid-configuration`);
	check(disco, {
		'discovery 200': (r) => r.status === 200,
		'has issuer': (r) => !!r.json('issuer'),
	});

	const jwks = http.get(`${BASE_URL}/.well-known/jwks.json`);
	check(jwks, {
		'jwks 200': (r) => r.status === 200,
		'has keys': (r) => (r.json('keys') || []).length > 0,
	});
}
