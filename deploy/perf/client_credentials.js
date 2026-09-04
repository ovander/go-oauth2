// client_credentials: the machine-to-machine grant. Signing-bound — this is the
// cheapest token path (no password hashing, no user lookup), so it is the
// closest thing to a measure of the RS256 signing and DB-read floor.
import http from 'k6/http';
import { check } from 'k6';
import { BASE_URL, CLIENT_ID, CLIENT_SECRET, form, thresholds, constantRate } from './lib/config.js';

export const options = {
	scenarios: { client_credentials: constantRate() },
	thresholds: thresholds(Number(__ENV.P95_MS || 100)),
};

export default function () {
	const res = http.post(
		`${BASE_URL}/oauth/token`,
		{
			grant_type: 'client_credentials',
			client_id: CLIENT_ID,
			client_secret: CLIENT_SECRET,
			scope: 'api',
		},
		form,
	);
	check(res, {
		'status 200': (r) => r.status === 200,
		'has access_token': (r) => !!r.json('access_token'),
	});
}
