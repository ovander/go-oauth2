// token_refresh: the highest-volume authenticated path in a live deployment —
// every session renews on this endpoint.
//
// Two things this script has to get right, and a naive version gets both wrong:
//
//  1. Refresh tokens are single-use and rotated. Reusing one token measures the
//     reuse-detection path instead of the refresh path, and under
//     REFRESH_REUSE_MODE=enforce it revokes the family it is testing. So each
//     VU holds its own chain and feeds every response's new token forward.
//
//  2. Logging in is bcrypt-bound (~70 ms of CPU). Doing it inside the measured
//     loop buries the refresh latency under password hashing and reports a
//     number that is mostly bcrypt. Chains are therefore minted in setup(),
//     before measurement starts, and handed to VUs by index.
//
// There is one chain per VU the scenario may ever start (MAX_VUS), not per
// pre-allocated VU: when the server slows down, k6 adds VUs to hold the rate,
// and a VU that shared a chain would present a token another VU had already
// rotated. That turns a slowdown into a cascade of 400s that measures the
// script, not the server.
import http from 'k6/http';
import { check, fail } from 'k6';
import { BASE_URL, CLIENT_ID, USER_EMAIL, USER_PASSWORD, form, json, thresholds, constantRate, MAX_VUS } from './lib/config.js';

export const options = {
	scenarios: { token_refresh: constantRate() },
	thresholds: thresholds(Number(__ENV.P95_MS || 150)),
	// setup() mints one chain per VU sequentially; give it room.
	setupTimeout: '120s',
};

// setup mints one refresh-token chain per possible VU, outside the measured
// window.
export function setup() {
	const chains = [];
	for (let i = 0; i < MAX_VUS; i++) {
		const res = http.post(
			`${BASE_URL}/api/auth/login`,
			JSON.stringify({ email: USER_EMAIL, password: USER_PASSWORD, app_client_id: CLIENT_ID }),
			json,
		);
		if (res.status !== 200) {
			fail(`setup: login ${i} failed (status ${res.status}): ${res.body}`);
		}
		chains.push(res.json('refresh_token'));
	}
	return { chains };
}

// Per-VU state: this VU's position in its own rotation chain.
let refreshToken = null;

export default function (data) {
	if (!refreshToken) {
		// __VU is 1-based, and there is a chain for every VU k6 may start.
		refreshToken = data.chains[__VU - 1];
	}

	const res = http.post(
		`${BASE_URL}/oauth/token`,
		{ grant_type: 'refresh_token', refresh_token: refreshToken, client_id: CLIENT_ID },
		form,
	);

	const ok = check(res, {
		'status 200': (r) => r.status === 200,
		'rotated refresh token': (r) => !!r.json('refresh_token'),
	});

	if (ok) {
		// Carry the rotated token forward, or the next iteration presents a
		// spent one and measures reuse detection instead.
		refreshToken = res.json('refresh_token');
	}
	// On a failure, keep the token: after a timeout or a 5xx it may still be
	// valid. Going back to the chain's first token would present a token
	// rotated long ago and fail on every later iteration.
}
