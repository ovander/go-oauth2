package service

import (
	"context"
	"errors"
	"testing"
	"time"
)

// markFailsRepo is a used-token store that reads fine but cannot write.
type markFailsRepo struct {
	*memUsedTokenRepo
}

func (r *markFailsRepo) MarkAsUsed(context.Context, string, string, uint, time.Time) error {
	return errors.New("used_tokens unavailable")
}

// #366: when the old refresh token cannot be retired, the refresh is refused
// (fail closed) — otherwise the old token stays redeemable alongside the new
// one. The error is a server error, not ErrInvalidToken, so the client keeps
// its token and retries.
func TestRefresh_MarkUsedErrorRefuses(t *testing.T) {
	svc, refreshToken := newHigh04Service(t, &markFailsRepo{memUsedTokenRepo: newMemUsedTokenRepo()})

	resp, err := svc.handleRefreshTokenGrant(context.Background(), refreshReq(refreshToken), "test-client", "")
	if err == nil || resp != nil {
		t.Fatalf("refresh with an unwritable store: (%v, %v), want a refusal and no tokens", resp, err)
	}
	if errors.Is(err, ErrInvalidToken) {
		t.Errorf("a store outage must not read as an invalid grant (the client would drop its token): %v", err)
	}
}
