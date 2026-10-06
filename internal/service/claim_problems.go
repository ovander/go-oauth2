package service

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/ovander/go-oauth2/internal/model"
	"github.com/ovander/go-oauth2/internal/repository"
	"github.com/ovander/go-oauth2/internal/shared/auth"
	"github.com/ovander/go-oauth2/pkg/logger"
)

// ClaimProblemRecorder turns the claim enricher's problems into security
// events (custom_claim_missing, custom_claims_dropped), so the monitoring
// console shows a user a client's tokens are missing a mapped claim for —
// e.g. an application refusing every request of a user with no tenant_id.
//
// Every refresh repeats the problem, and audit rows are chained (one append at
// a time), so each problem is recorded at most once per window for a user,
// client, claim and kind. The memory of what was recorded is bounded: when it
// is full of unexpired entries, further problems are not recorded until some
// expire (logged once), rather than growing without limit.
type ClaimProblemRecorder struct {
	repo   repository.SecurityAuditLogRepository
	window time.Duration
	max    int
	now    func() time.Time

	mu       sync.Mutex
	seen     map[string]time.Time
	fullOnce sync.Once
}

// NewClaimProblemRecorder records into repo, each problem at most once per
// window, remembering at most max problems.
func NewClaimProblemRecorder(repo repository.SecurityAuditLogRepository, window time.Duration, max int) *ClaimProblemRecorder {
	return &ClaimProblemRecorder{repo: repo, window: window, max: max, now: time.Now, seen: map[string]time.Time{}}
}

// Report implements the enricher's problem reporter. It returns quickly: the
// audit row is written in the background.
func (r *ClaimProblemRecorder) Report(p auth.ClaimIssueProblem) {
	if r == nil || r.repo == nil || !r.first(p) {
		return
	}
	event := model.SecurityEventCustomClaimMissing
	details := map[string]interface{}{"client_id": p.ClientID, "claim": p.Claim, "source": p.Source, "target": p.Target}
	if p.Kind == auth.ClaimProblemDropped {
		event = model.SecurityEventCustomClaimsDropped
		details = map[string]interface{}{"client_id": p.ClientID, "target": p.Target, "size": p.Size, "max_bytes": auth.MaxCustomClaimsBytes}
	}
	row := &model.SecurityAuditLog{
		EventType: event,
		Severity:  model.GetSeverityForEvent(event, false),
		Success:   false,
		Details:   details,
		CreatedAt: r.now(),
	}
	if p.UserID != 0 {
		id := p.UserID
		row.UserID = &id
	}
	if p.AppID != 0 {
		id := p.AppID
		row.AppID = &id
	}
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if err := r.repo.Create(ctx, row); err != nil {
			logger.Warnf("A2: failed to record %s for client %s: %v", event, p.ClientID, err)
		}
	}()
}

// first reports whether p has not been recorded within the window, and marks
// it recorded.
func (r *ClaimProblemRecorder) first(p auth.ClaimIssueProblem) bool {
	key := fmt.Sprintf("%s|%d|%s|%s", p.Kind, p.UserID, p.ClientID, p.Claim)
	now := r.now()
	r.mu.Lock()
	defer r.mu.Unlock()
	if at, ok := r.seen[key]; ok && now.Sub(at) < r.window {
		return false
	}
	if len(r.seen) >= r.max {
		for k, at := range r.seen {
			if now.Sub(at) >= r.window {
				delete(r.seen, k)
			}
		}
		if len(r.seen) >= r.max {
			r.fullOnce.Do(func() {
				logger.Warnf("A2: claim-problem memory full (%d); further problems are not recorded until older ones expire", r.max)
			})
			return false
		}
	}
	r.seen[key] = now
	return true
}
