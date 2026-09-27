package policy

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/ovandermoten/go-oauth2/pkg/logger"
)

// DefaultRefreshInterval bounds how long another instance's save takes to be
// seen here. Each check is one indexed MAX() over a table with a few hundred
// rows, and the full rule set is reloaded only when the number has moved.
const DefaultRefreshInterval = 10 * time.Second

// ValidationFailed carries every problem Validate found.
type ValidationFailed struct {
	Errors []ValidationError
}

func (e *ValidationFailed) Error() string {
	msgs := make([]string, 0, len(e.Errors))
	for _, v := range e.Errors {
		msgs = append(msgs, v.Error())
	}
	return "invalid policy: " + strings.Join(msgs, "; ")
}

// Service is the PDP: the current rule set, cached, plus the operations the
// admin API needs on its history.
type Service struct {
	store   Store
	mode    Mode
	refresh time.Duration
	now     func() time.Time

	mu      sync.RWMutex
	engine  *Engine
	checked time.Time
}

// NewService returns a PDP over store. refresh <= 0 uses
// DefaultRefreshInterval.
func NewService(store Store, mode Mode, refresh time.Duration) *Service {
	if refresh <= 0 {
		refresh = DefaultRefreshInterval
	}
	return &Service{store: store, mode: mode, refresh: refresh, now: time.Now}
}

// Mode is the configured rollout mode.
func (s *Service) Mode() Mode { return s.mode }

// Engine returns the engine for the latest version, reloading it when the
// refresh interval has passed and the latest version number has changed.
//
// When the store is unreachable but a rule set is already loaded, the loaded
// set keeps being used: a database blip must not make every decision fail.
// Only with nothing loaded at all is an error returned.
func (s *Service) Engine(ctx context.Context) (*Engine, error) {
	now := s.now()
	s.mu.RLock()
	e, fresh := s.engine, now.Sub(s.checked) < s.refresh
	s.mu.RUnlock()
	if e != nil && fresh {
		return e, nil
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	if s.engine != nil && now.Sub(s.checked) < s.refresh {
		return s.engine, nil // another goroutine refreshed while we waited
	}

	latest, err := s.store.LatestVersion(ctx)
	if err != nil {
		return s.keepStale(now, fmt.Errorf("policy: read latest version: %w", err))
	}
	if latest == 0 {
		// Nothing stored. Drop any loaded set too: someone deleted the
		// versions table's contents, and serving a set that no longer exists
		// would make every decision unexplainable.
		s.engine, s.checked = nil, now
		return nil, ErrNoPolicy
	}
	if s.engine != nil && s.engine.version == latest {
		s.checked = now
		return s.engine, nil
	}

	v, err := s.store.Get(ctx, latest)
	if err != nil {
		return s.keepStale(now, fmt.Errorf("policy: load version %d: %w", latest, err))
	}
	if errs := Validate(v.Rules); len(errs) > 0 {
		// Only reachable if a row was written around the API. Refuse it
		// rather than evaluate rules nobody validated.
		return s.keepStale(now, fmt.Errorf("policy: version %d fails validation: %w", latest, &ValidationFailed{Errors: errs}))
	}
	s.engine, s.checked = NewEngine(v.Version, v.Rules), now
	logger.WithFields(logger.Fields{"policy_version": v.Version, "rules": len(v.Rules)}).
		Info("A4: policy loaded")
	return s.engine, nil
}

// keepStale is called with s.mu held.
func (s *Service) keepStale(now time.Time, err error) (*Engine, error) {
	if s.engine == nil {
		return nil, err
	}
	// Back off for one interval rather than retry on every request.
	s.checked = now
	logger.WithFields(logger.Fields{"policy_version": s.engine.version, "error": err.Error()}).
		Warn("A4: policy refresh failed; still serving the loaded version")
	return s.engine, nil
}

// Invalidate forces the next Engine call to re-check the store. Called after
// a local save so this instance sees its own change immediately.
func (s *Service) Invalidate() {
	s.mu.Lock()
	s.checked = time.Time{}
	s.mu.Unlock()
}

// Decide evaluates in against the latest rule set. With no rule set available
// it returns a deny with ReasonPolicyUnloaded and the underlying error, and
// leaves it to the caller to decide whether that denies anything.
func (s *Service) Decide(ctx context.Context, in Input) (Decision, error) {
	e, err := s.Engine(ctx)
	if err != nil {
		return Decision{Allow: false, Reason: ReasonPolicyUnloaded}, err
	}
	return e.Decide(in), nil
}

// Simulate evaluates in with a per-rule trace — against draft when it is
// non-nil (after validating it), otherwise against the latest version.
func (s *Service) Simulate(ctx context.Context, in Input, draft []Rule) (Decision, []TraceEntry, error) {
	if draft != nil {
		if errs := Validate(draft); len(errs) > 0 {
			return Decision{}, nil, &ValidationFailed{Errors: errs}
		}
		d, trace := NewEngine(0, draft).Explain(in)
		return d, trace, nil
	}
	e, err := s.Engine(ctx)
	if err != nil {
		return Decision{}, nil, err
	}
	d, trace := e.Explain(in)
	return d, trace, nil
}

// Current returns the latest version.
func (s *Service) Current(ctx context.Context) (*Version, error) {
	latest, err := s.store.LatestVersion(ctx)
	if err != nil {
		return nil, err
	}
	if latest == 0 {
		return nil, ErrNoPolicy
	}
	return s.store.Get(ctx, latest)
}

// Get returns one version.
func (s *Service) Get(ctx context.Context, version int64) (*Version, error) {
	return s.store.Get(ctx, version)
}

// List returns version summaries, newest first.
func (s *Service) List(ctx context.Context, limit int, before int64) ([]VersionSummary, error) {
	return s.store.List(ctx, limit, before)
}

// Save validates rules and stores them as the version after base. base must be
// the latest version (0 when none exists yet); otherwise ErrVersionConflict.
func (s *Service) Save(ctx context.Context, base int64, rules []Rule, note string, by uint) (*Version, error) {
	if rules == nil {
		rules = []Rule{}
	}
	if errs := Validate(rules); len(errs) > 0 {
		return nil, &ValidationFailed{Errors: errs}
	}
	latest, err := s.store.LatestVersion(ctx)
	if err != nil {
		return nil, err
	}
	if base != latest {
		return nil, ErrVersionConflict
	}

	byID := by
	v := &Version{
		Version:   latest + 1,
		Rules:     rules,
		Note:      note,
		CreatedBy: &byID,
		CreatedAt: s.now().UTC(),
	}
	if err := s.store.Insert(ctx, v); err != nil {
		return nil, err
	}
	s.Invalidate()
	return v, nil
}

// Restore saves the rules of an earlier version as a new version. History is
// never rewritten: rolling back is itself a change, with its own author.
func (s *Service) Restore(ctx context.Context, version, base int64, by uint) (*Version, error) {
	old, err := s.store.Get(ctx, version)
	if err != nil {
		return nil, err
	}
	return s.Save(ctx, base, old.Rules, fmt.Sprintf("restore of version %d", version), by)
}

// EnsureBaseline seeds Baseline() as version 1 when no version exists. Safe to
// call from every instance on every start: if two race, one insert wins and
// the other sees a conflict, which is treated as success.
func (s *Service) EnsureBaseline(ctx context.Context) (bool, error) {
	latest, err := s.store.LatestVersion(ctx)
	if err != nil {
		return false, err
	}
	if latest > 0 {
		return false, nil
	}
	err = s.store.Insert(ctx, &Version{
		Version:   1,
		Rules:     Baseline(),
		Note:      "baseline: restates the admin API's code gates as rules",
		CreatedAt: s.now().UTC(),
	})
	if errors.Is(err, ErrVersionConflict) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	s.Invalidate()
	return true, nil
}

// Record appends a decision-log row. Failures are logged, never returned: the
// log is evidence about a decision, not part of making it.
func (s *Service) Record(ctx context.Context, rec *DecisionRecord) {
	if rec.CreatedAt.IsZero() {
		rec.CreatedAt = s.now().UTC()
	}
	ctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 2*time.Second)
	defer cancel()
	if err := s.store.AppendDecision(ctx, rec); err != nil {
		logger.WithFields(logger.Fields{
			"action":         rec.Action,
			"correlation_id": rec.CorrelationID,
			"error":          err.Error(),
		}).Warn("A4: failed to record policy decision")
	}
}

// Decisions queries the decision log.
func (s *Service) Decisions(ctx context.Context, f DecisionFilter) ([]DecisionRecord, error) {
	return s.store.Decisions(ctx, f)
}

// SweepDecisions deletes decision-log rows older than retention.
func (s *Service) SweepDecisions(ctx context.Context, retention time.Duration) (int64, error) {
	return s.store.SweepDecisions(ctx, s.now().Add(-retention))
}
