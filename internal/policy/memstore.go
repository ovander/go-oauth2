package policy

import (
	"context"
	"errors"
	"sort"
	"sync"
	"time"
)

// MemoryStore is an in-memory Store with the same conflict semantics as
// PostgresStore (the version number is the primary key). It exists for tests
// in this and other packages; production always uses PostgresStore.
type MemoryStore struct {
	mu        sync.Mutex
	versions  map[int64]*Version
	decisions []DecisionRecord
	// failRead and reads are test hooks for the service's outage handling.
	failRead bool
	reads    int
}

var _ Store = (*MemoryStore)(nil)

// NewMemoryStore returns an empty MemoryStore.
func NewMemoryStore() *MemoryStore { return &MemoryStore{versions: map[int64]*Version{}} }

// LatestVersion implements Store.
func (m *MemoryStore) LatestVersion(context.Context) (int64, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.reads++
	if m.failRead {
		return 0, errors.New("database unreachable")
	}
	var max int64
	for v := range m.versions {
		if v > max {
			max = v
		}
	}
	return max, nil
}

// Get implements Store.
func (m *MemoryStore) Get(_ context.Context, v int64) (*Version, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.failRead {
		return nil, errors.New("database unreachable")
	}
	ver, ok := m.versions[v]
	if !ok {
		return nil, ErrVersionNotFound
	}
	cp := *ver
	return &cp, nil
}

// List implements Store.
func (m *MemoryStore) List(_ context.Context, limit int, before int64) ([]VersionSummary, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	var out []VersionSummary
	for _, v := range m.versions {
		if before > 0 && v.Version >= before {
			continue
		}
		out = append(out, VersionSummary{Version: v.Version, Note: v.Note, RuleCount: len(v.Rules)})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Version > out[j].Version })
	if len(out) > limit {
		out = out[:limit]
	}
	return out, nil
}

// Insert implements Store.
func (m *MemoryStore) Insert(_ context.Context, v *Version) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, exists := m.versions[v.Version]; exists {
		return ErrVersionConflict
	}
	cp := *v
	m.versions[v.Version] = &cp
	return nil
}

// AppendDecision implements Store.
func (m *MemoryStore) AppendDecision(_ context.Context, r *DecisionRecord) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	r.ID = int64(len(m.decisions) + 1)
	m.decisions = append(m.decisions, *r)
	return nil
}

// Decisions implements Store, applying the filter the way PostgresStore does.
func (m *MemoryStore) Decisions(_ context.Context, f DecisionFilter) ([]DecisionRecord, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	var out []DecisionRecord
	for i := len(m.decisions) - 1; i >= 0; i-- { // newest first
		d := m.decisions[i]
		switch {
		case f.CorrelationID != "" && d.CorrelationID != f.CorrelationID,
			f.Allow != nil && d.Allow != *f.Allow,
			f.DivergenceOnly && d.Divergence == "",
			!f.Since.IsZero() && d.CreatedAt.Before(f.Since),
			f.BeforeID > 0 && d.ID >= f.BeforeID,
			f.Source != "" && d.Source != f.Source,
			f.ClientID != "" && d.ClientID != f.ClientID:
			continue
		}
		out = append(out, d)
		if f.Limit > 0 && len(out) == f.Limit {
			break
		}
	}
	return out, nil
}

// SummarizeDecisions implements Store.
func (m *MemoryStore) SummarizeDecisions(_ context.Context, since time.Time) (DecisionSummary, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	sum := newDecisionSummary(since)
	for _, d := range m.decisions {
		if !d.CreatedAt.Before(since) {
			sum.addSummaryRow(d.Source, d.Allow, d.Enforced, d.Divergence, 1)
		}
	}
	return sum, nil
}

// SweepDecisions implements Store.
func (m *MemoryStore) SweepDecisions(context.Context, time.Time) (int64, error) { return 0, nil }
