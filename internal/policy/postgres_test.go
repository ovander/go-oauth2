package policy_test

import (
	"context"
	"errors"
	"os"
	"reflect"
	"sync"
	"testing"
	"time"

	"github.com/ovandermoten/go-oauth2/internal/database/migrate"
	"github.com/ovandermoten/go-oauth2/internal/policy"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
)

// testDB connects to TEST_DATABASE_URL and applies the real migration chain,
// so these tests exercise the tables exactly as migrations 0023/0024 create
// them rather than a copy of their DDL. Skipped without the variable.
func testDB(t *testing.T) *gorm.DB {
	t.Helper()
	dsn := os.Getenv("TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("TEST_DATABASE_URL not set; skipping the Postgres integration test")
	}
	db, err := gorm.Open(postgres.Open(dsn), &gorm.Config{Logger: logger.Default.LogMode(logger.Silent)})
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	if err := migrate.Run(db); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	if err := db.Exec(`TRUNCATE policy_versions, policy_decisions`).Error; err != nil {
		t.Fatalf("truncate: %v", err)
	}
	return db
}

func TestPostgresStore_RoundTripsARuleSetExactly(t *testing.T) {
	db := testDB(t)
	s := policy.NewService(policy.NewPostgresStore(db), policy.ModeShadow, time.Minute)
	ctx := context.Background()

	rules := append(policy.Baseline(), policy.Rule{
		ID: "owner", Effect: policy.EffectAllow, Actions: []string{"doc.*"},
		When: &policy.Condition{All: []policy.Condition{
			{Attr: "resource.attributes.owner_id", Op: "eq", Ref: "principal.id"},
			{Attr: "context.ip", Op: "cidr", Value: []any{"10.0.0.0/8"}},
			{Not: &policy.Condition{Attr: "principal.auth_time_age", Op: "gt", Value: float64(900)}},
		}},
		Obligations: []string{policy.ObligationMFA},
	})
	saved, err := s.Save(ctx, 0, rules, "round trip", 9)
	if err != nil {
		t.Fatal(err)
	}
	got, err := s.Get(ctx, saved.Version)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(got.Rules, rules) {
		t.Fatalf("rules changed in storage:\n got  %+v\n want %+v", got.Rules, rules)
	}
	if got.Note != "round trip" || got.CreatedBy == nil || *got.CreatedBy != 9 {
		t.Fatalf("metadata = %+v", got)
	}

	list, err := s.List(ctx, 10, 0)
	if err != nil || len(list) != 1 || list[0].RuleCount != len(rules) {
		t.Fatalf("list = %+v, %v", list, err)
	}
}

// Ten editors all loaded version 1 and all press save at once. Exactly one
// wins; nine are told to reload. Nobody's change is silently lost.
func TestPostgresStore_ConcurrentSavesFromOneBase_ExactlyOneWins(t *testing.T) {
	db := testDB(t)
	ctx := context.Background()
	seed := policy.NewService(policy.NewPostgresStore(db), policy.ModeShadow, time.Minute)
	if _, err := seed.EnsureBaseline(ctx); err != nil {
		t.Fatal(err)
	}

	const editors = 10
	var wg sync.WaitGroup
	results := make(chan error, editors)
	for i := 0; i < editors; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			// A separate Service per editor: separate instances, one database.
			s := policy.NewService(policy.NewPostgresStore(db), policy.ModeShadow, time.Minute)
			_, err := s.Save(ctx, 1, []policy.Rule{{ID: "r", Effect: policy.EffectAllow, Actions: []string{"*"}}}, "", uint(i+1))
			results <- err
		}(i)
	}
	wg.Wait()
	close(results)

	wins, conflicts := 0, 0
	for err := range results {
		switch {
		case err == nil:
			wins++
		case errors.Is(err, policy.ErrVersionConflict):
			conflicts++
		default:
			t.Errorf("unexpected error: %v", err)
		}
	}
	if wins != 1 || conflicts != editors-1 {
		t.Fatalf("wins=%d conflicts=%d, want exactly 1 and %d", wins, conflicts, editors-1)
	}
	if latest, _ := policy.NewPostgresStore(db).LatestVersion(ctx); latest != 2 {
		t.Fatalf("latest = %d, want 2", latest)
	}
}

// Several instances starting at once on an empty database seed the baseline
// exactly once.
func TestPostgresStore_EnsureBaseline_RaceSeedsOnce(t *testing.T) {
	db := testDB(t)
	ctx := context.Background()

	var wg sync.WaitGroup
	var mu sync.Mutex
	seeded := 0
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			s := policy.NewService(policy.NewPostgresStore(db), policy.ModeShadow, time.Minute)
			ok, err := s.EnsureBaseline(ctx)
			if err != nil {
				t.Errorf("EnsureBaseline: %v", err)
			}
			if ok {
				mu.Lock()
				seeded++
				mu.Unlock()
			}
		}()
	}
	wg.Wait()

	var versions int64
	db.Raw(`SELECT count(*) FROM policy_versions`).Scan(&versions)
	if seeded != 1 || versions != 1 {
		t.Fatalf("seeded=%d versions=%d, want 1 and 1", seeded, versions)
	}
}

func TestPostgresStore_DecisionLog_FiltersAndSweep(t *testing.T) {
	db := testDB(t)
	ctx := context.Background()
	s := policy.NewService(policy.NewPostgresStore(db), policy.ModeShadow, time.Minute)
	uid := uint(7)

	old := time.Now().Add(-40 * 24 * time.Hour).UTC()
	rows := []policy.DecisionRecord{
		{CreatedAt: old, CorrelationID: "c-old", Source: policy.SourceAdminPEP, Mode: "shadow", Action: "GET /x", Reason: "no_applicable_rule"},
		{CorrelationID: "c-1", Source: policy.SourceAdminPEP, Mode: "shadow", Action: "DELETE /api/admin/apps/{id}",
			Rule: "no-deletes", Reason: "denied_by_rule", PolicyVersion: 3, PrincipalKind: "user", PrincipalID: &uid,
			Divergence: policy.DivergencePDPStricter, ResourceType: "apps", ResourceID: "5", StatusCode: 500},
		{CorrelationID: "c-2", Source: policy.SourceAdminPEP, Mode: "enforce", Enforced: true, Allow: false, Action: "GET /y", Reason: "denied_by_rule", StatusCode: 403},
	}
	for i := range rows {
		s.Record(ctx, &rows[i])
	}

	all, err := s.Decisions(ctx, policy.DecisionFilter{Limit: 10})
	if err != nil || len(all) != 3 {
		t.Fatalf("all = %d rows, %v", len(all), err)
	}
	if all[0].CorrelationID != "c-2" {
		t.Fatalf("not newest first: %+v", all[0])
	}

	byCorr, _ := s.Decisions(ctx, policy.DecisionFilter{CorrelationID: "c-1", Limit: 10})
	if len(byCorr) != 1 || byCorr[0].ResourceID != "5" || byCorr[0].PrincipalID == nil || *byCorr[0].PrincipalID != 7 ||
		byCorr[0].Rule != "no-deletes" || byCorr[0].PolicyVersion != 3 {
		t.Fatalf("by correlation id = %+v", byCorr)
	}
	div, _ := s.Decisions(ctx, policy.DecisionFilter{DivergenceOnly: true, Limit: 10})
	if len(div) != 1 || div[0].Divergence != policy.DivergencePDPStricter {
		t.Fatalf("divergence only = %+v", div)
	}
	page, _ := s.Decisions(ctx, policy.DecisionFilter{BeforeID: all[0].ID, Limit: 1})
	if len(page) != 1 || page[0].ID != all[1].ID {
		t.Fatalf("paging = %+v", page)
	}

	n, err := s.SweepDecisions(ctx, 30*24*time.Hour)
	if err != nil || n != 1 {
		t.Fatalf("sweep removed %d, %v; want 1 (the 40-day-old row)", n, err)
	}
}

func TestPostgresStore_SummaryAndSourceFilters(t *testing.T) {
	db := testDB(t)
	ctx := context.Background()
	s := policy.NewService(policy.NewPostgresStore(db), policy.ModeEnforce, time.Minute)

	old := time.Now().Add(-48 * time.Hour).UTC()
	for _, r := range []policy.DecisionRecord{
		{CreatedAt: old, Source: policy.SourceAdminPEP, Mode: "shadow", Action: "a", Reason: "r"},
		{Source: policy.SourceAdminPEP, Mode: "shadow", Action: "a", Reason: "r", Divergence: policy.DivergencePDPStricter},
		{Source: "decide_api", Mode: "enforce", Enforced: true, Action: "b", Reason: "r", ClientID: "billing"},
		{Source: "decide_api", Mode: "enforce", Enforced: true, Action: "b", Reason: "r", ClientID: "crm"},
		{Source: policy.SourceAdminPEP, Mode: "shadow", Allow: true, Action: "c", Reason: "r", Divergence: policy.DivergencePDPLooser},
	} {
		rec := r
		s.Record(ctx, &rec)
	}

	sum, err := s.SummarizeDecisions(ctx, time.Now().Add(-24*time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	if sum.Denials != 3 || sum.EnforcedDenials != 2 ||
		sum.Divergences[policy.DivergencePDPStricter] != 1 || sum.Divergences[policy.DivergencePDPLooser] != 1 ||
		sum.DenialsBySource["decide_api"] != 2 || sum.DenialsBySource[policy.SourceAdminPEP] != 1 {
		t.Fatalf("summary = %+v (the 48h-old row must be outside the window)", sum)
	}

	rows, _ := s.Decisions(ctx, policy.DecisionFilter{Source: "decide_api", ClientID: "crm", Limit: 10})
	if len(rows) != 1 || rows[0].ClientID != "crm" {
		t.Fatalf("source+client filter = %+v", rows)
	}
}
