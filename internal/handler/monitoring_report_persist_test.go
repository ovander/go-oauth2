package handler

import (
	"testing"
	"time"

	"github.com/ovander/go-oauth2/internal/dto"
)

// TestReportDataMapRoundTrip verifies the report payload survives the
// SecurityReportData -> map[string]interface{} -> SecurityReportData round-trip
// used to persist reports in the jsonb column. A regression here would corrupt
// stored reports without any build-time signal.
func TestReportDataMapRoundTrip(t *testing.T) {
	from := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	to := time.Date(2026, 1, 31, 0, 0, 0, 0, time.UTC)

	original := &dto.SecurityReportData{
		GeneratedAt: time.Date(2026, 2, 1, 12, 0, 0, 0, time.UTC),
		Period:      dto.ReportPeriod{From: from, To: to},
		Overview: dto.ReportOverview{
			TotalEvents:      1234,
			CriticalEvents:   7,
			SuccessfulLogins: 900,
			FailedLogins:     42,
			UniqueUsers:      88,
			BlockedIPs:       3,
			AlertsTriggered:  5,
		},
		Users: dto.ReportUsers{TotalUsers: 100, ActiveUsers: 88, NewUsers: 12},
		Apps:  dto.ReportApps{TotalApps: 9, ActiveApps: 6},
	}

	m, err := reportDataToMap(original)
	if err != nil {
		t.Fatalf("reportDataToMap: %v", err)
	}

	got, err := mapToReportData(m)
	if err != nil {
		t.Fatalf("mapToReportData: %v", err)
	}

	if got.Overview.TotalEvents != original.Overview.TotalEvents {
		t.Errorf("TotalEvents: got %d, want %d", got.Overview.TotalEvents, original.Overview.TotalEvents)
	}
	if got.Overview.CriticalEvents != original.Overview.CriticalEvents {
		t.Errorf("CriticalEvents: got %d, want %d", got.Overview.CriticalEvents, original.Overview.CriticalEvents)
	}
	if got.Users.TotalUsers != original.Users.TotalUsers {
		t.Errorf("TotalUsers: got %d, want %d", got.Users.TotalUsers, original.Users.TotalUsers)
	}
	if got.Apps.ActiveApps != original.Apps.ActiveApps {
		t.Errorf("ActiveApps: got %d, want %d", got.Apps.ActiveApps, original.Apps.ActiveApps)
	}
	if !got.Period.From.Equal(original.Period.From) || !got.Period.To.Equal(original.Period.To) {
		t.Errorf("Period round-trip mismatch: got %v–%v, want %v–%v",
			got.Period.From, got.Period.To, original.Period.From, original.Period.To)
	}
}
