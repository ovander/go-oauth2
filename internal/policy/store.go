package policy

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"gorm.io/gorm"

	"github.com/ovander/go-oauth2/internal/model"
)

// Errors returned by the store and the service.
var (
	ErrVersionNotFound = errors.New("policy version not found")
	// ErrVersionConflict means the caller edited a version that is no longer
	// the latest — someone else saved in between. The caller must reload and
	// re-apply rather than overwrite a change they never saw.
	ErrVersionConflict = errors.New("policy was changed by someone else; reload and re-apply")
	// ErrNoPolicy means no rule-set version exists at all.
	ErrNoPolicy = errors.New("no policy version is stored")
)

// Version is one immutable, numbered rule set. Every save creates a new
// version; nothing is ever updated in place, so any decision can be explained
// against the exact rules that made it, and any version can be restored.
type Version struct {
	Version   int64     `json:"version"`
	Rules     []Rule    `json:"rules"`
	Note      string    `json:"note,omitempty"`
	CreatedBy *uint     `json:"created_by,omitempty"`
	CreatedAt time.Time `json:"created_at"`
}

// VersionSummary is a Version without its rules, for listings.
type VersionSummary struct {
	Version   int64     `json:"version"`
	Note      string    `json:"note,omitempty"`
	CreatedBy *uint     `json:"created_by,omitempty"`
	CreatedAt time.Time `json:"created_at"`
	RuleCount int       `json:"rule_count"`
}

// Decision sources and divergence kinds.
const (
	SourceAdminPEP = "admin_pep"
	// SourceDecideAPI is an application asking through the decide endpoint.
	SourceDecideAPI = "decide_api"

	// DivergencePDPStricter: the PDP would deny a request the code gates let
	// through. In enforce mode this is a request the PDP actually refused.
	DivergencePDPStricter = "pdp_deny_code_allow"
	// DivergencePDPLooser: the PDP would allow a request the code gates
	// refused. Harmless while the code gates stay in place (both must allow),
	// but it is exactly what has to be zero before a gate can be retired.
	DivergencePDPLooser = "pdp_allow_code_deny"
)

// DecisionRecord is one row of the decision log. Only denials and
// divergences are recorded; agreeing allows are counted in metrics instead,
// so the log stays a list of things worth reading.
type DecisionRecord struct {
	ID            int64     `json:"id"`
	CreatedAt     time.Time `json:"created_at"`
	CorrelationID string    `json:"correlation_id,omitempty"`
	Source        string    `json:"source"`
	Mode          string    `json:"mode"`
	// Enforced is true when the decision was taken in enforce mode — a deny
	// was answered with 403. In shadow mode it is always false: the decision
	// was recorded, not acted on.
	Enforced      bool   `json:"enforced"`
	Allow         bool   `json:"allow"`
	Divergence    string `json:"divergence,omitempty"`
	Action        string `json:"action"`
	Rule          string `json:"rule,omitempty"`
	Reason        string `json:"reason"`
	PolicyVersion int64  `json:"policy_version"`
	PrincipalKind string `json:"principal_kind,omitempty"`
	PrincipalID   *uint  `json:"principal_id,omitempty"`
	ClientID      string `json:"client_id,omitempty"`
	ResourceType  string `json:"resource_type,omitempty"`
	ResourceID    string `json:"resource_id,omitempty"`
	IPAddress     string `json:"ip_address,omitempty"`
	// StatusCode is the response status the request ended with (admin PEP).
	StatusCode int `json:"status_code,omitempty"`
	// Obligations are the obligations the decision carried. With an unmet one,
	// Allow is false and Reason is "obligation_unmet:<name>".
	Obligations []string `json:"obligations,omitempty"`
}

// DecisionFilter narrows a decision-log query. Zero values mean "any".
type DecisionFilter struct {
	CorrelationID  string
	Allow          *bool
	DivergenceOnly bool
	Since          time.Time
	// BeforeID pages backwards: only rows with a smaller id.
	BeforeID int64
	// Source is SourceAdminPEP or the decide endpoint's source.
	Source string
	// ClientID is the client the decision concerned — for the decide
	// endpoint, the calling application.
	ClientID string
	Limit    int
}

// DecisionSummary counts decision-log rows since a point in time — the
// numbers a SOC dashboard shows next to the list.
type DecisionSummary struct {
	Since time.Time `json:"since"`
	// Denials counts every logged denial, would-be (shadow) or real.
	Denials int64 `json:"denials"`
	// EnforcedDenials counts the denials that were answered with a refusal.
	EnforcedDenials int64 `json:"enforced_denials"`
	// Divergences counts disagreements with the code gates, by kind.
	Divergences map[string]int64 `json:"divergences"`
	// DenialsBySource splits Denials by where the decision was asked.
	DenialsBySource map[string]int64 `json:"denials_by_source"`
}

// addSummaryRow folds one (source, allow, enforced, divergence) group into s.
func (s *DecisionSummary) addSummaryRow(source string, allow, enforced bool, divergence string, n int64) {
	if !allow {
		s.Denials += n
		s.DenialsBySource[source] += n
		if enforced {
			s.EnforcedDenials += n
		}
	}
	if divergence != "" {
		s.Divergences[divergence] += n
	}
}

func newDecisionSummary(since time.Time) DecisionSummary {
	return DecisionSummary{Since: since, Divergences: map[string]int64{}, DenialsBySource: map[string]int64{}}
}

// Store persists rule-set versions and the decision log.
type Store interface {
	LatestVersion(ctx context.Context) (int64, error)
	Get(ctx context.Context, version int64) (*Version, error)
	List(ctx context.Context, limit int, before int64) ([]VersionSummary, error)
	// Insert stores a new version, returning ErrVersionConflict if that
	// version number already exists.
	Insert(ctx context.Context, v *Version) error
	AppendDecision(ctx context.Context, rec *DecisionRecord) error
	Decisions(ctx context.Context, f DecisionFilter) ([]DecisionRecord, error)
	SweepDecisions(ctx context.Context, before time.Time) (int64, error)
	SummarizeDecisions(ctx context.Context, since time.Time) (DecisionSummary, error)
}

// PostgresStore is the Store over the policy_versions and policy_decisions
// tables (migrations 0023 and 0024).
type PostgresStore struct {
	db *gorm.DB
}

// NewPostgresStore returns a store over db.
func NewPostgresStore(db *gorm.DB) *PostgresStore { return &PostgresStore{db: db} }

type versionRow struct {
	Version   int64
	Rules     []byte
	Note      string
	CreatedBy *uint
	CreatedAt time.Time
	RuleCount int
}

// LatestVersion returns the highest stored version, or 0 when none exists.
func (s *PostgresStore) LatestVersion(ctx context.Context) (int64, error) {
	var v int64
	err := s.db.WithContext(ctx).
		Raw(`SELECT COALESCE(MAX(version), 0) FROM policy_versions`).
		Scan(&v).Error
	return v, err
}

// Get returns one version.
func (s *PostgresStore) Get(ctx context.Context, version int64) (*Version, error) {
	var rows []versionRow
	err := s.db.WithContext(ctx).Raw(
		`SELECT version, rules, note, created_by, created_at FROM policy_versions WHERE version = ?`,
		version,
	).Scan(&rows).Error
	if err != nil {
		return nil, err
	}
	if len(rows) == 0 {
		return nil, ErrVersionNotFound
	}
	var rules []Rule
	if err := json.Unmarshal(rows[0].Rules, &rules); err != nil {
		return nil, fmt.Errorf("policy version %d: stored rules unreadable: %w", version, err)
	}
	return &Version{
		Version:   rows[0].Version,
		Rules:     rules,
		Note:      rows[0].Note,
		CreatedBy: rows[0].CreatedBy,
		CreatedAt: rows[0].CreatedAt,
	}, nil
}

// List returns version summaries, newest first.
func (s *PostgresStore) List(ctx context.Context, limit int, before int64) ([]VersionSummary, error) {
	q := `SELECT version, note, created_by, created_at, jsonb_array_length(rules) AS rule_count
	      FROM policy_versions`
	args := []any{}
	if before > 0 {
		q += ` WHERE version < ?`
		args = append(args, before)
	}
	q += ` ORDER BY version DESC LIMIT ?`
	args = append(args, limit)

	var rows []versionRow
	if err := s.db.WithContext(ctx).Raw(q, args...).Scan(&rows).Error; err != nil {
		return nil, err
	}
	out := make([]VersionSummary, len(rows))
	for i, r := range rows {
		out[i] = VersionSummary{Version: r.Version, Note: r.Note, CreatedBy: r.CreatedBy,
			CreatedAt: r.CreatedAt, RuleCount: r.RuleCount}
	}
	return out, nil
}

// Insert stores v. The primary key is the version number, so two editors who
// both started from version N cannot both create N+1: the second insert
// affects no row and is reported as a conflict.
func (s *PostgresStore) Insert(ctx context.Context, v *Version) error {
	raw, err := json.Marshal(v.Rules)
	if err != nil {
		return err
	}
	res := s.db.WithContext(ctx).Exec(
		`INSERT INTO policy_versions (version, rules, note, created_by, created_at)
		 VALUES (?, ?::jsonb, ?, ?, ?)
		 ON CONFLICT (version) DO NOTHING`,
		v.Version, string(raw), v.Note, v.CreatedBy, v.CreatedAt,
	)
	if res.Error != nil {
		return res.Error
	}
	if res.RowsAffected == 0 {
		return ErrVersionConflict
	}
	return nil
}

// AppendDecision writes one decision-log row.
func (s *PostgresStore) AppendDecision(ctx context.Context, r *DecisionRecord) error {
	return s.db.WithContext(ctx).Exec(
		`INSERT INTO policy_decisions (
			created_at, correlation_id, source, mode, enforced, allow, divergence,
			action, rule_id, reason, policy_version, principal_kind, principal_id,
			client_id, resource_type, resource_id, ip_address, status_code, obligations
		) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		r.CreatedAt, r.CorrelationID, r.Source, r.Mode, r.Enforced, r.Allow, r.Divergence,
		r.Action, r.Rule, r.Reason, r.PolicyVersion, r.PrincipalKind, r.PrincipalID,
		r.ClientID, r.ResourceType, r.ResourceID, r.IPAddress, r.StatusCode,
		// Never NULL: StringArray writes a nil slice as NULL, and the column is NOT NULL.
		model.StringArray(append([]string{}, r.Obligations...)),
	).Error
}

type decisionRow struct {
	ID            int64
	CreatedAt     time.Time
	CorrelationID string
	Source        string
	Mode          string
	Enforced      bool
	Allow         bool
	Divergence    string
	Action        string
	RuleID        string
	Reason        string
	PolicyVersion int64
	PrincipalKind string
	PrincipalID   *uint
	ClientID      string
	ResourceType  string
	ResourceID    string
	IPAddress     string
	StatusCode    int
	Obligations   model.StringArray `gorm:"type:text[]"`
}

// Decisions queries the decision log, newest first.
func (s *PostgresStore) Decisions(ctx context.Context, f DecisionFilter) ([]DecisionRecord, error) {
	q := s.db.WithContext(ctx).Table("policy_decisions").Order("id DESC").Limit(f.Limit)
	if f.CorrelationID != "" {
		q = q.Where("correlation_id = ?", f.CorrelationID)
	}
	if f.Allow != nil {
		q = q.Where("allow = ?", *f.Allow)
	}
	if f.DivergenceOnly {
		q = q.Where("divergence <> ''")
	}
	if !f.Since.IsZero() {
		q = q.Where("created_at >= ?", f.Since)
	}
	if f.BeforeID > 0 {
		q = q.Where("id < ?", f.BeforeID)
	}
	if f.Source != "" {
		q = q.Where("source = ?", f.Source)
	}
	if f.ClientID != "" {
		q = q.Where("client_id = ?", f.ClientID)
	}

	var rows []decisionRow
	if err := q.Find(&rows).Error; err != nil {
		return nil, err
	}
	out := make([]DecisionRecord, len(rows))
	for i, r := range rows {
		out[i] = DecisionRecord{
			ID: r.ID, CreatedAt: r.CreatedAt, CorrelationID: r.CorrelationID, Source: r.Source,
			Mode: r.Mode, Enforced: r.Enforced, Allow: r.Allow, Divergence: r.Divergence,
			Action: r.Action, Rule: r.RuleID, Reason: r.Reason, PolicyVersion: r.PolicyVersion,
			PrincipalKind: r.PrincipalKind, PrincipalID: r.PrincipalID, ClientID: r.ClientID,
			ResourceType: r.ResourceType, ResourceID: r.ResourceID, IPAddress: r.IPAddress,
			StatusCode: r.StatusCode,
		}
		if len(r.Obligations) > 0 {
			out[i].Obligations = []string(r.Obligations)
		}
	}
	return out, nil
}

// SweepDecisions deletes decision-log rows older than before.
func (s *PostgresStore) SweepDecisions(ctx context.Context, before time.Time) (int64, error) {
	res := s.db.WithContext(ctx).Exec(`DELETE FROM policy_decisions WHERE created_at < ?`, before)
	return res.RowsAffected, res.Error
}

// SummarizeDecisions counts decision-log rows since the given time, grouped in
// the database so the cost does not grow with the number of rows returned.
func (s *PostgresStore) SummarizeDecisions(ctx context.Context, since time.Time) (DecisionSummary, error) {
	var rows []struct {
		Source     string
		Allow      bool
		Enforced   bool
		Divergence string
		N          int64
	}
	err := s.db.WithContext(ctx).Raw(
		`SELECT source, allow, enforced, divergence, count(*) AS n
		 FROM policy_decisions WHERE created_at >= ?
		 GROUP BY source, allow, enforced, divergence`, since,
	).Scan(&rows).Error
	if err != nil {
		return DecisionSummary{}, err
	}
	sum := newDecisionSummary(since)
	for _, r := range rows {
		sum.addSummaryRow(r.Source, r.Allow, r.Enforced, r.Divergence, r.N)
	}
	return sum, nil
}
