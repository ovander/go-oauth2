// Package http — A4 part 2: the decide endpoint for applications, driven
// through the real admin router with real service-account and user tokens.
package http

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	nethttp "net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/ovander/go-oauth2/internal/handler"
	"github.com/ovander/go-oauth2/internal/model"
	"github.com/ovander/go-oauth2/internal/policy"
	"github.com/ovander/go-oauth2/internal/repository"
	"github.com/ovander/go-oauth2/internal/shared/auth"
)

type decideUsers struct {
	repository.UserRepository
	users map[uint]*model.User
}

func (r *decideUsers) FindByID(_ context.Context, id uint) (*model.User, error) {
	if u, ok := r.users[id]; ok {
		return u, nil
	}
	return nil, errors.New("user not found")
}

type decideApps struct {
	repository.AppRepository
	apps map[uint]*model.App
}

func (r *decideApps) FindByID(_ context.Context, id uint) (*model.App, error) {
	if a, ok := r.apps[id]; ok {
		return a, nil
	}
	return nil, errors.New("app not found")
}

type decideRoles struct {
	repository.UserAppRoleRepository
	roles map[[2]uint]model.AppRole
}

func (r *decideRoles) FindByUserAndApp(_ context.Context, userID, appID uint) (*model.UserAppRole, error) {
	if role, ok := r.roles[[2]uint{userID, appID}]; ok {
		return &model.UserAppRole{UserID: userID, AppID: appID, Role: role}, nil
	}
	return nil, errors.New("record not found")
}

type decideFixture struct {
	h       nethttp.Handler
	ts      *auth.TokenService
	store   *policy.MemoryStore
	billing *model.App
	crm     *model.App
	alice   *model.User // billing admin, attribute department=finance
	bob     *model.User // CRM member only
	carol   *model.User // billing member, locked
	root    *model.User // global admin, no per-app rows
}

// billingRules allow invoice approval to billing's admins in finance, with
// MFA required, and deny it over 10k to anyone without the "approver" group.
const billingRules = `[
	{"id":"billing-admins-approve","effect":"allow","actions":["invoice.approve"],
	 "when":{"all":[
		{"attr":"app.client_id","op":"eq","value":"billing"},
		{"attr":"principal.app_role","op":"eq","value":"admin"},
		{"attr":"principal.attributes.department","op":"eq","value":"finance"}]},
	 "obligations":["require_mfa"]},
	{"id":"large-invoices-need-approver","effect":"deny","actions":["invoice.approve"],
	 "when":{"all":[
		{"attr":"resource.attributes.amount","op":"gt","value":10000},
		{"not":{"attr":"principal.attributes.groups","op":"contains","value":"approver"}}]}},
	{"id":"apps-read-themselves","effect":"allow","actions":["app.self-check"],
	 "when":{"attr":"principal.kind","op":"eq","value":"client"}},
	{"id":"office-only","effect":"deny","actions":["report.export"],
	 "when":{"not":{"attr":"context.ip_country","op":"in","value":["BE"]}}},
	{"id":"exports","effect":"allow","actions":["report.export"]},
	{"id":"refunds-need-mfa","effect":"deny","actions":["refund.issue"],
	 "when":{"not":{"attr":"principal.amr","op":"contains","value":"mfa"}}},
	{"id":"refunds","effect":"allow","actions":["refund.issue"]}
]`

func newDecideFixture(t *testing.T, mode policy.Mode) *decideFixture {
	t.Helper()
	ts := p31TokenService(t)
	f := &decideFixture{
		ts:      ts,
		billing: &model.App{ID: 3, ClientID: "billing", Active: true},
		crm:     &model.App{ID: 4, ClientID: "crm", Active: true},
		alice: &model.User{ID: 10, Role: model.UserRoleUser, IsVerified: true,
			Attributes: model.JSONMap{"department": "finance", "groups": []any{"staff"}}},
		bob:  &model.User{ID: 11, Role: model.UserRoleUser, IsVerified: true},
		root: &model.User{ID: 1, Role: model.UserRoleSuperadmin, IsVerified: true},
	}
	lockedUntil := time.Now().Add(time.Hour)
	f.carol = &model.User{ID: 12, Role: model.UserRoleUser, IsVerified: true, LockedUntil: &lockedUntil}

	var rules []policy.Rule
	if err := json.Unmarshal([]byte(billingRules), &rules); err != nil {
		t.Fatal(err)
	}
	f.store = policy.NewMemoryStore()
	pdp := policy.NewService(f.store, mode, time.Nanosecond)
	if _, err := pdp.Save(context.Background(), 0, rules, "", 1); err != nil {
		t.Fatal(err)
	}

	users := &decideUsers{users: map[uint]*model.User{10: f.alice, 11: f.bob, 12: f.carol, 1: f.root}}
	roles := &decideRoles{roles: map[[2]uint]model.AppRole{
		{10, 3}: model.AppRoleAdmin,
		{11, 4}: "user",
		{12, 3}: "user",
	}}
	decide := handler.NewPolicyDecideHandler(pdp, ts, users, nil, roles)
	decide.SetCountryLookup(func(ip string) string {
		if strings.HasPrefix(ip, "192.0.2.") {
			return "BE"
		}
		return "US"
	})
	f.h = newAdminRouter(nil, nil, nil, nil, nil, nil, nil, nil, nil, nil,
		ts, users, nil, roles, &decideApps{apps: map[uint]*model.App{3: f.billing, 4: f.crm}},
		RouterConfig{PolicyDecideHandler: decide})
	return f
}

func (f *decideFixture) serviceToken(t *testing.T, app *model.App) string {
	t.Helper()
	tok, err := f.ts.GenerateClientCredentialsToken(app, "")
	if err != nil {
		t.Fatal(err)
	}
	return tok
}

func (f *decideFixture) userToken(t *testing.T, u *model.User, amr ...string) string {
	t.Helper()
	set, err := f.ts.GenerateTokenSetWithAuth(u, f.billing, string(u.Role), "openid", nil, "", time.Now().Unix(), amr, "")
	if err != nil {
		t.Fatal(err)
	}
	return set.AccessToken
}

type decideResult struct {
	code int
	body string
	resp struct {
		Allow       bool     `json:"allow"`
		Rule        string   `json:"rule"`
		Reason      string   `json:"reason"`
		Obligations []string `json:"obligations"`
		Mode        string   `json:"mode"`
		Error       string   `json:"error"`
		PEPAccepted bool     `json:"pep_mode_accepted"`
	}
}

func (f *decideFixture) decide(t *testing.T, appID, bearer, body string, headers ...string) decideResult {
	t.Helper()
	req := httptest.NewRequest(nethttp.MethodPost, "/api/apps/"+appID+"/service/policy/decide", strings.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+bearer)
	req.Header.Set("Content-Type", "application/json")
	for i := 0; i+1 < len(headers); i += 2 {
		req.Header.Set(headers[i], headers[i+1])
	}
	rr := httptest.NewRecorder()
	f.h.ServeHTTP(rr, req)
	var res decideResult
	res.code, res.body = rr.Code, strings.TrimSpace(rr.Body.String())
	_ = json.Unmarshal(rr.Body.Bytes(), &res.resp)
	return res
}

func TestDecide_SubjectToken_ResolvesRoleAttributesAndTokenFacts(t *testing.T) {
	f := newDecideFixture(t, policy.ModeShadow)
	svc := f.serviceToken(t, f.billing)
	body := `{"subject":{"token":"` + f.userToken(t, f.alice, "pwd") + `"},"action":"invoice.approve","resource":{"type":"invoice","id":"inv-1","attributes":{"amount":250}}}`

	r := f.decide(t, "3", svc, body)
	if r.code != 200 || !r.resp.Allow || r.resp.Rule != "billing-admins-approve" || r.resp.Mode != "shadow" {
		t.Fatalf("alice approving a small invoice → %d %s", r.code, r.body)
	}
	// The obligation is returned for the application's PEP to honour.
	if len(r.resp.Obligations) != 1 || r.resp.Obligations[0] != policy.ObligationMFA {
		t.Fatalf("obligations = %v, want [require_mfa]", r.resp.Obligations)
	}

	// Over 10k without the approver group: the deny overrides.
	body = strings.Replace(body, `"amount":250`, `"amount":25000`, 1)
	r = f.decide(t, "3", svc, body, "X-Correlation-ID", "corr-big-invoice")
	if r.resp.Allow || r.resp.Rule != "large-invoices-need-approver" {
		t.Fatalf("large invoice → %s", r.body)
	}
	// Two rows: the small invoice's allow, whose require_mfa this
	// password-only token does not meet (see TestDecide_UnmetObligation_…),
	// then the large invoice's deny.
	d, _ := f.store.Decisions(context.Background(), policy.DecisionFilter{CorrelationID: "corr-big-invoice"})
	if all, _ := f.store.Decisions(context.Background(), policy.DecisionFilter{}); len(all) != 2 {
		t.Fatalf("decision log has %d rows, want 2: %+v", len(all), all)
	}
	if len(d) != 1 || d[0].Source != policy.SourceDecideAPI || d[0].ClientID != "billing" ||
		d[0].CorrelationID != "corr-big-invoice" || d[0].PrincipalID == nil || *d[0].PrincipalID != 10 ||
		d[0].ResourceID != "inv-1" || d[0].Enforced {
		t.Fatalf("decision log = %+v", d)
	}
}

// An allow whose obligation the subject's token does not meet is answered as
// an allow (the application's PEP honours the obligation), and logged as the
// refusal that PEP will make, so shadow mode shows who lacks MFA.
func TestDecide_UnmetObligation_IsLoggedNotAnswered(t *testing.T) {
	f := newDecideFixture(t, policy.ModeShadow)
	svc := f.serviceToken(t, f.billing)
	approve := func(subject string) decideResult {
		return f.decide(t, "3", svc, `{"subject":`+subject+`,"action":"invoice.approve","resource":{"type":"invoice","id":"inv-7","attributes":{"amount":250}}}`)
	}

	r := approve(`{"token":"` + f.userToken(t, f.alice, "pwd") + `"}`)
	if r.code != 200 || !r.resp.Allow || len(r.resp.Obligations) != 1 {
		t.Fatalf("the answer must stay an allow with its obligation: %d %s", r.code, r.body)
	}
	d, _ := f.store.Decisions(context.Background(), policy.DecisionFilter{})
	if len(d) != 1 {
		t.Fatalf("want one logged row, got %+v", d)
	}
	row := d[0]
	if row.Allow || row.Reason != policy.ReasonObligationUnmet+":"+policy.ObligationMFA ||
		row.Rule != "billing-admins-approve" || len(row.Obligations) != 1 || row.Obligations[0] != policy.ObligationMFA ||
		row.PrincipalID == nil || *row.PrincipalID != 10 || row.ResourceID != "inv-7" {
		t.Fatalf("logged row = %+v", row)
	}

	// Met (an MFA token), or unknowable (a bare user id: the application's
	// PEP checks a token Socrate has not seen): nothing more is logged.
	approve(`{"token":"` + f.userToken(t, f.alice, "pwd", "otp", "mfa") + `"}`)
	approve(`{"user_id":10}`)
	if d, _ := f.store.Decisions(context.Background(), policy.DecisionFilter{}); len(d) != 1 {
		t.Fatalf("met or unknowable obligations must not be logged: %+v", d)
	}
}

func TestDecide_UserID_HasNoTokenFacts_SoTheyAreUnknown(t *testing.T) {
	f := newDecideFixture(t, policy.ModeShadow)
	svc := f.serviceToken(t, f.billing)
	// Same small invoice, by user id: role and attributes resolve, so the
	// allow applies.
	r := f.decide(t, "3", svc, `{"subject":{"user_id":10},"action":"invoice.approve","resource":{"attributes":{"amount":250}}}`)
	if r.code != 200 || !r.resp.Allow {
		t.Fatalf("by user id → %d %s", r.code, r.body)
	}

	// But a rule on how they authenticated cannot be satisfied by a bare
	// user id: amr is unknown, and the deny that depends on it applies.
	r = f.decide(t, "3", svc, `{"subject":{"user_id":10},"action":"refund.issue"}`)
	if r.resp.Allow || r.resp.Reason != policy.ReasonIndeterminate {
		t.Fatalf("refund by user id → %s, want an indeterminate deny", r.body)
	}
	r = f.decide(t, "3", svc, `{"subject":{"token":"`+f.userToken(t, f.alice, "pwd")+`"},"action":"refund.issue"}`)
	if r.resp.Allow || r.resp.Reason != policy.ReasonDenied {
		t.Fatalf("refund with a password-only token → %s, want a definite deny", r.body)
	}
	r = f.decide(t, "3", svc, `{"subject":{"token":"`+f.userToken(t, f.alice, "pwd", "otp", "mfa")+`"},"action":"refund.issue"}`)
	if !r.resp.Allow {
		t.Fatalf("refund with an MFA token → %s, want allow", r.body)
	}
}

// An application can only ask about its own users. "Not a member" and "no
// such user" must be indistinguishable.
func TestDecide_SubjectMustBelongToTheCallingApp(t *testing.T) {
	f := newDecideFixture(t, policy.ModeShadow)
	svc := f.serviceToken(t, f.billing)

	notMember := f.decide(t, "3", svc, `{"subject":{"user_id":11},"action":"invoice.approve"}`)
	noSuchUser := f.decide(t, "3", svc, `{"subject":{"user_id":999},"action":"invoice.approve"}`)
	if notMember.code != nethttp.StatusNotFound || noSuchUser.code != nethttp.StatusNotFound || notMember.body != noSuchUser.body {
		t.Fatalf("not a member → %d %s; no such user → %d %s; want identical 404s",
			notMember.code, notMember.body, noSuchUser.code, noSuchUser.body)
	}
	// Bob's own token doesn't help either: membership, not possession, decides.
	r := f.decide(t, "3", svc, `{"subject":{"token":"`+f.userToken(t, f.bob)+`"},"action":"invoice.approve"}`)
	if r.code != nethttp.StatusNotFound {
		t.Fatalf("non-member's token → %d %s", r.code, r.body)
	}
	// A global admin has implicit access to every application.
	if r := f.decide(t, "3", svc, `{"subject":{"user_id":1},"action":"invoice.approve"}`); r.code != 200 {
		t.Fatalf("global admin → %d %s", r.code, r.body)
	}
}

func TestDecide_TheCallerMustBeTheApp(t *testing.T) {
	f := newDecideFixture(t, policy.ModeShadow)
	body := `{"subject":{"user_id":10},"action":"invoice.approve"}`

	// CRM's service token cannot ask on billing's behalf.
	if r := f.decide(t, "3", f.serviceToken(t, f.crm), body); r.code != nethttp.StatusForbidden {
		t.Fatalf("crm token on billing's route → %d", r.code)
	}
	// A user's token is not a service-account token.
	if r := f.decide(t, "3", f.userToken(t, f.alice), body); r.code != nethttp.StatusForbidden {
		t.Fatalf("user token as caller → %d", r.code)
	}
	if r := f.decide(t, "3", "garbage", body); r.code != nethttp.StatusUnauthorized {
		t.Fatalf("garbage caller token → %d", r.code)
	}
	// And a service token is not a user: it cannot be passed off as a subject.
	svc := f.serviceToken(t, f.billing)
	if r := f.decide(t, "3", svc, `{"subject":{"token":"`+svc+`"},"action":"invoice.approve"}`); r.code != nethttp.StatusBadRequest {
		t.Fatalf("service token as subject → %d %s", r.code, r.body)
	}
}

func TestDecide_LockedSubject_IsDeniedWithoutEvaluation(t *testing.T) {
	f := newDecideFixture(t, policy.ModeEnforce)
	svc := f.serviceToken(t, f.billing)
	for name, body := range map[string]string{
		"user_id": `{"subject":{"user_id":12},"action":"report.export","context":{"ip":"192.0.2.9"}}`,
		"token":   `{"subject":{"token":"` + f.userToken(t, f.carol) + `"},"action":"report.export","context":{"ip":"192.0.2.9"}}`,
	} {
		r := f.decide(t, "3", svc, body)
		if r.code != 200 || r.resp.Allow || r.resp.Reason != policy.ReasonSubjectLocked {
			t.Errorf("%s: locked subject → %d %s", name, r.code, r.body)
		}
	}
}

func TestDecide_NoSubject_TheAppIsThePrincipal(t *testing.T) {
	f := newDecideFixture(t, policy.ModeShadow)
	r := f.decide(t, "3", f.serviceToken(t, f.billing), `{"action":"app.self-check"}`)
	if r.code != 200 || !r.resp.Allow {
		t.Fatalf("client principal → %d %s", r.code, r.body)
	}
}

func TestDecide_CountryFromCallerReportedIP(t *testing.T) {
	f := newDecideFixture(t, policy.ModeShadow)
	svc := f.serviceToken(t, f.billing)
	if r := f.decide(t, "3", svc, `{"subject":{"user_id":10},"action":"report.export","context":{"ip":"192.0.2.9"}}`); !r.resp.Allow {
		t.Fatalf("BE → %s", r.body)
	}
	if r := f.decide(t, "3", svc, `{"subject":{"user_id":10},"action":"report.export","context":{"ip":"198.51.100.4"}}`); r.resp.Allow || r.resp.Rule != "office-only" {
		t.Fatalf("US → %s", r.body)
	}
	// No IP at all: the country is unknown, so the deny applies.
	if r := f.decide(t, "3", svc, `{"subject":{"user_id":10},"action":"report.export"}`); r.resp.Allow || r.resp.Reason != policy.ReasonIndeterminate {
		t.Fatalf("no IP → %s", r.body)
	}
}

func TestDecide_RejectsMalformedRequests(t *testing.T) {
	f := newDecideFixture(t, policy.ModeShadow)
	svc := f.serviceToken(t, f.billing)
	keys := make([]string, 65)
	for i := range keys {
		keys[i] = fmt.Sprintf("%q:1", fmt.Sprintf("k%d", i))
	}
	many := "{" + strings.Join(keys, ",") + "}"
	for name, body := range map[string]string{
		"no action":             `{"subject":{"user_id":10}}`,
		"admin namespace":       `{"subject":{"user_id":10},"action":"DELETE /api/admin/apps/{id}"}`,
		"both subjects":         `{"subject":{"user_id":10,"token":"x"},"action":"a"}`,
		"misspelt field":        `{"subjet":{"user_id":10},"action":"a"}`,
		"too many attributes":   `{"action":"a","resource":{"attributes":` + many + `}}`,
		"invalid subject token": `{"subject":{"token":"not-a-jwt"},"action":"a"}`,
	} {
		if r := f.decide(t, "3", svc, body); r.code != nethttp.StatusBadRequest {
			t.Errorf("%s → %d %s, want 400", name, r.code, r.body)
		}
	}
	// A look-alike that is not the admin namespace is fine.
	if r := f.decide(t, "3", svc, `{"subject":{"user_id":10},"action":"GET /api/administrators"}`); r.code != 200 {
		t.Errorf("non-admin path action → %d %s", r.code, r.body)
	}
}

func TestDecide_ModeOff_AnswersButRecordsNothing(t *testing.T) {
	f := newDecideFixture(t, policy.ModeOff)
	r := f.decide(t, "3", f.serviceToken(t, f.billing), `{"subject":{"user_id":10},"action":"nothing.covers.this"}`)
	if r.code != 200 || r.resp.Mode != "off" || r.resp.Allow {
		t.Fatalf("off → %d %s", r.code, r.body)
	}
	if d, _ := f.store.Decisions(context.Background(), policy.DecisionFilter{}); len(d) != 0 {
		t.Fatalf("mode off recorded %d decisions", len(d))
	}
}

func TestDecide_NoPolicy_Is503(t *testing.T) {
	f := newDecideFixture(t, policy.ModeEnforce)
	// Swap in an empty PDP by building a fresh router over an empty store.
	users := &decideUsers{users: map[uint]*model.User{10: f.alice}}
	roles := &decideRoles{roles: map[[2]uint]model.AppRole{{10, 3}: model.AppRoleAdmin}}
	empty := policy.NewService(policy.NewMemoryStore(), policy.ModeEnforce, time.Nanosecond)
	f.h = newAdminRouter(nil, nil, nil, nil, nil, nil, nil, nil, nil, nil,
		f.ts, users, nil, roles, &decideApps{apps: map[uint]*model.App{3: f.billing}},
		RouterConfig{PolicyDecideHandler: handler.NewPolicyDecideHandler(empty, f.ts, users, nil, roles)})

	r := f.decide(t, "3", f.serviceToken(t, f.billing), `{"subject":{"user_id":10},"action":"a"}`)
	if r.code != nethttp.StatusServiceUnavailable || r.resp.Error != "policy_unavailable" || r.resp.Mode != "enforce" {
		t.Fatalf("no policy → %d %s", r.code, r.body)
	}
}
