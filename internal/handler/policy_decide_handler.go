package handler

import (
	"encoding/json"
	"errors"
	"net/http"
	"regexp"
	"strings"

	"github.com/ovandermoten/go-oauth2/internal/dto"
	"github.com/ovandermoten/go-oauth2/internal/metrics"
	"github.com/ovandermoten/go-oauth2/internal/middleware"
	"github.com/ovandermoten/go-oauth2/internal/model"
	"github.com/ovandermoten/go-oauth2/internal/policy"
	"github.com/ovandermoten/go-oauth2/internal/repository"
	"github.com/ovandermoten/go-oauth2/internal/shared/auth"
)

// Bounds on what an application may send. The body is already capped by
// MaxRequestBody; these keep one decision from carrying an attribute map large
// enough to make evaluation the expensive part.
const (
	maxDecideActionLen   = 256
	maxDecideAttributes  = 64
	maxDecideResourceLen = 256
)

// adminActionPattern matches the admin API's action namespace. Those actions
// are decided only by the admin enforcement point, on the admin API's own
// requests; an application asking about them would be probing the admin
// policy, not deciding anything of its own.
var adminActionPattern = regexp.MustCompile(`^[A-Z]+ ` + regexp.QuoteMeta(policy.AdminPrefix) + `(/|$)`)

// PolicyDecideHandler serves POST /api/apps/{app_id}/service/policy/decide
// (A4 part 2): an application's backend asks the PDP about one of its own
// users. It sits behind ServiceAccountMiddleware, so the caller is an active
// application proven by its client-credentials token and pinned to the
// {app_id} in the URL.
//
// Who the subject is — role, attributes, membership, token facts — is always
// resolved here, from Socrate's own records. The application supplies the
// action, the resource and the request context: facts about its own domain
// that only it knows. It cannot assert anything about the user.
type PolicyDecideHandler struct {
	pdp             *policy.Service
	tokenService    *auth.TokenService
	userRepo        repository.UserRepository
	usedTokenRepo   repository.UsedTokenRepository
	userAppRoleRepo repository.UserAppRoleRepository
	countryOf       func(ip string) string
}

func NewPolicyDecideHandler(
	pdp *policy.Service,
	tokenService *auth.TokenService,
	userRepo repository.UserRepository,
	usedTokenRepo repository.UsedTokenRepository,
	userAppRoleRepo repository.UserAppRoleRepository,
) *PolicyDecideHandler {
	return &PolicyDecideHandler{
		pdp:             pdp,
		tokenService:    tokenService,
		userRepo:        userRepo,
		usedTokenRepo:   usedTokenRepo,
		userAppRoleRepo: userAppRoleRepo,
	}
}

// SetCountryLookup supplies context.ip_country from the caller-reported IP.
func (h *PolicyDecideHandler) SetCountryLookup(fn func(ip string) string) { h.countryOf = fn }

// errUnknownSubject is deliberately the same for "no such user" and "not a
// member of your application": an application must not be able to use the
// decide endpoint to find out which user ids exist elsewhere.
var errUnknownSubject = errors.New("unknown subject")

// POST /api/apps/{app_id}/service/policy/decide
func (h *PolicyDecideHandler) Decide(w http.ResponseWriter, r *http.Request) {
	app, ok := middleware.GetServiceAccountAppFromContext(r.Context())
	if !ok || app == nil {
		writeError(w, "service account required", http.StatusUnauthorized)
		return
	}

	var req dto.PolicyDecideRequest
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields() // a misspelt "subjet" must not silently become "no subject"
	if err := dec.Decode(&req); err != nil {
		writeError(w, "invalid JSON: "+err.Error(), http.StatusBadRequest)
		return
	}
	if msg := validateDecideRequest(&req); msg != "" {
		writeError(w, msg, http.StatusBadRequest)
		return
	}

	in := policy.Input{
		App:      &policy.App{ID: app.ID, ClientID: app.ClientID},
		Action:   req.Action,
		Resource: req.Resource,
		Context:  policy.Env{IP: req.Context.IP, Attributes: req.Context.Attributes},
	}
	if h.countryOf != nil && in.Context.IP != "" {
		in.Context.IPCountry = h.countryOf(in.Context.IP)
	}

	principal, locked, err := h.resolveSubject(r, app, req.Subject)
	switch {
	case errors.Is(err, errUnknownSubject):
		writeError(w, err.Error(), http.StatusNotFound)
		return
	case err != nil:
		writeError(w, err.Error(), http.StatusBadRequest)
		return
	}
	in.Principal = principal

	mode := h.pdp.Mode()
	var d policy.Decision
	if locked {
		d = policy.Decision{Allow: false, Reason: policy.ReasonSubjectLocked}
	} else {
		d, err = h.pdp.Decide(r.Context(), in)
		if err != nil {
			metrics.PolicyDecision(policy.SourceDecideAPI, string(mode), "error")
			if mode != policy.ModeOff {
				h.record(r, app, &in, d, mode, http.StatusServiceUnavailable)
			}
			w.WriteHeader(http.StatusServiceUnavailable)
			writeJSON(w, map[string]string{"error": "policy_unavailable", "mode": string(mode)})
			return
		}
	}

	outcome := "allow"
	if !d.Allow {
		outcome = "deny"
	}
	metrics.PolicyDecision(policy.SourceDecideAPI, string(mode), outcome)
	// Off means nothing is being consulted: the application's enforcement
	// point will ignore this answer, so it is not evidence of anything.
	if mode != policy.ModeOff && !d.Allow {
		h.record(r, app, &in, d, mode, http.StatusOK)
	}

	writeJSON(w, dto.PolicyDecideResponse{Decision: d, Mode: string(mode)})
}

// resolveSubject builds the principal from Socrate's records. It reports
// locked when the subject exists but its account is locked.
func (h *PolicyDecideHandler) resolveSubject(r *http.Request, app *model.App, s *dto.PolicySubject) (policy.Principal, bool, error) {
	if s == nil || (s.Token == "" && s.UserID == 0) {
		// The application asking about itself.
		return policy.Principal{Kind: policy.PrincipalClient, ID: app.ID, ClientID: app.ClientID}, false, nil
	}
	if s.Token != "" && s.UserID != 0 {
		return policy.Principal{}, false, errors.New("subject: give token or user_id, not both")
	}

	var (
		user   *model.User
		claims *auth.AccessTokenClaims
		locked bool
	)
	if s.Token != "" {
		u, c, terr := middleware.VerifyUserToken(r.Context(), h.tokenService, h.userRepo, h.usedTokenRepo, s.Token)
		switch {
		case terr != nil && terr.Detail == middleware.UserTokenLocked:
			// A valid token for a locked account: the user is known, and
			// membership is still checked below, but nothing is evaluated.
			user, locked = u, true
		case terr != nil:
			// A subject token that fails any check is the application's
			// problem to report, not an authorisation decision: a revoked
			// or expired token means the user has no session to decide for.
			return policy.Principal{}, false, errors.New("invalid subject token: " + terr.Message)
		default:
			user, claims = u, c
		}
	} else {
		u, err := h.userRepo.FindByID(r.Context(), s.UserID)
		if err != nil {
			return policy.Principal{}, false, errUnknownSubject
		}
		user, locked = u, u.IsLocked()
	}

	// The subject must belong to the calling application. Global admins have
	// implicit access to every application and never hold per-app rows.
	appRole := ""
	if role, err := h.userAppRoleRepo.FindByUserAndApp(r.Context(), user.ID, app.ID); err == nil && role != nil {
		appRole = string(role.Role)
	} else if !user.IsGlobalAdmin() {
		return policy.Principal{}, false, errUnknownSubject
	}

	p := policy.Principal{
		Kind:               policy.PrincipalUser,
		ID:                 user.ID,
		Role:               string(user.Role),
		AppRole:            appRole,
		Attributes:         map[string]any(user.Attributes),
		MustChangePassword: user.MustChangePassword,
	}
	if claims != nil {
		// Token facts are only known when the token was presented. With a
		// bare user id they stay absent, so a rule that needs them evaluates
		// to unknown — which a deny rule treats as a deny.
		p.Scopes = strings.Fields(claims.Scope)
		p.AMR = claims.Amr
		if p.AMR == nil {
			p.AMR = []string{}
		}
		p.AuthTime = claims.AuthTime
		if len(claims.Audience) > 0 {
			p.ClientID = claims.Audience[0]
		}
	}
	return p, locked, nil
}

func (h *PolicyDecideHandler) record(r *http.Request, app *model.App, in *policy.Input, d policy.Decision, mode policy.Mode, status int) {
	rec := &policy.DecisionRecord{
		CorrelationID: middleware.GetCorrelationID(r.Context()),
		Source:        policy.SourceDecideAPI,
		Mode:          string(mode),
		Enforced:      mode == policy.ModeEnforce,
		Allow:         d.Allow,
		Action:        in.Action,
		Rule:          d.Rule,
		Reason:        d.Reason,
		PolicyVersion: d.Version,
		PrincipalKind: in.Principal.Kind,
		// The calling application, whoever the principal is: this is the
		// column a SOC analyst filters on to see one application's denials.
		ClientID:     app.ClientID,
		ResourceType: in.Resource.Type,
		ResourceID:   in.Resource.ID,
		IPAddress:    in.Context.IP,
		StatusCode:   status,
	}
	if in.Principal.ID != 0 {
		id := in.Principal.ID
		rec.PrincipalID = &id
	}
	h.pdp.Record(r.Context(), rec)
}

func validateDecideRequest(req *dto.PolicyDecideRequest) string {
	switch {
	case req.Action == "":
		return "action is required"
	case len(req.Action) > maxDecideActionLen:
		return "action is too long"
	case adminActionPattern.MatchString(req.Action):
		return "actions under " + policy.AdminPrefix + " are reserved for the admin API"
	case len(req.Resource.Type) > maxDecideResourceLen || len(req.Resource.ID) > maxDecideResourceLen:
		return "resource type and id must be at most 256 characters"
	case len(req.Resource.Attributes) > maxDecideAttributes:
		return "resource.attributes: too many keys"
	case len(req.Context.Attributes) > maxDecideAttributes:
		return "context.attributes: too many keys"
	}
	return ""
}
