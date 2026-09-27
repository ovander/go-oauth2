package handler

import (
	"encoding/json"
	"errors"
	"net/http"
	"sort"
	"strconv"
	"sync"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/ovandermoten/go-oauth2/internal/contextkeys"
	"github.com/ovandermoten/go-oauth2/internal/dto"
	"github.com/ovandermoten/go-oauth2/internal/middleware"
	"github.com/ovandermoten/go-oauth2/internal/model"
	"github.com/ovandermoten/go-oauth2/internal/policy"
	"github.com/ovandermoten/go-oauth2/internal/service"
)

// PolicyHandler serves the policy administration API (A4).
//
// Every route is superadmin-only, and the router adds fresh step-up to the
// writes: whoever can edit the policy can, in enforce mode, lock every other
// admin out, so this is the most privileged surface in the admin API. For the
// same reason these routes are exempt from the policy they edit — a bad rule
// must never be able to make itself unfixable.
type PolicyHandler struct {
	pdp             *policy.Service
	adminLogService service.AdminLogService

	mu            sync.RWMutex
	adminActions  []string
	exemptActions []string
}

func NewPolicyHandler(pdp *policy.Service, adminLogService service.AdminLogService) *PolicyHandler {
	return &PolicyHandler{pdp: pdp, adminLogService: adminLogService}
}

// SetAdminActions records the admin API's action catalogue. The router calls
// it once its routes are registered, since only the router knows them.
func (h *PolicyHandler) SetAdminActions(actions, exempt []string) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.adminActions = append([]string(nil), actions...)
	h.exemptActions = append([]string(nil), exempt...)
	sort.Strings(h.adminActions)
	sort.Strings(h.exemptActions)
}

func (h *PolicyHandler) requireSuperadmin(w http.ResponseWriter, r *http.Request) (uint, bool) {
	adminID, ok := middleware.GetUserIDFromContext(r.Context())
	if !ok {
		writeError(w, "unauthorized", http.StatusUnauthorized)
		return 0, false
	}
	user, _ := r.Context().Value(contextkeys.CurrentUserKey).(*model.User)
	if user == nil || user.Role != model.UserRoleSuperadmin {
		writeError(w, "forbidden: superadmin required", http.StatusForbidden)
		return 0, false
	}
	return adminID, true
}

func writePolicyServiceError(w http.ResponseWriter, err error) {
	var vf *policy.ValidationFailed
	switch {
	case errors.As(err, &vf):
		w.WriteHeader(http.StatusUnprocessableEntity)
		writeJSON(w, dto.PolicyValidationResponse{Error: "invalid_policy", Errors: vf.Errors})
	case errors.Is(err, policy.ErrVersionConflict):
		writeError(w, err.Error(), http.StatusConflict)
	case errors.Is(err, policy.ErrVersionNotFound), errors.Is(err, policy.ErrNoPolicy):
		writeError(w, err.Error(), http.StatusNotFound)
	default:
		writeError(w, "policy store error", http.StatusInternalServerError)
	}
}

// GET /api/admin/policy — the current version.
func (h *PolicyHandler) Get(w http.ResponseWriter, r *http.Request) {
	if _, ok := h.requireSuperadmin(w, r); !ok {
		return
	}
	v, err := h.pdp.Current(r.Context())
	if err != nil {
		writePolicyServiceError(w, err)
		return
	}
	writeJSON(w, dto.PolicyResponse{Version: v, Mode: string(h.pdp.Mode())})
}

// PUT /api/admin/policy — save a new version.
func (h *PolicyHandler) Save(w http.ResponseWriter, r *http.Request) {
	adminID, ok := h.requireSuperadmin(w, r)
	if !ok {
		return
	}
	var req dto.SavePolicyRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, "invalid JSON", http.StatusBadRequest)
		return
	}
	v, err := h.pdp.Save(r.Context(), req.BaseVersion, req.Rules, req.Note, adminID)
	if err != nil {
		writePolicyServiceError(w, err)
		return
	}
	h.logAction(r, adminID, model.AdminActionPolicyUpdated, map[string]interface{}{
		"version":      v.Version,
		"base_version": req.BaseVersion,
		"rule_count":   len(v.Rules),
		"note":         v.Note,
	})
	writeJSON(w, dto.PolicyResponse{Version: v, Mode: string(h.pdp.Mode())})
}

// POST /api/admin/policy/validate — check a draft without saving it.
func (h *PolicyHandler) Validate(w http.ResponseWriter, r *http.Request) {
	if _, ok := h.requireSuperadmin(w, r); !ok {
		return
	}
	var req dto.ValidatePolicyRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, "invalid JSON", http.StatusBadRequest)
		return
	}
	if errs := policy.Validate(req.Rules); len(errs) > 0 {
		writePolicyServiceError(w, &policy.ValidationFailed{Errors: errs})
		return
	}
	writeJSON(w, map[string]any{"valid": true, "rule_count": len(req.Rules)})
}

// POST /api/admin/policy/simulate — evaluate an input with a per-rule trace.
func (h *PolicyHandler) Simulate(w http.ResponseWriter, r *http.Request) {
	if _, ok := h.requireSuperadmin(w, r); !ok {
		return
	}
	var req dto.SimulatePolicyRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, "invalid JSON", http.StatusBadRequest)
		return
	}
	if req.At != nil {
		req.Input.Context.Now = *req.At
	}
	d, trace, err := h.pdp.Simulate(r.Context(), req.Input, req.Rules)
	if err != nil {
		writePolicyServiceError(w, err)
		return
	}
	if trace == nil {
		trace = []policy.TraceEntry{}
	}
	writeJSON(w, dto.SimulatePolicyResponse{Decision: d, Trace: trace})
}

// GET /api/admin/policy/versions?limit=&before=
func (h *PolicyHandler) ListVersions(w http.ResponseWriter, r *http.Request) {
	if _, ok := h.requireSuperadmin(w, r); !ok {
		return
	}
	limit := queryInt(r, "limit", 50, 1, 200)
	before, _ := strconv.ParseInt(r.URL.Query().Get("before"), 10, 64)
	list, err := h.pdp.List(r.Context(), limit, before)
	if err != nil {
		writePolicyServiceError(w, err)
		return
	}
	if list == nil {
		list = []policy.VersionSummary{}
	}
	writeJSON(w, map[string]any{"versions": list})
}

// GET /api/admin/policy/versions/{version}
func (h *PolicyHandler) GetVersion(w http.ResponseWriter, r *http.Request) {
	if _, ok := h.requireSuperadmin(w, r); !ok {
		return
	}
	version, ok := policyVersionParam(w, r)
	if !ok {
		return
	}
	v, err := h.pdp.Get(r.Context(), version)
	if err != nil {
		writePolicyServiceError(w, err)
		return
	}
	writeJSON(w, dto.PolicyResponse{Version: v, Mode: string(h.pdp.Mode())})
}

// POST /api/admin/policy/versions/{version}/restore
func (h *PolicyHandler) Restore(w http.ResponseWriter, r *http.Request) {
	adminID, ok := h.requireSuperadmin(w, r)
	if !ok {
		return
	}
	version, ok := policyVersionParam(w, r)
	if !ok {
		return
	}
	var req dto.RestorePolicyRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, "invalid JSON", http.StatusBadRequest)
		return
	}
	v, err := h.pdp.Restore(r.Context(), version, req.BaseVersion, adminID)
	if err != nil {
		writePolicyServiceError(w, err)
		return
	}
	h.logAction(r, adminID, model.AdminActionPolicyRestored, map[string]interface{}{
		"version":          v.Version,
		"restored_version": version,
		"base_version":     req.BaseVersion,
		"rule_count":       len(v.Rules),
	})
	writeJSON(w, dto.PolicyResponse{Version: v, Mode: string(h.pdp.Mode())})
}

// GET /api/admin/policy/catalogue — the vocabulary a rule can use.
func (h *PolicyHandler) Catalogue(w http.ResponseWriter, r *http.Request) {
	if _, ok := h.requireSuperadmin(w, r); !ok {
		return
	}
	fixed, maps := policy.AttributePaths()
	sort.Strings(fixed)
	h.mu.RLock()
	actions := append([]string{}, h.adminActions...)
	exempt := append([]string{}, h.exemptActions...)
	h.mu.RUnlock()
	writeJSON(w, dto.PolicyCatalogueResponse{
		Mode:          string(h.pdp.Mode()),
		AdminActions:  actions,
		ExemptActions: exempt,
		Attributes:    fixed,
		AttributeMaps: maps,
		Operators:     policy.Operators(),
		Obligations:   policy.Obligations(),
	})
}

// GET /api/admin/policy/decisions?correlation_id=&allow=&divergence=true&since=&before_id=&limit=
func (h *PolicyHandler) Decisions(w http.ResponseWriter, r *http.Request) {
	if _, ok := h.requireSuperadmin(w, r); !ok {
		return
	}
	q := r.URL.Query()
	f := policy.DecisionFilter{
		CorrelationID:  q.Get("correlation_id"),
		DivergenceOnly: q.Get("divergence") == "true",
		Limit:          queryInt(r, "limit", 100, 1, 500),
	}
	if raw := q.Get("allow"); raw != "" {
		b, err := strconv.ParseBool(raw)
		if err != nil {
			writeError(w, "invalid allow", http.StatusBadRequest)
			return
		}
		f.Allow = &b
	}
	if raw := q.Get("since"); raw != "" {
		t, err := time.Parse(time.RFC3339, raw)
		if err != nil {
			writeError(w, "invalid since: want RFC 3339", http.StatusBadRequest)
			return
		}
		f.Since = t
	}
	if raw := q.Get("before_id"); raw != "" {
		id, err := strconv.ParseInt(raw, 10, 64)
		if err != nil {
			writeError(w, "invalid before_id", http.StatusBadRequest)
			return
		}
		f.BeforeID = id
	}

	rows, err := h.pdp.Decisions(r.Context(), f)
	if err != nil {
		writePolicyServiceError(w, err)
		return
	}
	if rows == nil {
		rows = []policy.DecisionRecord{}
	}
	writeJSON(w, map[string]any{"decisions": rows})
}

func (h *PolicyHandler) logAction(r *http.Request, adminID uint, action model.AdminAction, details map[string]interface{}) {
	if h.adminLogService == nil {
		return
	}
	_ = h.adminLogService.LogAction(r.Context(), adminID, nil, nil, action, details)
}

func policyVersionParam(w http.ResponseWriter, r *http.Request) (int64, bool) {
	v, err := strconv.ParseInt(chi.URLParam(r, "version"), 10, 64)
	if err != nil || v <= 0 {
		writeError(w, "invalid policy version", http.StatusBadRequest)
		return 0, false
	}
	return v, true
}

// queryInt reads an integer query parameter, clamped to [lo, hi].
func queryInt(r *http.Request, name string, def, lo, hi int) int {
	v, err := strconv.Atoi(r.URL.Query().Get(name))
	if err != nil {
		return def
	}
	return min(max(v, lo), hi)
}
