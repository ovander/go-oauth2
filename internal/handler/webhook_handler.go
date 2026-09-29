package handler

import (
	"encoding/json"
	"errors"
	"net/http"
	"strconv"

	"github.com/go-chi/chi/v5"
	"github.com/ovander/go-oauth2/internal/contextkeys"
	"github.com/ovander/go-oauth2/internal/dto"
	"github.com/ovander/go-oauth2/internal/middleware"
	"github.com/ovander/go-oauth2/internal/model"
	"github.com/ovander/go-oauth2/internal/service"
)

// WebhookHandler serves the admin API for webhook subscriptions and the
// delivery outbox (A3). Every route is global-admin only: a subscription is an
// egress channel for identity events, so registering one is a platform-level
// decision, not an app-level one.
type WebhookHandler struct {
	webhookService  service.WebhookService
	adminLogService service.AdminLogService
}

func NewWebhookHandler(webhookService service.WebhookService, adminLogService service.AdminLogService) *WebhookHandler {
	return &WebhookHandler{webhookService: webhookService, adminLogService: adminLogService}
}

// requireGlobalAdmin resolves the acting admin, or writes the error response and
// returns false.
func (h *WebhookHandler) requireGlobalAdmin(w http.ResponseWriter, r *http.Request) (uint, bool) {
	adminID, ok := middleware.GetUserIDFromContext(r.Context())
	if !ok {
		writeError(w, "unauthorized", http.StatusUnauthorized)
		return 0, false
	}
	currentUser, _ := r.Context().Value(contextkeys.CurrentUserKey).(*model.User)
	if currentUser == nil || !currentUser.IsGlobalAdmin() {
		writeError(w, "forbidden: global admin required", http.StatusForbidden)
		return 0, false
	}
	return adminID, true
}

// writeServiceError maps a webhook service error to a status code.
func writeServiceError(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, service.ErrWebhookNotFound), errors.Is(err, service.ErrDeliveryNotFound):
		writeError(w, err.Error(), http.StatusNotFound)
	case errors.Is(err, service.ErrWebhookInvalidURL),
		errors.Is(err, service.ErrWebhookInvalidEvent),
		errors.Is(err, service.ErrWebhookNoEvents):
		writeError(w, err.Error(), http.StatusBadRequest)
	case errors.Is(err, service.ErrWebhookNoSecretKey):
		// A deployment without SECRET_KEY_BASE cannot hold a signing secret
		// safely; that is a server configuration problem, not a bad request.
		writeError(w, err.Error(), http.StatusNotImplemented)
	default:
		writeError(w, err.Error(), http.StatusInternalServerError)
	}
}

// GET /api/admin/webhooks
func (h *WebhookHandler) List(w http.ResponseWriter, r *http.Request) {
	if _, ok := h.requireGlobalAdmin(w, r); !ok {
		return
	}

	var appID *uint
	if raw := r.URL.Query().Get("app_id"); raw != "" {
		id, err := strconv.ParseUint(raw, 10, 64)
		if err != nil {
			writeError(w, "invalid app_id", http.StatusBadRequest)
			return
		}
		v := uint(id)
		appID = &v
	}

	subs, err := h.webhookService.List(r.Context(), appID)
	if err != nil {
		writeServiceError(w, err)
		return
	}

	out := make([]dto.WebhookResponse, len(subs))
	for i := range subs {
		out[i] = webhookToResponse(&subs[i])
	}
	writeJSON(w, dto.WebhookListResponse{Webhooks: out, TotalCount: int64(len(out))})
}

// GET /api/admin/webhooks/events — the subscribable event catalogue.
func (h *WebhookHandler) Catalogue(w http.ResponseWriter, r *http.Request) {
	if _, ok := h.requireGlobalAdmin(w, r); !ok {
		return
	}
	writeJSON(w, map[string]any{
		"events":   model.WebhookEventCatalogue(),
		"wildcard": model.WebhookEventWildcard,
	})
}

// GET /api/admin/webhooks/{id}
func (h *WebhookHandler) Get(w http.ResponseWriter, r *http.Request) {
	if _, ok := h.requireGlobalAdmin(w, r); !ok {
		return
	}
	id, ok := webhookIDParam(w, r)
	if !ok {
		return
	}

	sub, err := h.webhookService.GetByID(r.Context(), id)
	if err != nil {
		writeServiceError(w, err)
		return
	}
	writeJSON(w, webhookToResponse(sub))
}

// POST /api/admin/webhooks
func (h *WebhookHandler) Create(w http.ResponseWriter, r *http.Request) {
	adminID, ok := h.requireGlobalAdmin(w, r)
	if !ok {
		return
	}

	var req dto.CreateWebhookRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, "invalid JSON", http.StatusBadRequest)
		return
	}

	sub, secret, err := h.webhookService.Create(r.Context(), req, adminID)
	if err != nil {
		writeServiceError(w, err)
		return
	}

	h.logAction(r, adminID, sub, model.AdminActionWebhookCreated, map[string]interface{}{
		"url":         sub.URL,
		"event_types": []string(sub.EventTypes),
	})

	w.WriteHeader(http.StatusCreated)
	writeJSON(w, dto.WebhookWithSecretResponse{
		WebhookResponse: webhookToResponse(sub),
		Secret:          secret,
	})
}

// PUT /api/admin/webhooks/{id}
func (h *WebhookHandler) Update(w http.ResponseWriter, r *http.Request) {
	adminID, ok := h.requireGlobalAdmin(w, r)
	if !ok {
		return
	}
	id, ok := webhookIDParam(w, r)
	if !ok {
		return
	}

	var req dto.UpdateWebhookRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, "invalid JSON", http.StatusBadRequest)
		return
	}

	sub, err := h.webhookService.Update(r.Context(), id, req)
	if err != nil {
		writeServiceError(w, err)
		return
	}

	h.logAction(r, adminID, sub, model.AdminActionWebhookUpdated, map[string]interface{}{
		"url":         sub.URL,
		"event_types": []string(sub.EventTypes),
		"active":      sub.Active,
	})
	writeJSON(w, webhookToResponse(sub))
}

// DELETE /api/admin/webhooks/{id}
func (h *WebhookHandler) Delete(w http.ResponseWriter, r *http.Request) {
	adminID, ok := h.requireGlobalAdmin(w, r)
	if !ok {
		return
	}
	id, ok := webhookIDParam(w, r)
	if !ok {
		return
	}

	sub, err := h.webhookService.GetByID(r.Context(), id)
	if err != nil {
		writeServiceError(w, err)
		return
	}
	if err := h.webhookService.Delete(r.Context(), id); err != nil {
		writeServiceError(w, err)
		return
	}

	h.logAction(r, adminID, sub, model.AdminActionWebhookDeleted, map[string]interface{}{
		"url": sub.URL,
	})
	writeJSON(w, map[string]string{"message": "webhook subscription deleted"})
}

// POST /api/admin/webhooks/{id}/rotate-secret
func (h *WebhookHandler) RotateSecret(w http.ResponseWriter, r *http.Request) {
	adminID, ok := h.requireGlobalAdmin(w, r)
	if !ok {
		return
	}
	id, ok := webhookIDParam(w, r)
	if !ok {
		return
	}

	sub, secret, err := h.webhookService.RotateSecret(r.Context(), id)
	if err != nil {
		writeServiceError(w, err)
		return
	}

	h.logAction(r, adminID, sub, model.AdminActionWebhookSecretRotated, map[string]interface{}{
		"url": sub.URL,
	})
	writeJSON(w, dto.WebhookWithSecretResponse{
		WebhookResponse: webhookToResponse(sub),
		Secret:          secret,
	})
}

// GET /api/admin/webhooks/deliveries — the outbox, optionally filtered by
// subscription_id and status.
func (h *WebhookHandler) ListDeliveries(w http.ResponseWriter, r *http.Request) {
	if _, ok := h.requireGlobalAdmin(w, r); !ok {
		return
	}

	var subID *uint
	if raw := r.URL.Query().Get("subscription_id"); raw != "" {
		id, err := strconv.ParseUint(raw, 10, 64)
		if err != nil {
			writeError(w, "invalid subscription_id", http.StatusBadRequest)
			return
		}
		v := uint(id)
		subID = &v
	}

	status := r.URL.Query().Get("status")
	switch status {
	case "", model.WebhookDeliveryPending, model.WebhookDeliveryDelivered, model.WebhookDeliveryDead:
	default:
		writeError(w, "invalid status", http.StatusBadRequest)
		return
	}

	page, _ := strconv.Atoi(r.URL.Query().Get("page"))
	pageSize, _ := strconv.Atoi(r.URL.Query().Get("page_size"))
	if page < 1 {
		page = 1
	}
	if pageSize < 1 || pageSize > 100 {
		pageSize = 20
	}

	deliveries, total, err := h.webhookService.ListDeliveries(r.Context(), subID, status, page, pageSize)
	if err != nil {
		writeServiceError(w, err)
		return
	}

	out := make([]dto.WebhookDeliveryResponse, len(deliveries))
	for i := range deliveries {
		out[i] = deliveryToResponse(&deliveries[i])
	}
	writeJSON(w, dto.WebhookDeliveryListResponse{
		Deliveries: out,
		TotalCount: total,
		Page:       page,
		PageSize:   pageSize,
	})
}

// GET /api/admin/webhooks/deliveries/stats — outbox depth per status.
func (h *WebhookHandler) DeliveryStats(w http.ResponseWriter, r *http.Request) {
	if _, ok := h.requireGlobalAdmin(w, r); !ok {
		return
	}
	stats, err := h.webhookService.DeliveryStats(r.Context())
	if err != nil {
		writeServiceError(w, err)
		return
	}
	// Report every status explicitly, so a console does not have to distinguish
	// "zero" from "key absent".
	for _, s := range []string{model.WebhookDeliveryPending, model.WebhookDeliveryDelivered, model.WebhookDeliveryDead} {
		if _, ok := stats[s]; !ok {
			stats[s] = 0
		}
	}
	writeJSON(w, stats)
}

// POST /api/admin/webhooks/deliveries/{id}/requeue — replay a dead or stuck
// delivery after fixing the target.
func (h *WebhookHandler) RequeueDelivery(w http.ResponseWriter, r *http.Request) {
	adminID, ok := h.requireGlobalAdmin(w, r)
	if !ok {
		return
	}
	id, ok := webhookIDParam(w, r)
	if !ok {
		return
	}

	if err := h.webhookService.RequeueDelivery(r.Context(), id); err != nil {
		writeServiceError(w, err)
		return
	}

	if h.adminLogService != nil {
		_ = h.adminLogService.LogAction(r.Context(), adminID, nil, nil, model.AdminActionWebhookRequeued, map[string]interface{}{
			"delivery_id": id,
		})
	}
	writeJSON(w, map[string]string{"message": "delivery requeued"})
}

// logAction records a subscription change in the admin trail. The signing
// secret is never part of the details.
func (h *WebhookHandler) logAction(r *http.Request, adminID uint, sub *model.WebhookSubscription, action model.AdminAction, details map[string]interface{}) {
	if h.adminLogService == nil {
		return
	}
	if sub != nil {
		details["webhook_id"] = sub.ID
		details["name"] = sub.Name
	}
	_ = h.adminLogService.LogAction(r.Context(), adminID, subAppID(sub), nil, action, details)
}

func subAppID(sub *model.WebhookSubscription) *uint {
	if sub == nil {
		return nil
	}
	return sub.AppID
}

func webhookIDParam(w http.ResponseWriter, r *http.Request) (uint, bool) {
	id, err := strconv.ParseUint(chi.URLParam(r, "id"), 10, 64)
	if err != nil {
		writeError(w, "invalid webhook ID", http.StatusBadRequest)
		return 0, false
	}
	return uint(id), true
}

func webhookToResponse(sub *model.WebhookSubscription) dto.WebhookResponse {
	return dto.WebhookResponse{
		ID:         sub.ID,
		Name:       sub.Name,
		URL:        sub.URL,
		AppID:      sub.AppID,
		EventTypes: sub.EventTypes,
		Active:     sub.Active,
		CreatedBy:  sub.CreatedBy,
		CreatedAt:  sub.CreatedAt,
		UpdatedAt:  sub.UpdatedAt,
	}
}

func deliveryToResponse(d *model.WebhookDelivery) dto.WebhookDeliveryResponse {
	return dto.WebhookDeliveryResponse{
		ID:             d.ID,
		SubscriptionID: d.SubscriptionID,
		AuditLogID:     d.AuditLogID,
		EventType:      string(d.EventType),
		Status:         d.Status,
		Attempts:       d.Attempts,
		NextAttemptAt:  d.NextAttemptAt,
		LastStatusCode: d.LastStatusCode,
		LastError:      d.LastError,
		DeliveredAt:    d.DeliveredAt,
		CreatedAt:      d.CreatedAt,
		Payload:        d.Payload,
	}
}
