package repository

import (
	"context"
	"errors"
	"sync"
	"time"

	"github.com/ovander/go-oauth2/internal/model"
	"github.com/ovander/go-oauth2/pkg/logger"
)

// Asynchronous audit appends (AUDIT_WRITE_MODE=async).
//
// With integrity stamping on, every audit row takes the chain's advisory lock
// and holds it until its own commit (RFC-007). Written inline, that puts every
// token issuance behind one global lock and one fsync each: when the disk
// stalls, all in-flight requests stall with it. The asynchronous appender takes
// the write off the request path. Create queues a copy of the row and returns;
// one writer goroutine appends what is queued in batches, each batch in one
// transaction under the same lock, chained in queue order. The chain stays
// linear because there is a single writer per process, and the advisory lock
// still orders it against other instances and synchronous writers.
//
// Trade-off: rows still queued when the process dies without a graceful
// shutdown are lost. A failed audit write was already ignored by every caller
// (fire and forget), so the guarantee changes little, but it is no longer
// "written before the response". A full queue never drops a row: Create then
// writes synchronously, as in sync mode.

// AsyncAuditConfig sizes the asynchronous appender.
type AsyncAuditConfig struct {
	// QueueSize bounds the rows waiting to be written. Zero means 4096.
	QueueSize int
	// MaxBatch bounds the rows written in one transaction. Zero means 256.
	MaxBatch int
	// OnSyncFallback, when set, is called each time a full queue (or a closed
	// appender) makes Create write synchronously.
	OnSyncFallback func()
	// OnBatch, when set, is called after each batch with its size and outcome.
	OnBatch func(rows int, err error)
}

// AsyncAuditRepository is a SecurityAuditLogRepository whose Create queues the
// row for a background writer. Close drains the queue.
type AsyncAuditRepository struct {
	SecurityAuditLogRepository // reads go straight to the database

	inner   *gormSecurityAuditLogRepository
	cfg     AsyncAuditConfig
	queue   chan *model.SecurityAuditLog
	done    chan struct{}
	mu      sync.RWMutex // guards closed and the send on queue
	closed  bool
	closeMu sync.Once
}

// ErrAsyncAuditUnsupported is returned when the repository to wrap is not the
// GORM audit repository (only it can append a chained batch).
var ErrAsyncAuditUnsupported = errors.New("asynchronous audit writes need the GORM audit repository")

// NewAsyncAuditRepository wraps repo, which must come from
// NewSecurityAuditLogRepository(WithIntegrity), and starts its writer.
func NewAsyncAuditRepository(repo SecurityAuditLogRepository, cfg AsyncAuditConfig) (*AsyncAuditRepository, error) {
	inner, ok := repo.(*gormSecurityAuditLogRepository)
	if !ok {
		return nil, ErrAsyncAuditUnsupported
	}
	if cfg.QueueSize <= 0 {
		cfg.QueueSize = 4096
	}
	if cfg.MaxBatch <= 0 {
		cfg.MaxBatch = 256
	}
	a := &AsyncAuditRepository{
		SecurityAuditLogRepository: repo,
		inner:                      inner,
		cfg:                        cfg,
		queue:                      make(chan *model.SecurityAuditLog, cfg.QueueSize),
		done:                       make(chan struct{}),
	}
	go a.run()
	return a, nil
}

// SetOutboxWriter installs the webhook outbox on the wrapped repository, so
// the A3 transactional guarantee holds for queued rows too.
func (a *AsyncAuditRepository) SetOutboxWriter(w AuditOutboxWriter) { a.inner.SetOutboxWriter(w) }

// Create queues a copy of log and returns. Its CreatedAt is stamped now, so the
// row records when the event happened, not when it was written. When the queue
// is full or the appender is closed, the row is written synchronously instead.
func (a *AsyncAuditRepository) Create(ctx context.Context, log *model.SecurityAuditLog) error {
	normalizeAuditCreatedAt(log)
	row := *log // the writer owns its copy; the caller keeps log

	a.mu.RLock()
	if !a.closed {
		select {
		case a.queue <- &row:
			a.mu.RUnlock()
			return nil
		default:
		}
	}
	a.mu.RUnlock()

	if a.cfg.OnSyncFallback != nil {
		a.cfg.OnSyncFallback()
	}
	return a.inner.Create(ctx, &row)
}

// run is the single writer: it waits for a row, takes whatever else is already
// queued (up to MaxBatch), and appends the batch in one transaction.
func (a *AsyncAuditRepository) run() {
	defer close(a.done)
	batch := make([]*model.SecurityAuditLog, 0, a.cfg.MaxBatch)
	for first := range a.queue {
		batch = append(batch[:0], first)
	fill:
		for len(batch) < a.cfg.MaxBatch {
			select {
			case row, ok := <-a.queue:
				if !ok {
					break fill
				}
				batch = append(batch, row)
			default:
				break fill
			}
		}
		a.write(batch)
	}
}

// write appends one batch. Requests are long gone, so it uses its own context.
// If the batch transaction fails, each row is retried alone so one bad row
// cannot lose the others; a row that still fails is logged, never dropped
// silently.
func (a *AsyncAuditRepository) write(batch []*model.SecurityAuditLog) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	err := a.inner.createRows(ctx, batch)
	if a.cfg.OnBatch != nil {
		a.cfg.OnBatch(len(batch), err)
	}
	if err == nil {
		return
	}
	for _, row := range batch {
		row.ID, row.PrevHash, row.RowHash = 0, "", ""
		if rerr := a.inner.createRows(ctx, []*model.SecurityAuditLog{row}); rerr != nil {
			logger.WithFields(logger.Fields{
				"error":          rerr.Error(),
				"event_type":     string(row.EventType),
				"correlation_id": row.CorrelationID,
			}).Error("audit: asynchronous write failed; the security event is lost")
		}
	}
}

// Close stops accepting rows (later Creates write synchronously) and waits
// until every queued row is written, or ctx ends.
func (a *AsyncAuditRepository) Close(ctx context.Context) error {
	a.closeMu.Do(func() {
		a.mu.Lock()
		a.closed = true
		close(a.queue)
		a.mu.Unlock()
	})
	select {
	case <-a.done:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

// Pending reports how many rows are queued.
func (a *AsyncAuditRepository) Pending() int { return len(a.queue) }
