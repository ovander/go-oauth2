package middleware

import "net/http"

// DefaultMaxRequestBody caps every JSON/form request body the API accepts.
// The largest legitimate body on this server (a report request, a client
// registration with a handful of redirect URIs) is a few kilobytes; 1 MiB
// leaves an order of magnitude of headroom while making a multi-hundred-MB
// JSON string on an unauthenticated endpoint (P4-3) a 400 instead of an
// allocation.
const DefaultMaxRequestBody int64 = 1 << 20

// MaxRequestBody wraps r.Body in http.MaxBytesReader so any handler that
// decodes it — json.NewDecoder, ParseForm, io.ReadAll — receives an error
// once n bytes have been read; MaxBytesReader also marks the connection to
// be closed. Handlers that set their own tighter limit keep it (a
// MaxBytesReader inside a MaxBytesReader takes the smaller).
func MaxRequestBody(n int64) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.Body != nil && r.Body != http.NoBody {
				r.Body = http.MaxBytesReader(w, r.Body, n)
			}
			next.ServeHTTP(w, r)
		})
	}
}
