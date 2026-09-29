module github.com/ovander/go-oauth2

go 1.25.13

// Build, test and ship with a pinned toolchain: Go 1.25 is out of support
// since Go 1.27's release, so it receives no more security fixes. The go
// directive above stays the language minimum; this line decides what CI and
// local builds actually compile with (GOTOOLCHAIN=auto fetches it). Keep it
// equal to the Dockerfile's golang image tag.
toolchain go1.27.1

require (
	github.com/go-chi/chi/v5 v5.3.0
	github.com/go-chi/cors v1.2.1
	github.com/golang-jwt/jwt/v5 v5.3.1
	github.com/google/uuid v1.6.0
	github.com/joho/godotenv v1.5.1
	github.com/oschwald/geoip2-golang v1.13.0
	github.com/prometheus/client_golang v1.24.1
	github.com/sirupsen/logrus v1.9.3
	// Newest x/crypto that still declares go 1.25: v0.56.0+ require go 1.26,
	// which would raise the go directive above and with it the GODEBUG
	// defaults. Only x/crypto/bcrypt is imported; the advisories left open at
	// this version (ssh, openpgp) sit in packages this module does not use.
	golang.org/x/crypto v0.55.0
	gorm.io/driver/postgres v1.5.9
	gorm.io/gorm v1.25.12
)

require (
	github.com/beorn7/perks v1.0.1 // indirect
	github.com/cespare/xxhash/v2 v2.3.0 // indirect
	github.com/jackc/pgpassfile v1.0.0 // indirect
	github.com/jackc/pgservicefile v0.0.0-20240606120523-5a60cdf6a761 // indirect
	github.com/jackc/pgx/v5 v5.9.2 // indirect
	github.com/jackc/puddle/v2 v2.2.2 // indirect
	github.com/jinzhu/inflection v1.0.0 // indirect
	github.com/jinzhu/now v1.1.5 // indirect
	github.com/kylelemons/godebug v1.1.0 // indirect
	github.com/munnerz/goautoneg v0.0.0-20191010083416-a7dc8b61c822 // indirect
	github.com/oschwald/maxminddb-golang v1.13.0 // indirect
	github.com/prometheus/client_model v0.6.2 // indirect
	github.com/prometheus/common v0.70.1 // indirect
	github.com/prometheus/procfs v0.21.1 // indirect
	golang.org/x/sync v0.22.0 // indirect
	golang.org/x/sys v0.47.0 // indirect
	golang.org/x/text v0.41.0 // indirect
	google.golang.org/protobuf v1.36.11 // indirect
)
