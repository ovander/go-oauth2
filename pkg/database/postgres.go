package database

import (
	"strings"
	"time"

	"github.com/ovandermoten/go-oauth2/pkg/logger"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"
	glogger "gorm.io/gorm/logger"
)

// ConnectionConfig holds database connection configuration
type ConnectionConfig struct {
	PoolSize         int
	MaxIdleConns     int
	ConnMaxLifetime  time.Duration
	ConnMaxIdleTime  time.Duration
	SlowQueryLogTime time.Duration
	PrepareStmt      bool
	// LogLevel controls GORM query logging. Default Warn: normal queries are not
	// logged (and not even rendered), only slow queries (Warn) and errors
	// (Error). Set Info to surface every statement — at DEBUG, so it requires
	// LOG_LEVEL=debug too. Avoids logging bound parameters (emails, hashes,
	// tokens) at info in production (HIGH-06).
	LogLevel glogger.LogLevel
}

// DefaultConnectionConfig returns sensible defaults for connection config
func DefaultConnectionConfig(poolSize int) ConnectionConfig {
	return ConnectionConfig{
		PoolSize:         poolSize,
		MaxIdleConns:     poolSize / 2,
		ConnMaxLifetime:  time.Hour,
		ConnMaxIdleTime:  10 * time.Minute,
		SlowQueryLogTime: 200 * time.Millisecond,
		PrepareStmt:      true,
		LogLevel:         glogger.Warn,
	}
}

// ParseGormLogLevel maps a DB_LOG_LEVEL string to a GORM log level. Unknown or
// empty values fall back to Warn (the safe, quiet default).
func ParseGormLogLevel(s string) glogger.LogLevel {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "silent":
		return glogger.Silent
	case "error":
		return glogger.Error
	case "info":
		return glogger.Info
	default: // "warn" and anything unrecognized
		return glogger.Warn
	}
}

// Connect connects to the database with default settings
func Connect(databaseURL string, poolSize int) *gorm.DB {
	return ConnectWithConfig(databaseURL, DefaultConnectionConfig(poolSize))
}

// ConnectWithConfig connects to the database with custom configuration
func ConnectWithConfig(databaseURL string, cfg ConnectionConfig) *gorm.DB {
	level := cfg.LogLevel
	if level == 0 { // unset zero value → safe quiet default
		level = glogger.Warn
	}
	gormConfig := &gorm.Config{
		Logger:      logger.NewGormLogger(level, cfg.SlowQueryLogTime, true),
		PrepareStmt: cfg.PrepareStmt, // Cache prepared statements for better performance
	}

	db, err := gorm.Open(postgres.Open(databaseURL), gormConfig)
	if err != nil {
		logger.Fatalf("Failed to connect to database: %v", err)
	}

	sqlDB, err := db.DB()
	if err != nil {
		logger.Fatalf("Failed to get underlying sql.DB: %v", err)
	}

	// Connection pool settings
	sqlDB.SetMaxOpenConns(cfg.PoolSize)
	sqlDB.SetMaxIdleConns(cfg.MaxIdleConns)
	sqlDB.SetConnMaxLifetime(cfg.ConnMaxLifetime)
	sqlDB.SetConnMaxIdleTime(cfg.ConnMaxIdleTime)

	logger.Info("✅ Database connected successfully")
	return db
}
