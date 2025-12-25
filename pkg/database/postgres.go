package database

import (
	"log"
	"time"

	"gorm.io/driver/postgres"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
)

// ConnectionConfig holds database connection configuration
type ConnectionConfig struct {
	PoolSize          int
	MaxIdleConns      int
	ConnMaxLifetime   time.Duration
	ConnMaxIdleTime   time.Duration
	SlowQueryLogTime  time.Duration
	PrepareStmt       bool
}

// DefaultConnectionConfig returns sensible defaults for connection config
func DefaultConnectionConfig(poolSize int) ConnectionConfig {
	return ConnectionConfig{
		PoolSize:          poolSize,
		MaxIdleConns:      poolSize / 2,
		ConnMaxLifetime:   time.Hour,
		ConnMaxIdleTime:   10 * time.Minute,
		SlowQueryLogTime:  200 * time.Millisecond,
		PrepareStmt:       true,
	}
}

// Connect connects to the database with default settings
func Connect(databaseURL string, poolSize int) *gorm.DB {
	return ConnectWithConfig(databaseURL, DefaultConnectionConfig(poolSize))
}

// ConnectWithConfig connects to the database with custom configuration
func ConnectWithConfig(databaseURL string, cfg ConnectionConfig) *gorm.DB {
	gormConfig := &gorm.Config{
		Logger:      logger.Default.LogMode(logger.Info),
		PrepareStmt: cfg.PrepareStmt, // Cache prepared statements for better performance
	}

	db, err := gorm.Open(postgres.Open(databaseURL), gormConfig)
	if err != nil {
		log.Fatalf("Failed to connect to database: %v", err)
	}

	sqlDB, err := db.DB()
	if err != nil {
		log.Fatalf("Failed to get underlying sql.DB: %v", err)
	}

	// Connection pool settings
	sqlDB.SetMaxOpenConns(cfg.PoolSize)
	sqlDB.SetMaxIdleConns(cfg.MaxIdleConns)
	sqlDB.SetConnMaxLifetime(cfg.ConnMaxLifetime)
	sqlDB.SetConnMaxIdleTime(cfg.ConnMaxIdleTime)

	log.Println("Database connected successfully")
	return db
}
