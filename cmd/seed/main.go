package main

import (
	"crypto/rand"
	"flag"
	"fmt"
	"math/big"
	"time"

	"github.com/ovander/go-oauth2/config"
	"github.com/ovander/go-oauth2/internal/model"
	"github.com/ovander/go-oauth2/internal/shared/auth"
	"github.com/ovander/go-oauth2/pkg/database"
	"github.com/ovander/go-oauth2/pkg/logger"
	"gorm.io/gorm"
)

func main() {
	// Command line flags
	email := flag.String("email", "admin@example.com", "Admin email address")
	name := flag.String("name", "Admin User", "Admin display name")
	password := flag.String("password", "", "Admin password (will prompt if not provided)")
	force := flag.Bool("force", false, "Force creation even if user exists (will update)")
	flag.Parse()

	// Load configuration
	cfg := config.Load()

	// Connect to database
	db := database.Connect(cfg.DatabaseURL, cfg.DBPoolSize)

	// Auto-migrate database schema
	if err := db.AutoMigrate(
		&model.User{},
		&model.App{},
		&model.UserAppRole{},
	); err != nil {
		logger.Fatalf("Failed to auto-migrate database: %v", err)
	}
	logger.Info("✅ Database schema migrated successfully")

	// Get or generate password
	adminPassword := *password
	if adminPassword == "" {
		// Generate a secure random password
		adminPassword = generateSecurePassword()
		logger.Infof("Generated password: %s", adminPassword)
		logger.Warn("⚠️  Save this password now - it will not be shown again!")
	}

	// Validate password
	if err := auth.ValidatePassword(adminPassword); err != nil {
		logger.Fatalf("Password validation failed: %v", err)
	}

	// Hash password
	hashedPassword, err := auth.HashPassword(adminPassword)
	if err != nil {
		logger.Fatalf("Failed to hash password: %v", err)
	}

	// Check if user already exists
	var existingUser model.User
	result := db.Where("email = ?", *email).First(&existingUser)

	now := time.Now()

	if result.Error == nil {
		// User exists
		if !*force {
			logger.Fatalf("User %s already exists. Use -force to update.", *email)
		}

		// Update existing user
		applyForcedReset(&existingUser, *name, hashedPassword, now)

		// Save the account without its token version and lockout columns,
		// and increment the token version in the database (invalidating
		// existing tokens) in the same transaction: incrementing the value
		// read above could undo a revocation made since.
		err := db.Transaction(func(tx *gorm.DB) error {
			if err := tx.Omit("token_version", "failed_login_attempts", "locked_until").Save(&existingUser).Error; err != nil {
				return err
			}
			return tx.Model(&model.User{}).Where("id = ?", existingUser.ID).
				UpdateColumn("token_version", gorm.Expr("token_version + 1")).Error
		})
		if err != nil {
			logger.Fatalf("Failed to update admin user: %v", err)
		}

		logger.Infof("✅ Admin user updated: %s", *email)
	} else {
		// Create new user
		admin := &model.User{
			Email:              *email,
			Name:               *name,
			HashedPassword:     hashedPassword,
			Role:               model.UserRoleSuperadmin,
			IsVerified:         true,
			MustChangePassword: true, // Force password change on first login
			TokenVersion:       1,
			Source:             "seed",
			ConfirmedAt:        &now,
			CreatedAt:          now,
			UpdatedAt:          now,
		}

		if err := db.Create(admin).Error; err != nil {
			logger.Fatalf("Failed to create admin user: %v", err)
		}

		logger.Infof("✅ Admin user created: %s", *email)
	}

	fmt.Println()
	fmt.Println("============================================")
	fmt.Printf("Email:    %s\n", *email)
	fmt.Printf("Password: %s\n", adminPassword)
	fmt.Println("============================================")
	fmt.Println()
	fmt.Println("⚠️  IMPORTANT: Password change required on first login!")
	fmt.Println()
}

// generateSecurePassword generates a random password that meets all requirements
func generateSecurePassword() string {
	// Use crypto/rand for secure random generation
	const (
		lowercase = "abcdefghijklmnopqrstuvwxyz"
		uppercase = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
		digits    = "0123456789"
		special   = "!@#$%^&*"
		all       = lowercase + uppercase + digits + special
	)

	password := make([]byte, 16)

	// Ensure at least one of each required character type
	password[0] = lowercase[randInt(len(lowercase))]
	password[1] = uppercase[randInt(len(uppercase))]
	password[2] = digits[randInt(len(digits))]
	password[3] = special[randInt(len(special))]

	// Fill the rest randomly
	for i := 4; i < len(password); i++ {
		password[i] = all[randInt(len(all))]
	}

	// Shuffle the password
	for i := len(password) - 1; i > 0; i-- {
		j := randInt(i + 1)
		password[i], password[j] = password[j], password[i]
	}

	return string(password)
}

func randInt(max int) int {
	n, err := rand.Int(rand.Reader, big.NewInt(int64(max)))
	if err != nil {
		// Fallback to time-based (less secure, but works)
		return int(time.Now().UnixNano()) % max
	}
	return int(n.Int64())
}

// applyForcedReset makes u the seeded superadmin again (-force): its name, a
// new password that must be changed at first sign-in, a verified account.
// The password counts as changed now, so reset links issued before no longer
// work, as after any password change (#366).
func applyForcedReset(u *model.User, name, hashedPassword string, now time.Time) {
	u.Name = name
	u.HashedPassword = hashedPassword
	u.Role = model.UserRoleSuperadmin
	u.IsVerified = true
	u.MustChangePassword = true
	u.ConfirmedAt = &now
	u.UpdatedAt = now
	u.PasswordChangedAt = &now
}
