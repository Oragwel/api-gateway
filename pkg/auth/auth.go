package auth

import (
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/Oragwel/api-gateway/pkg/config"
	"github.com/golang-jwt/jwt/v5"
	"golang.org/x/crypto/bcrypt"
)

var (
	ErrInvalidToken     = errors.New("invalid token")
	ErrTokenExpired     = errors.New("token expired")
	ErrInvalidCredentials = errors.New("invalid credentials")
	ErrUserNotFound     = errors.New("user not found")
	ErrUnauthorized     = errors.New("unauthorized")
)

// Claims represents JWT claims
type Claims struct {
	UserID   string   `json:"user_id"`
	Email    string   `json:"email"`
	Roles    []string `json:"roles"`
	IsAdmin  bool     `json:"is_admin"`
	jwt.RegisteredClaims
}

// User represents a user in the system
type User struct {
	ID           string    `json:"id"`
	Email        string    `json:"email"`
	PasswordHash string    `json:"password_hash"`
	Roles        []string  `json:"roles"`
	IsAdmin      bool      `json:"is_admin"`
	CreatedAt    time.Time `json:"created_at"`
	LastLogin    time.Time `json:"last_login"`
	IsActive     bool      `json:"is_active"`
}

// TokenPair represents access and refresh tokens
type TokenPair struct {
	AccessToken  string    `json:"access_token"`
	RefreshToken string    `json:"refresh_token"`
	ExpiresAt    time.Time `json:"expires_at"`
	TokenType    string    `json:"token_type"`
}

// LoginRequest represents login request payload
type LoginRequest struct {
	Email    string `json:"email" binding:"required,email"`
	Password string `json:"password" binding:"required,min=6"`
}

// RefreshRequest represents token refresh request
type RefreshRequest struct {
	RefreshToken string `json:"refresh_token" binding:"required"`
}

// Service handles authentication operations
type Service struct {
	config       config.AuthConfig
	users        map[string]*User // In-memory store (use database in production)
	refreshTokens map[string]*RefreshTokenData
}

// RefreshTokenData stores refresh token information
type RefreshTokenData struct {
	UserID    string    `json:"user_id"`
	ExpiresAt time.Time `json:"expires_at"`
	IsRevoked bool      `json:"is_revoked"`
}

// NewService creates a new authentication service
func NewService(config config.AuthConfig) *Service {
	service := &Service{
		config:        config,
		users:         make(map[string]*User),
		refreshTokens: make(map[string]*RefreshTokenData),
	}

	// Initialize with demo users
	service.initializeDemoUsers()

	return service
}

// initializeDemoUsers creates demo users for testing
func (s *Service) initializeDemoUsers() {
	// Demo admin user
	adminHash, _ := bcrypt.GenerateFromPassword([]byte("admin123"), bcrypt.DefaultCost)
	adminUser := &User{
		ID:           "admin-001",
		Email:        "admin@tidingstechnologies.com",
		PasswordHash: string(adminHash),
		Roles:        []string{"admin", "user"},
		IsAdmin:      true,
		CreatedAt:    time.Now(),
		IsActive:     true,
	}
	s.users[adminUser.Email] = adminUser

	// Demo regular user
	userHash, _ := bcrypt.GenerateFromPassword([]byte("user123"), bcrypt.DefaultCost)
	regularUser := &User{
		ID:           "user-001",
		Email:        "user@tidingstechnologies.com",
		PasswordHash: string(userHash),
		Roles:        []string{"user"},
		IsAdmin:      false,
		CreatedAt:    time.Now(),
		IsActive:     true,
	}
	s.users[regularUser.Email] = regularUser

	// Demo API user
	apiHash, _ := bcrypt.GenerateFromPassword([]byte("api123"), bcrypt.DefaultCost)
	apiUser := &User{
		ID:           "api-001",
		Email:        "api@tidingstechnologies.com",
		PasswordHash: string(apiHash),
		Roles:        []string{"api", "service"},
		IsAdmin:      false,
		CreatedAt:    time.Now(),
		IsActive:     true,
	}
	s.users[apiUser.Email] = apiUser
}

// Login authenticates a user and returns tokens
func (s *Service) Login(email, password string) (*TokenPair, error) {
	user, exists := s.users[email]
	if !exists || !user.IsActive {
		return nil, ErrInvalidCredentials
	}

	// Verify password
	if err := bcrypt.CompareHashAndPassword([]byte(user.PasswordHash), []byte(password)); err != nil {
		return nil, ErrInvalidCredentials
	}

	// Update last login
	user.LastLogin = time.Now()

	// Generate tokens
	return s.generateTokenPair(user)
}

// generateTokenPair creates access and refresh tokens
func (s *Service) generateTokenPair(user *User) (*TokenPair, error) {
	now := time.Now()
	
	// Create access token claims
	claims := &Claims{
		UserID:  user.ID,
		Email:   user.Email,
		Roles:   user.Roles,
		IsAdmin: user.IsAdmin,
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer:    s.config.Issuer,
			Audience:  []string{s.config.Audience},
			Subject:   user.ID,
			ExpiresAt: jwt.NewNumericDate(now.Add(s.config.TokenExpiry)),
			NotBefore: jwt.NewNumericDate(now),
			IssuedAt:  jwt.NewNumericDate(now),
		},
	}

	// Create and sign access token
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	accessToken, err := token.SignedString([]byte(s.config.JWTSecret))
	if err != nil {
		return nil, fmt.Errorf("failed to sign access token: %w", err)
	}

	// Generate refresh token
	refreshToken, err := s.generateRefreshToken(user.ID)
	if err != nil {
		return nil, fmt.Errorf("failed to generate refresh token: %w", err)
	}

	return &TokenPair{
		AccessToken:  accessToken,
		RefreshToken: refreshToken,
		ExpiresAt:    now.Add(s.config.TokenExpiry),
		TokenType:    "Bearer",
	}, nil
}

// generateRefreshToken creates a new refresh token
func (s *Service) generateRefreshToken(userID string) (string, error) {
	// Generate random bytes
	bytes := make([]byte, 32)
	if _, err := rand.Read(bytes); err != nil {
		return "", err
	}

	refreshToken := base64.URLEncoding.EncodeToString(bytes)
	
	// Store refresh token data
	s.refreshTokens[refreshToken] = &RefreshTokenData{
		UserID:    userID,
		ExpiresAt: time.Now().Add(s.config.RefreshExpiry),
		IsRevoked: false,
	}

	return refreshToken, nil
}

// ValidateToken validates and parses a JWT token
func (s *Service) ValidateToken(tokenString string) (*Claims, error) {
	// Remove Bearer prefix if present
	tokenString = strings.TrimPrefix(tokenString, "Bearer ")

	// Parse token
	token, err := jwt.ParseWithClaims(tokenString, &Claims{}, func(token *jwt.Token) (interface{}, error) {
		// Validate signing method
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		return []byte(s.config.JWTSecret), nil
	})

	if err != nil {
		return nil, ErrInvalidToken
	}

	// Extract claims
	claims, ok := token.Claims.(*Claims)
	if !ok || !token.Valid {
		return nil, ErrInvalidToken
	}

	// Check if token is expired
	if claims.ExpiresAt.Before(time.Now()) {
		return nil, ErrTokenExpired
	}

	return claims, nil
}

// RefreshToken generates new tokens using refresh token
func (s *Service) RefreshToken(refreshToken string) (*TokenPair, error) {
	// Validate refresh token
	tokenData, exists := s.refreshTokens[refreshToken]
	if !exists || tokenData.IsRevoked || tokenData.ExpiresAt.Before(time.Now()) {
		return nil, ErrInvalidToken
	}

	// Find user
	var user *User
	for _, u := range s.users {
		if u.ID == tokenData.UserID {
			user = u
			break
		}
	}

	if user == nil || !user.IsActive {
		return nil, ErrUserNotFound
	}

	// Revoke old refresh token
	tokenData.IsRevoked = true

	// Generate new token pair
	return s.generateTokenPair(user)
}

// RevokeToken revokes a refresh token
func (s *Service) RevokeToken(refreshToken string) error {
	tokenData, exists := s.refreshTokens[refreshToken]
	if !exists {
		return ErrInvalidToken
	}

	tokenData.IsRevoked = true
	return nil
}

// IsAdmin checks if user has admin privileges
func (s *Service) IsAdmin(userID string) bool {
	for _, user := range s.users {
		if user.ID == userID {
			return user.IsAdmin
		}
	}
	return false
}

// HasRole checks if user has a specific role
func (s *Service) HasRole(userID, role string) bool {
	for _, user := range s.users {
		if user.ID == userID {
			for _, userRole := range user.Roles {
				if userRole == role {
					return true
				}
			}
		}
	}
	return false
}

// GetUser retrieves user by ID
func (s *Service) GetUser(userID string) (*User, error) {
	for _, user := range s.users {
		if user.ID == userID {
			// Return copy without password hash
			userCopy := *user
			userCopy.PasswordHash = ""
			return &userCopy, nil
		}
	}
	return nil, ErrUserNotFound
}

// CreateUser creates a new user (admin only)
func (s *Service) CreateUser(email, password string, roles []string, isAdmin bool) (*User, error) {
	// Check if user already exists
	if _, exists := s.users[email]; exists {
		return nil, errors.New("user already exists")
	}

	// Hash password
	passwordHash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return nil, fmt.Errorf("failed to hash password: %w", err)
	}

	// Generate user ID
	userID := fmt.Sprintf("user-%d", time.Now().Unix())

	// Create user
	user := &User{
		ID:           userID,
		Email:        email,
		PasswordHash: string(passwordHash),
		Roles:        roles,
		IsAdmin:      isAdmin,
		CreatedAt:    time.Now(),
		IsActive:     true,
	}

	// Store user
	s.users[email] = user

	// Return copy without password hash
	userCopy := *user
	userCopy.PasswordHash = ""
	return &userCopy, nil
}

// UpdateUser updates user information (admin only)
func (s *Service) UpdateUser(userID string, updates map[string]interface{}) (*User, error) {
	var targetUser *User
	for _, user := range s.users {
		if user.ID == userID {
			targetUser = user
			break
		}
	}

	if targetUser == nil {
		return nil, ErrUserNotFound
	}

	// Apply updates
	if email, ok := updates["email"].(string); ok {
		targetUser.Email = email
	}
	if roles, ok := updates["roles"].([]string); ok {
		targetUser.Roles = roles
	}
	if isAdmin, ok := updates["is_admin"].(bool); ok {
		targetUser.IsAdmin = isAdmin
	}
	if isActive, ok := updates["is_active"].(bool); ok {
		targetUser.IsActive = isActive
	}

	// Return copy without password hash
	userCopy := *targetUser
	userCopy.PasswordHash = ""
	return &userCopy, nil
}

// ListUsers returns all users (admin only)
func (s *Service) ListUsers() []*User {
	users := make([]*User, 0, len(s.users))
	for _, user := range s.users {
		userCopy := *user
		userCopy.PasswordHash = "" // Don't expose password hashes
		users = append(users, &userCopy)
	}
	return users
}
