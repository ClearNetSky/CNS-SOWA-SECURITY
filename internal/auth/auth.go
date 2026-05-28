package auth

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"log"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/ClearNetSky/CNS-SOWA-SECURITY/internal/config"
)

// Manager handles authentication and session management
type Manager struct {
	cfg      *config.Config
	sessions map[string]*Session
	mu       sync.RWMutex
}

// Session represents an authenticated session
type Session struct {
	Token     string    `json:"token"`
	Username  string    `json:"username"`
	CreatedAt time.Time `json:"created_at"`
	ExpiresAt time.Time `json:"expires_at"`
	IP        string    `json:"ip"`
	UserAgent string    `json:"user_agent"`
}

// LoginRequest represents login credentials
type LoginRequest struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

// LoginResponse is returned on successful login
type LoginResponse struct {
	Token     string `json:"token"`
	ExpiresAt int64  `json:"expires_at"`
}

// New creates a new auth manager
func New(cfg *config.Config) *Manager {
	m := &Manager{
		cfg:      cfg,
		sessions: make(map[string]*Session),
	}

	// Start session cleanup
	go m.cleanupLoop()

	return m
}

// IsConfigured checks if authentication is set up (password hash exists)
func (m *Manager) IsConfigured() bool {
	return m.cfg.Auth.PasswordHash != ""
}

// SetupPassword sets the initial admin password
func (m *Manager) SetupPassword(username, password string) error {
	if password == "" {
		return fmt.Errorf("password cannot be empty")
	}
	if len(password) < 4 {
		return fmt.Errorf("password must be at least 4 characters")
	}

	hash := hashPassword(password)
	return m.cfg.Update(func(cfg *config.Config) {
		cfg.Auth.Username = username
		cfg.Auth.PasswordHash = hash
	})
}

// Login validates credentials and creates a session
func (m *Manager) Login(username, password string, ip, userAgent string) (*LoginResponse, error) {
	if !m.IsConfigured() {
		return nil, fmt.Errorf("authentication not configured - run setup first")
	}

	if username != m.cfg.Auth.Username {
		log.Printf("[Auth] Failed login attempt for user '%s' from %s", username, ip)
		return nil, fmt.Errorf("invalid credentials")
	}

	if hashPassword(password) != m.cfg.Auth.PasswordHash {
		log.Printf("[Auth] Failed login attempt for user '%s' from %s", username, ip)
		return nil, fmt.Errorf("invalid credentials")
	}

	// Create session
	token := generateToken()
	ttl := time.Duration(m.cfg.Auth.SessionTTL) * time.Hour
	if ttl <= 0 {
		ttl = 720 * time.Hour // 30 days default
	}

	session := &Session{
		Token:     token,
		Username:  username,
		CreatedAt: time.Now(),
		ExpiresAt: time.Now().Add(ttl),
		IP:        ip,
		UserAgent: userAgent,
	}

	m.mu.Lock()
	m.sessions[token] = session
	m.mu.Unlock()

	log.Printf("[Auth] User '%s' logged in from %s", username, ip)

	return &LoginResponse{
		Token:     token,
		ExpiresAt: session.ExpiresAt.Unix(),
	}, nil
}

// Logout invalidates a session
func (m *Manager) Logout(token string) {
	m.mu.Lock()
	delete(m.sessions, token)
	m.mu.Unlock()
}

// ValidateToken checks if a session token is valid
func (m *Manager) ValidateToken(token string) (*Session, bool) {
	m.mu.RLock()
	session, ok := m.sessions[token]
	m.mu.RUnlock()

	if !ok {
		return nil, false
	}

	if time.Now().After(session.ExpiresAt) {
		m.mu.Lock()
		delete(m.sessions, token)
		m.mu.Unlock()
		return nil, false
	}

	return session, true
}

// GetSessions returns all active sessions
func (m *Manager) GetSessions() []Session {
	m.mu.RLock()
	defer m.mu.RUnlock()

	var sessions []Session
	now := time.Now()
	for _, s := range m.sessions {
		if s.ExpiresAt.After(now) {
			sessions = append(sessions, *s)
		}
	}
	return sessions
}

// Middleware returns HTTP middleware that enforces authentication
// Paths in skipPaths are accessible without authentication
func (m *Manager) Middleware(next http.Handler, skipPaths []string) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Skip auth for certain paths
		for _, path := range skipPaths {
			if strings.HasPrefix(r.URL.Path, path) {
				next.ServeHTTP(w, r)
				return
			}
		}

		// Static files don't need auth
		if !strings.HasPrefix(r.URL.Path, "/api/") {
			next.ServeHTTP(w, r)
			return
		}

		// If auth is not configured, allow all API access
		if !m.IsConfigured() {
			next.ServeHTTP(w, r)
			return
		}

		// Check Authorization header
		token := ""
		authHeader := r.Header.Get("Authorization")
		if strings.HasPrefix(authHeader, "Bearer ") {
			token = strings.TrimPrefix(authHeader, "Bearer ")
		}

		// Also check cookie
		if token == "" {
			if cookie, err := r.Cookie("sowa_session"); err == nil {
				token = cookie.Value
			}
		}

		// Also check query parameter (for SSE, WebSocket)
		if token == "" {
			token = r.URL.Query().Get("token")
		}

		if token == "" {
			http.Error(w, `{"error":"unauthorized"}`, http.StatusUnauthorized)
			return
		}

		if _, valid := m.ValidateToken(token); !valid {
			http.Error(w, `{"error":"session expired"}`, http.StatusUnauthorized)
			return
		}

		next.ServeHTTP(w, r)
	})
}

// ChangePassword changes the admin password
func (m *Manager) ChangePassword(oldPassword, newPassword string) error {
	if hashPassword(oldPassword) != m.cfg.Auth.PasswordHash {
		return fmt.Errorf("current password is incorrect")
	}
	if len(newPassword) < 4 {
		return fmt.Errorf("new password must be at least 4 characters")
	}

	hash := hashPassword(newPassword)
	err := m.cfg.Update(func(cfg *config.Config) {
		cfg.Auth.PasswordHash = hash
	})
	if err != nil {
		return err
	}

	// Invalidate all sessions
	m.mu.Lock()
	m.sessions = make(map[string]*Session)
	m.mu.Unlock()

	return nil
}

// cleanupLoop removes expired sessions periodically
func (m *Manager) cleanupLoop() {
	ticker := time.NewTicker(15 * time.Minute)
	defer ticker.Stop()

	for range ticker.C {
		m.mu.Lock()
		now := time.Now()
		for token, session := range m.sessions {
			if now.After(session.ExpiresAt) {
				delete(m.sessions, token)
			}
		}
		m.mu.Unlock()
	}
}

// hashPassword creates a SHA-256 hash of the password
func hashPassword(password string) string {
	hash := sha256.Sum256([]byte(password + "sowa_security_salt_2024"))
	return hex.EncodeToString(hash[:])
}

// generateToken creates a random session token
func generateToken() string {
	bytes := make([]byte, 32)
	if _, err := rand.Read(bytes); err != nil {
		// Fallback
		return fmt.Sprintf("%d", time.Now().UnixNano())
	}
	return hex.EncodeToString(bytes)
}
