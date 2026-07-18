package auth

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/ClearNetSky/CNS-SOWA-SECURITY/internal/config"
)

const (
	// maxLoginFailures is the number of failed attempts per IP before lockout
	maxLoginFailures = 5
	// loginLockDuration is how long an IP stays locked out
	loginLockDuration = 15 * time.Minute
	// minPasswordLength is the minimum accepted admin password length
	minPasswordLength = 8

	// PBKDF2 parameters for password hashing
	pbkdf2Iterations = 150000
	pbkdf2KeyLen     = 32
	// legacySalt was used by the old unsalted SHA-256 scheme; kept only
	// to verify (and transparently upgrade) pre-1.5.0 password hashes
	legacySalt = "sowa_security_salt_2024"
)

// Manager handles authentication and session management
type Manager struct {
	cfg      *config.Config
	sessions map[string]*Session
	failed   map[string]*loginAttempts
	mu       sync.RWMutex
}

// loginAttempts tracks failed logins per client IP for brute-force protection
type loginAttempts struct {
	failures    int
	lockedUntil time.Time
	lastFailure time.Time
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
		failed:   make(map[string]*loginAttempts),
	}

	// Restore sessions persisted by a previous run so a server restart
	// does not log every admin out
	m.loadSessions()

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
	if len(password) < minPasswordLength {
		return fmt.Errorf("password must be at least %d characters", minPasswordLength)
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

	// Brute-force protection: reject while the IP is locked out
	if locked, remaining := m.isLockedOut(ip); locked {
		log.Printf("[Auth] Login blocked for %s: too many failed attempts (retry in %s)", ip, remaining.Round(time.Second))
		return nil, fmt.Errorf("too many failed attempts, try again in %s", remaining.Round(time.Second))
	}

	userOK := subtle.ConstantTimeCompare([]byte(username), []byte(m.cfg.Auth.Username)) == 1
	passOK := verifyPassword(password, m.cfg.Auth.PasswordHash)
	if !userOK || !passOK {
		m.recordFailure(ip)
		log.Printf("[Auth] Failed login attempt for user '%s' from %s", username, ip)
		return nil, fmt.Errorf("invalid credentials")
	}

	m.clearFailures(ip)

	// Transparently upgrade pre-1.5.0 unsalted hashes to PBKDF2
	if isLegacyHash(m.cfg.Auth.PasswordHash) {
		newHash := hashPassword(password)
		if err := m.cfg.Update(func(cfg *config.Config) {
			cfg.Auth.PasswordHash = newHash
		}); err == nil {
			log.Printf("[Auth] Password hash upgraded to PBKDF2 for user '%s'", username)
		}
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
	m.saveSessions()

	log.Printf("[Auth] User '%s' logged in from %s", username, ip)

	return &LoginResponse{
		Token:     token,
		ExpiresAt: session.ExpiresAt.Unix(),
	}, nil
}

// isLockedOut reports whether an IP is currently locked out and for how long
func (m *Manager) isLockedOut(ip string) (bool, time.Duration) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	if a, ok := m.failed[ip]; ok && time.Now().Before(a.lockedUntil) {
		return true, time.Until(a.lockedUntil)
	}
	return false, 0
}

// recordFailure registers a failed login and locks the IP after too many
func (m *Manager) recordFailure(ip string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	a, ok := m.failed[ip]
	if !ok {
		a = &loginAttempts{}
		m.failed[ip] = a
	}
	a.failures++
	a.lastFailure = time.Now()
	if a.failures >= maxLoginFailures {
		a.lockedUntil = time.Now().Add(loginLockDuration)
		a.failures = 0
		log.Printf("[Auth] IP %s locked out for %s after repeated failed logins", ip, loginLockDuration)
	}
}

// clearFailures resets the failure counter after a successful login
func (m *Manager) clearFailures(ip string) {
	m.mu.Lock()
	delete(m.failed, ip)
	m.mu.Unlock()
}

// Logout invalidates a session
func (m *Manager) Logout(token string) {
	m.mu.Lock()
	delete(m.sessions, token)
	m.mu.Unlock()
	m.saveSessions()
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
	if !verifyPassword(oldPassword, m.cfg.Auth.PasswordHash) {
		return fmt.Errorf("current password is incorrect")
	}
	if len(newPassword) < minPasswordLength {
		return fmt.Errorf("new password must be at least %d characters", minPasswordLength)
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
	m.saveSessions()

	return nil
}

// cleanupLoop removes expired sessions periodically
func (m *Manager) cleanupLoop() {
	ticker := time.NewTicker(15 * time.Minute)
	defer ticker.Stop()

	for range ticker.C {
		m.mu.Lock()
		now := time.Now()
		removed := 0
		for token, session := range m.sessions {
			if now.After(session.ExpiresAt) {
				delete(m.sessions, token)
				removed++
			}
		}
		// Drop stale brute-force tracking entries
		for ip, a := range m.failed {
			if now.After(a.lockedUntil) && now.Sub(a.lastFailure) > time.Hour {
				delete(m.failed, ip)
			}
		}
		m.mu.Unlock()
		if removed > 0 {
			m.saveSessions()
		}
	}
}

// ==================== Session Persistence ====================

func (m *Manager) sessionsFilePath() string {
	return filepath.Join(config.GetConfigDir(), "sessions.json")
}

// saveSessions persists active sessions so restarts keep admins logged in
func (m *Manager) saveSessions() {
	m.mu.RLock()
	list := make([]*Session, 0, len(m.sessions))
	for _, s := range m.sessions {
		list = append(list, s)
	}
	m.mu.RUnlock()

	data, err := json.MarshalIndent(list, "", "  ")
	if err != nil {
		return
	}
	// 0600: the file contains session tokens
	if err := os.WriteFile(m.sessionsFilePath(), data, 0600); err != nil {
		log.Printf("[Auth] Warning: failed to persist sessions: %v", err)
	}
}

// loadSessions restores previously persisted, still-valid sessions
func (m *Manager) loadSessions() {
	data, err := os.ReadFile(m.sessionsFilePath())
	if err != nil {
		return // no previous sessions
	}

	var list []*Session
	if err := json.Unmarshal(data, &list); err != nil {
		log.Printf("[Auth] Warning: failed to parse sessions file: %v", err)
		return
	}

	now := time.Now()
	restored := 0
	m.mu.Lock()
	for _, s := range list {
		if s != nil && s.Token != "" && s.ExpiresAt.After(now) {
			m.sessions[s.Token] = s
			restored++
		}
	}
	m.mu.Unlock()

	if restored > 0 {
		log.Printf("[Auth] Restored %d active session(s)", restored)
	}
}

// ==================== Password Hashing ====================

// hashPassword creates a salted PBKDF2-SHA256 hash in the format
// pbkdf2:sha256:<iterations>:<salt-hex>:<key-hex>
func hashPassword(password string) string {
	salt := make([]byte, 16)
	if _, err := rand.Read(salt); err != nil {
		// Extremely unlikely; fall back to a time-derived salt rather
		// than storing an unsalted hash
		fallback := sha256.Sum256([]byte(fmt.Sprintf("%d", time.Now().UnixNano())))
		copy(salt, fallback[:16])
	}
	key := pbkdf2Key([]byte(password), salt, pbkdf2Iterations, pbkdf2KeyLen)
	return fmt.Sprintf("pbkdf2:sha256:%d:%s:%s",
		pbkdf2Iterations, hex.EncodeToString(salt), hex.EncodeToString(key))
}

// verifyPassword checks a password against a stored hash. It supports the
// current PBKDF2 format and the legacy unsalted SHA-256 format.
func verifyPassword(password, stored string) bool {
	if stored == "" {
		return false
	}
	if strings.HasPrefix(stored, "pbkdf2:sha256:") {
		parts := strings.Split(stored, ":")
		if len(parts) != 5 {
			return false
		}
		iter, err := strconv.Atoi(parts[2])
		if err != nil || iter <= 0 || iter > 10_000_000 {
			return false
		}
		salt, err := hex.DecodeString(parts[3])
		if err != nil {
			return false
		}
		want, err := hex.DecodeString(parts[4])
		if err != nil || len(want) == 0 {
			return false
		}
		got := pbkdf2Key([]byte(password), salt, iter, len(want))
		return subtle.ConstantTimeCompare(got, want) == 1
	}

	// Legacy pre-1.5.0 format: sha256(password + static salt)
	legacy := sha256.Sum256([]byte(password + legacySalt))
	return subtle.ConstantTimeCompare(
		[]byte(hex.EncodeToString(legacy[:])), []byte(stored)) == 1
}

// isLegacyHash reports whether a stored hash uses the old unsalted format
func isLegacyHash(stored string) bool {
	return stored != "" && !strings.HasPrefix(stored, "pbkdf2:")
}

// pbkdf2Key implements PBKDF2 (RFC 2898) with HMAC-SHA256 using only the
// standard library, so no extra dependencies are required.
func pbkdf2Key(password, salt []byte, iter, keyLen int) []byte {
	prf := hmac.New(sha256.New, password)
	hashLen := prf.Size()
	numBlocks := (keyLen + hashLen - 1) / hashLen

	var buf [4]byte
	dk := make([]byte, 0, numBlocks*hashLen)
	u := make([]byte, hashLen)
	for block := 1; block <= numBlocks; block++ {
		prf.Reset()
		prf.Write(salt)
		buf[0] = byte(block >> 24)
		buf[1] = byte(block >> 16)
		buf[2] = byte(block >> 8)
		buf[3] = byte(block)
		prf.Write(buf[:4])
		dk = prf.Sum(dk)
		t := dk[len(dk)-hashLen:]
		copy(u, t)
		for n := 2; n <= iter; n++ {
			prf.Reset()
			prf.Write(u)
			u = u[:0]
			u = prf.Sum(u)
			for x := range u {
				t[x] ^= u[x]
			}
		}
	}
	return dk[:keyLen]
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
