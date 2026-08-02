package config

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"strconv"
	"strings"
	"sync"
	"time"

	_ "github.com/mattn/go-sqlite3"
	"golang.org/x/crypto/scrypt"
)

// Store provides persistence for Config using SQLite.
type Store struct {
	db *sql.DB

	// Deriving the encryption key is deliberately expensive, and the inputs
	// only change when the operator changes -secret or the database is
	// replaced. Caching it keeps that cost at startup instead of on every
	// configuration write, which Save is called from on the request path.
	keyMu      sync.Mutex
	cachedKey  []byte
	cachedFor  string
	cachedSalt []byte

	// warnMu guards diagnostics collected before a logger exists. Load runs
	// before the log level is known, so anything worth saying is buffered for
	// the caller to emit once it can.
	warnMu   sync.Mutex
	warnings []string
}

func (s *Store) warn(format string, args ...interface{}) {
	s.warnMu.Lock()
	s.warnings = append(s.warnings, fmt.Sprintf(format, args...))
	s.warnMu.Unlock()
}

// Warnings returns and clears diagnostics gathered since the last call.
func (s *Store) Warnings() []string {
	if s == nil {
		return nil
	}
	s.warnMu.Lock()
	defer s.warnMu.Unlock()
	out := s.warnings
	s.warnings = nil
	return out
}

// key returns the AES key for secret and salt, deriving it at most once per
// distinct pair.
func (s *Store) key(secret string, salt []byte) ([]byte, error) {
	s.keyMu.Lock()
	defer s.keyMu.Unlock()
	if s.cachedKey != nil && s.cachedFor == secret && bytes.Equal(s.cachedSalt, salt) {
		return s.cachedKey, nil
	}
	k, err := deriveKey(secret, salt)
	if err != nil {
		return nil, err
	}
	s.cachedKey, s.cachedFor = k, secret
	s.cachedSalt = append([]byte(nil), salt...)
	return k, nil
}

// sealCredential is encrypt using the cached key.
func (s *Store) sealCredential(secret string, salt []byte, plain string) (string, error) {
	if len(salt) == 0 {
		return "", errors.New("missing kdf salt")
	}
	k, err := s.key(secret, salt)
	if err != nil {
		return "", err
	}
	out, err := seal(k, plain)
	if err != nil {
		return "", err
	}
	return cipherV2Prefix + out, nil
}

// openCredential is decrypt using the cached key, still falling back to the
// legacy derivation for ciphertext written by older builds.
func (s *Store) openCredential(secret string, salt []byte, cipherText string) (string, error) {
	tagged, ok := strings.CutPrefix(cipherText, cipherV2Prefix)
	if !ok {
		return open(deriveKeyLegacy(secret), cipherText)
	}
	if len(salt) == 0 {
		return "", errors.New("missing kdf salt")
	}
	k, err := s.key(secret, salt)
	if err != nil {
		return "", err
	}
	return open(k, tagged)
}

// Ciphertext written by this package is tagged so the key derivation can be
// changed without stranding databases written by an older build. Untagged
// values predate the salted KDF and are read with the legacy derivation.
const cipherV2Prefix = "v2:"

const (
	// scrypt parameters. N is the work factor; 1<<15 is the interactive-login
	// preset and costs ~32MB and a few tens of milliseconds, which is
	// unnoticeable here because credentials are only sealed on save.
	scryptN   = 1 << 15
	scryptR   = 8
	scryptP   = 1
	keyLen    = 32
	kdfSaltLn = 16
)

// deriveKey stretches the operator's secret into an AES key. The salt makes a
// stolen database useless for precomputation, and scrypt's cost makes guessing
// a human-chosen secret expensive rather than instant.
func deriveKey(secret string, salt []byte) ([]byte, error) {
	return scrypt.Key([]byte(secret), salt, scryptN, scryptR, scryptP, keyLen)
}

// deriveKeyLegacy reproduces the original unsalted SHA-256 derivation. Read-only:
// nothing is ever written with it again, and Save re-seals with the current
// scheme the first time it runs.
func deriveKeyLegacy(secret string) []byte {
	h := sha256.Sum256([]byte(secret))
	return h[:]
}

func seal(key []byte, plain string) (string, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return "", err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(gcm.Seal(nonce, nonce, []byte(plain), nil)), nil
}

func open(key []byte, encoded string) (string, error) {
	raw, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		return "", err
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return "", err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}
	if len(raw) < gcm.NonceSize() {
		return "", errors.New("ciphertext too short")
	}
	plain, err := gcm.Open(nil, raw[:gcm.NonceSize()], raw[gcm.NonceSize():], nil)
	if err != nil {
		return "", err
	}
	return string(plain), nil
}

// encrypt seals plain with a salted, stretched key and tags the result.
func encrypt(secret string, salt []byte, plain string) (string, error) {
	if len(salt) == 0 {
		return "", errors.New("missing kdf salt")
	}
	key, err := deriveKey(secret, salt)
	if err != nil {
		return "", err
	}
	out, err := seal(key, plain)
	if err != nil {
		return "", err
	}
	return cipherV2Prefix + out, nil
}

// decrypt opens ciphertext written by either scheme, picking the derivation
// from the tag rather than guessing.
func decrypt(secret string, salt []byte, cipherText string) (string, error) {
	if tagged, ok := strings.CutPrefix(cipherText, cipherV2Prefix); ok {
		if len(salt) == 0 {
			return "", errors.New("missing kdf salt")
		}
		key, err := deriveKey(secret, salt)
		if err != nil {
			return "", err
		}
		return open(key, tagged)
	}
	return open(deriveKeyLegacy(secret), cipherText)
}

// NewStore opens or creates an SQLite database at path and initializes schema.
func NewStore(path string) (*Store, error) {
	db, err := sql.Open("sqlite3", path)
	if err != nil {
		return nil, err
	}
	if err := initSchema(db); err != nil {
		db.Close()
		return nil, err
	}
	return &Store{db: db}, nil
}

func initSchema(db *sql.DB) error {
	_, err := db.Exec(`CREATE TABLE IF NOT EXISTS headers (name TEXT PRIMARY KEY, value TEXT);`)
	if err != nil {
		return err
	}
	_, err = db.Exec(`CREATE TABLE IF NOT EXISTS settings (key TEXT PRIMARY KEY, value TEXT);`)
	if err != nil {
		return err
	}
	return initAuditSchema(db)
}

// Close closes the underlying database.
func (s *Store) Close() error {
	if s == nil || s.db == nil {
		return nil
	}
	return s.db.Close()
}

// salt returns the stored KDF salt, or nil when the database has never been
// written with an encryption secret.
func (s *Store) salt() ([]byte, error) {
	var encoded string
	err := s.db.QueryRow(`SELECT value FROM settings WHERE key='kdf_salt'`).Scan(&encoded)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return base64.StdEncoding.DecodeString(encoded)
}

// ensureSalt returns the stored salt, minting one on first use.
func ensureSalt(tx *sql.Tx) ([]byte, error) {
	var encoded string
	err := tx.QueryRow(`SELECT value FROM settings WHERE key='kdf_salt'`).Scan(&encoded)
	if err == nil {
		if salt, decErr := base64.StdEncoding.DecodeString(encoded); decErr == nil && len(salt) > 0 {
			return salt, nil
		}
		// Unreadable salt: fall through and mint a replacement. Anything sealed
		// with the old one is unrecoverable either way.
	} else if !errors.Is(err, sql.ErrNoRows) {
		return nil, err
	}
	salt := make([]byte, kdfSaltLn)
	if _, err := io.ReadFull(rand.Reader, salt); err != nil {
		return nil, err
	}
	if _, err := tx.Exec(`INSERT OR REPLACE INTO settings(key, value) VALUES('kdf_salt', ?)`,
		base64.StdEncoding.EncodeToString(salt)); err != nil {
		return nil, err
	}
	return salt, nil
}

// Load populates cfg with data from the store. It overrides fields present in the database.
func (s *Store) Load(cfg *Config) error {
	if s == nil || s.db == nil {
		return nil
	}
	rows, err := s.db.Query(`SELECT name, value FROM headers`)
	if err != nil {
		return err
	}
	defer rows.Close()
	for rows.Next() {
		var name, value string
		if err := rows.Scan(&name, &value); err != nil {
			return err
		}
		if err := cfg.SetHeader(name, value); err != nil {
			// Written by an older build, before the map path was validated.
			// Refusing to start over it would strand the proxy on a value only
			// the UI can fix; the next save drops it.
			s.warn("stored header %q is invalid and was ignored: %v", name, err)
		}
	}
	if err := rows.Err(); err != nil {
		return err
	}

	salt, err := s.salt()
	if err != nil {
		return err
	}

	// settings
	var val string
	if err := s.db.QueryRow(`SELECT value FROM settings WHERE key='log_level'`).Scan(&val); err == nil {
		cfg.SetLogLevel(ParseLogLevel(val))
	}
	if err := s.db.QueryRow(`SELECT value FROM settings WHERE key='auth_enabled'`).Scan(&val); err == nil {
		enabled, _ := strconv.ParseBool(val)
		cfg.SetAuthEnabled(enabled)
	}
	if err := s.db.QueryRow(`SELECT value FROM settings WHERE key='stats_enabled'`).Scan(&val); err == nil {
		enabled, _ := strconv.ParseBool(val)
		cfg.SetStatsEnabled(enabled)
	}
	if err := s.db.QueryRow(`SELECT value FROM settings WHERE key='proxy_name'`).Scan(&val); err == nil {
		cfg.SetProxyName(val)
	}
	if err := s.db.QueryRow(`SELECT value FROM settings WHERE key='proxy_id'`).Scan(&val); err == nil {
		cfg.SetProxyID(val)
	}
	if err := s.db.QueryRow(`SELECT value FROM settings WHERE key='client_rules'`).Scan(&val); err == nil {
		if err := cfg.SetClientRules(val); err != nil {
			s.warn("stored client rules are invalid and were ignored: %v", err)
		}
	}
	if err := s.db.QueryRow(`SELECT value FROM settings WHERE key='policy_rules'`).Scan(&val); err == nil {
		if err := cfg.SetPolicyRules(val); err != nil {
			// Refusing to start over a stored rule set would strand the proxy
			// on a value only the UI can fix. Warn and carry on with no rules,
			// which leaves the private-address default in place.
			s.warn("stored policy rules are invalid and were ignored: %v", err)
		}
	}
	if err := s.db.QueryRow(`SELECT value FROM settings WHERE key='quota_rules'`).Scan(&val); err == nil {
		if err := cfg.SetQuotas(val); err != nil {
			s.warn("stored quota rules are invalid and were ignored: %v", err)
		}
	}
	if err := s.db.QueryRow(`SELECT value FROM settings WHERE key='header_rules'`).Scan(&val); err == nil {
		if err := cfg.SetHeaderRules(val); err != nil {
			s.warn("stored header rules are invalid and were ignored: %v", err)
		}
	}

	// The parent's URL and bypass list are plaintext; its credentials come back
	// through the same sealed path as the proxy's own, below.
	var upURL, upBypass string
	if err := s.db.QueryRow(`SELECT value FROM settings WHERE key='upstream_proxy'`).Scan(&val); err == nil {
		upURL = val
	}
	if err := s.db.QueryRow(`SELECT value FROM settings WHERE key='upstream_proxy_bypass'`).Scan(&val); err == nil {
		upBypass = val
	}
	if upURL != "" {
		if err := cfg.SetUpstreamProxy(upURL, upBypass); err != nil {
			s.warn("stored upstream proxy is invalid and was ignored: %v", err)
		}
	}

	_, user, pass := cfg.GetAuth()
	if err := s.db.QueryRow(`SELECT value FROM settings WHERE key='username'`).Scan(&val); err == nil {
		user = s.plaintext(cfg.SecretKey, salt, val, user, "username")
	}
	if err := s.db.QueryRow(`SELECT value FROM settings WHERE key='password'`).Scan(&val); err == nil {
		pass = s.plaintext(cfg.SecretKey, salt, val, pass, "password")
	}
	cfg.SetCredentials(user, pass)

	upUser, upPass := cfg.UpstreamProxyCredentials()
	if err := s.db.QueryRow(`SELECT value FROM settings WHERE key='upstream_proxy_user'`).Scan(&val); err == nil {
		upUser = s.plaintext(cfg.SecretKey, salt, val, upUser, "upstream proxy username")
	}
	if err := s.db.QueryRow(`SELECT value FROM settings WHERE key='upstream_proxy_password'`).Scan(&val); err == nil {
		upPass = s.plaintext(cfg.SecretKey, salt, val, upPass, "upstream proxy password")
	}
	if upUser != "" || upPass != "" {
		cfg.SetUpstreamProxyCredentials(upUser, upPass)
	}
	return nil
}

// plaintext decodes a stored credential, falling back to the value already in
// the config when the secret cannot open it — a wrong -secret should not
// silently blank out working credentials.
func (s *Store) plaintext(secret string, salt []byte, stored, current, what string) string {
	if secret == "" {
		return stored
	}
	dec, err := s.openCredential(secret, salt, stored)
	if err != nil {
		// Keeping the live value is deliberate — a mistyped -secret must not
		// blank working credentials — but doing it silently leaves the operator
		// with no idea the stored value was unreadable, and the next Save
		// re-seals under the new secret and orphans it for good.
		s.warn("stored %s could not be decrypted with the configured -secret; "+
			"keeping the value from flags/environment, and the next save will replace it", what)
		return current
	}
	return dec
}

// Save writes the given configuration to the store, recording what changed.
//
// The audit is computed here, inside the write transaction, rather than by each
// caller. That is deliberate: with fifteen call sites across the UI, the API and
// startup, an audit that every caller has to remember to invoke is complete only
// until someone adds the sixteenth — and then it is silently incomplete while
// still looking complete, which is worse than not having one. Diffing here makes
// coverage a property of the code rather than of everyone's diligence, and gets
// "same transaction as the change" for free: a write that rolls back leaves no
// entry claiming it happened.
func (s *Store) Save(cfg *Config, by Actor) error {
	if s == nil || s.db == nil {
		return nil
	}
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback() //nolint:errcheck // no-op once committed

	// headers
	if _, err := tx.Exec(`DELETE FROM headers`); err != nil {
		return err
	}
	for k, v := range cfg.GetHeaders() {
		if _, err := tx.Exec(`INSERT INTO headers(name, value) VALUES(?, ?)`, k, v); err != nil {
			return err
		}
	}

	authEnabled, user, pass := cfg.GetAuth()
	proxyName, proxyID := cfg.GetIdentity()
	settings := [][2]string{
		{"log_level", LevelString(cfg.GetLogLevel())},
		{"auth_enabled", strconv.FormatBool(authEnabled)},
		{"stats_enabled", strconv.FormatBool(cfg.StatsEnabledState())},
		{"proxy_name", proxyName},
		{"proxy_id", proxyID},
		{"policy_rules", cfg.PolicyRulesText()},
		{"client_rules", cfg.ClientRulesText()},
		{"quota_rules", cfg.QuotaText()},
		{"header_rules", cfg.HeaderRulesText()},
		{"upstream_proxy", cfg.UpstreamProxyURL()},
		{"upstream_proxy_bypass", cfg.UpstreamProxyBypass()},
	}

	// The parent proxy's credentials are sealed on the same path as the proxy's
	// own, so -secret covers both rather than protecting one and leaving the
	// other in the clear.
	upUser, upPass := cfg.UpstreamProxyCredentials()

	// Keep the plaintext for the audit diff before sealing replaces them.
	userPlain, passPlain := user, pass
	upUserPlain, upPassPlain := upUser, upPass

	if cfg.SecretKey != "" {
		salt, err := ensureSalt(tx)
		if err != nil {
			return err
		}
		// Only substitute the ciphertext if sealing succeeded; writing the
		// plaintext because encryption failed would be the worst outcome.
		if enc, err := s.sealCredential(cfg.SecretKey, salt, user); err == nil {
			user = enc
		} else {
			return err
		}
		if enc, err := s.sealCredential(cfg.SecretKey, salt, pass); err == nil {
			pass = enc
		} else {
			return err
		}
		if upUser != "" {
			if enc, err := s.sealCredential(cfg.SecretKey, salt, upUser); err == nil {
				upUser = enc
			} else {
				return err
			}
		}
		if upPass != "" {
			if enc, err := s.sealCredential(cfg.SecretKey, salt, upPass); err == nil {
				upPass = enc
			} else {
				return err
			}
		}
	}
	// Diff before writing, and diff the credentials on their plaintext.
	//
	// Sealing uses a fresh nonce every time, so the stored ciphertext differs on
	// every save even when the password is untouched. Comparing stored forms
	// would therefore record a credential change on every single write — an
	// audit that cries wolf is worse than no audit, because it trains whoever
	// reads it to ignore exactly the entry that matters.
	plainCreds := map[string]string{
		"username":                userPlain,
		"password":                passPlain,
		"upstream_proxy_user":     upUserPlain,
		"upstream_proxy_password": upPassPlain,
	}
	changes, err := s.diff(tx, cfg, settings, plainCreds)
	if err != nil {
		return err
	}

	settings = append(settings,
		[2]string{"username", user}, [2]string{"password", pass},
		[2]string{"upstream_proxy_user", upUser}, [2]string{"upstream_proxy_password", upPass})

	for _, kv := range settings {
		if _, err := tx.Exec(`INSERT OR REPLACE INTO settings(key, value) VALUES(?, ?)`, kv[0], kv[1]); err != nil {
			return err
		}
	}
	if err := recordAudit(tx, by, changes, time.Now()); err != nil {
		return err
	}
	return tx.Commit()
}

// diff reports what this Save will change, reading the current values through
// the caller's transaction so the comparison and the write see the same state.
//
// plainCreds carries the credential settings by their plaintext, keyed by
// setting name; those are compared on plaintext and recorded redacted.
func (s *Store) diff(tx *sql.Tx, cfg *Config, settings [][2]string, plainCreds map[string]string) ([]AuditEntry, error) {
	var out []AuditEntry

	for _, kv := range settings {
		key, newValue := kv[0], kv[1]
		oldValue, err := storedSetting(tx, key)
		if err != nil {
			return nil, err
		}
		if oldValue == newValue {
			continue
		}
		out = append(out, AuditEntry{Setting: key, OldValue: oldValue, NewValue: newValue})
	}

	for key, newPlain := range plainCreds {
		stored, err := storedSetting(tx, key)
		if err != nil {
			return nil, err
		}
		oldPlain := stored
		if cfg.SecretKey != "" && stored != "" {
			salt, err := ensureSalt(tx)
			if err != nil {
				return nil, err
			}
			// An unreadable stored credential is about to be replaced anyway.
			// Treat it as different rather than failing the whole save.
			if dec, err := s.openCredential(cfg.SecretKey, salt, stored); err == nil {
				oldPlain = dec
			} else {
				oldPlain = "\x00unreadable"
			}
		}
		if oldPlain == newPlain {
			continue
		}
		out = append(out, AuditEntry{
			Setting:  key,
			OldValue: auditValue(oldPlain),
			NewValue: auditValue(newPlain),
		})
	}
	return out, nil
}

// storedSetting reads a setting through the transaction, treating "absent" as
// empty — which is what an unset setting means everywhere else here.
func storedSetting(tx *sql.Tx, key string) (string, error) {
	var v string
	err := tx.QueryRow(`SELECT value FROM settings WHERE key = ?`, key).Scan(&v)
	if errors.Is(err, sql.ErrNoRows) {
		return "", nil
	}
	if err != nil {
		return "", err
	}
	return v, nil
}

// CredentialsAtRisk reports whether Save would persist non-empty credentials
// without encrypting them, so the caller can warn once the logger exists.
func CredentialsAtRisk(cfg *Config) bool {
	if cfg.SecretKey != "" {
		return false
	}
	_, user, pass := cfg.GetAuth()
	return user != "" || pass != ""
}
