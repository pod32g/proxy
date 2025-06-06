package config

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/base64"
	"errors"
	"io"
	"strconv"

	_ "github.com/mattn/go-sqlite3"
)

// Store provides persistence for Config using SQLite.
type Store struct {
	db *sql.DB
}

func encrypt(key, plain string) (string, error) {
	h := sha256.Sum256([]byte(key))
	block, err := aes.NewCipher(h[:])
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
	data := gcm.Seal(nonce, nonce, []byte(plain), nil)
	return base64.StdEncoding.EncodeToString(data), nil
}

func decrypt(key, cipherText string) (string, error) {
	raw, err := base64.StdEncoding.DecodeString(cipherText)
	if err != nil {
		return "", err
	}
	h := sha256.Sum256([]byte(key))
	block, err := aes.NewCipher(h[:])
	if err != nil {
		return "", err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}
	nonceSize := gcm.NonceSize()
	if len(raw) < nonceSize {
		return "", errors.New("ciphertext too short")
	}
	nonce := raw[:nonceSize]
	plain, err := gcm.Open(nil, nonce, raw[nonceSize:], nil)
	if err != nil {
		return "", err
	}
	return string(plain), nil
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
	return err
}

// Close closes the underlying database.
func (s *Store) Close() error {
	if s == nil || s.db == nil {
		return nil
	}
	return s.db.Close()
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
		cfg.SetHeader(name, value)
	}
	// settings
	var val string
	if err := s.db.QueryRow(`SELECT value FROM settings WHERE key='log_level'`).Scan(&val); err == nil {
		cfg.SetLogLevel(ParseLogLevel(val))
	}
	if err := s.db.QueryRow(`SELECT value FROM settings WHERE key='auth_enabled'`).Scan(&val); err == nil {
		cfg.AuthEnabled, _ = strconv.ParseBool(val)
	}
	if err := s.db.QueryRow(`SELECT value FROM settings WHERE key='stats_enabled'`).Scan(&val); err == nil {
		cfg.StatsEnabled, _ = strconv.ParseBool(val)
	}
	if err := s.db.QueryRow(`SELECT value FROM settings WHERE key='debug_logs'`).Scan(&val); err == nil {
		cfg.DebugLogs, _ = strconv.ParseBool(val)
	}
	if err := s.db.QueryRow(`SELECT value FROM settings WHERE key='ultra_debug'`).Scan(&val); err == nil {
		cfg.UltraDebug, _ = strconv.ParseBool(val)
	}
	if err := s.db.QueryRow(`SELECT value FROM settings WHERE key='username'`).Scan(&val); err == nil {
		if cfg.SecretKey != "" {
			if dec, err := decrypt(cfg.SecretKey, val); err == nil {
				cfg.Username = dec
			}
		} else {
			cfg.Username = val
		}
	}
	if err := s.db.QueryRow(`SELECT value FROM settings WHERE key='password'`).Scan(&val); err == nil {
		if cfg.SecretKey != "" {
			if dec, err := decrypt(cfg.SecretKey, val); err == nil {
				cfg.Password = dec
			}
		} else {
			cfg.Password = val
		}
	}
	return rows.Err()
}

// Save writes the given configuration to the store.
func (s *Store) Save(cfg *Config) error {
	if s == nil || s.db == nil {
		return nil
	}
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	// headers
	if _, err := tx.Exec(`DELETE FROM headers`); err != nil {
		tx.Rollback()
		return err
	}
	for k, v := range cfg.GetHeaders() {
		if _, err := tx.Exec(`INSERT INTO headers(name, value) VALUES(?, ?)`, k, v); err != nil {
			tx.Rollback()
			return err
		}
	}
	// log level
	if _, err := tx.Exec(`INSERT OR REPLACE INTO settings(key, value) VALUES('log_level', ?)`, LevelString(cfg.GetLogLevel())); err != nil {
		tx.Rollback()
		return err
	}
	if _, err := tx.Exec(`INSERT OR REPLACE INTO settings(key, value) VALUES('auth_enabled', ?)`, strconv.FormatBool(cfg.AuthEnabled)); err != nil {
		tx.Rollback()
		return err
	}
	if _, err := tx.Exec(`INSERT OR REPLACE INTO settings(key, value) VALUES('stats_enabled', ?)`, strconv.FormatBool(cfg.StatsEnabled)); err != nil {
		tx.Rollback()
		return err
	}
	if _, err := tx.Exec(`INSERT OR REPLACE INTO settings(key, value) VALUES('debug_logs', ?)`, strconv.FormatBool(cfg.DebugLogs)); err != nil {
		tx.Rollback()
		return err
	}
	if _, err := tx.Exec(`INSERT OR REPLACE INTO settings(key, value) VALUES('ultra_debug', ?)`, strconv.FormatBool(cfg.UltraDebug)); err != nil {
		tx.Rollback()
		return err
	}
	user := cfg.Username
	pass := cfg.Password
	if cfg.SecretKey != "" {
		if enc, err := encrypt(cfg.SecretKey, cfg.Username); err == nil {
			user = enc
		}
		if enc, err := encrypt(cfg.SecretKey, cfg.Password); err == nil {
			pass = enc
		}
	}
	if _, err := tx.Exec(`INSERT OR REPLACE INTO settings(key, value) VALUES('username', ?)`, user); err != nil {
		tx.Rollback()
		return err
	}
	if _, err := tx.Exec(`INSERT OR REPLACE INTO settings(key, value) VALUES('password', ?)`, pass); err != nil {
		tx.Rollback()
		return err
	}
	return tx.Commit()
}
