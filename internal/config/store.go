package config

import (
	"database/sql"
	_ "github.com/mattn/go-sqlite3"
)

// Store provides persistence for Config using SQLite.
type Store struct {
	db *sql.DB
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
	return tx.Commit()
}
