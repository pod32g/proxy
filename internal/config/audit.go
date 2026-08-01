package config

import (
	"database/sql"
	"fmt"
	"time"
)

// AuditRetention is how many entries the trail keeps. Trimming happens in the
// same transaction as the write that adds a row, so the table cannot grow
// without bound and the bound is one number rather than an external job that
// someone has to remember to schedule.
//
// At one entry per changed setting, this is thousands of configuration changes
// — far more history than an admin surface with a handful of settings will
// produce between the incident and the investigation.
const AuditRetention = 5000

// Via says which surface a change arrived through.
const (
	ViaUI      = "ui"
	ViaAPI     = "api"
	ViaStartup = "startup"
)

// Actor is who made a change. Every field is optional; a zero Actor records an
// anonymous change rather than suppressing the entry, because "we do not know
// who did this" is itself worth knowing.
type Actor struct {
	// Source is the address the change came from.
	Source string
	// User is the authenticated username, when authentication is on.
	User string
	// Via is ViaUI, ViaAPI or ViaStartup.
	Via string
}

// AuditEntry is one recorded change.
type AuditEntry struct {
	ID       int64     `json:"id"`
	At       time.Time `json:"at"`
	Source   string    `json:"source,omitempty"`
	User     string    `json:"user,omitempty"`
	Via      string    `json:"via,omitempty"`
	Setting  string    `json:"setting"`
	OldValue string    `json:"old_value"`
	NewValue string    `json:"new_value"`
}

// Values a credential is rendered as. The trail records that a credential
// changed and never what it changed to — but "unset" to "set" is a real
// transition an investigation wants to see, and neither word is a secret.
const (
	auditSet   = "[set]"
	auditUnset = "[unset]"
)

// auditValue renders a credential for the trail.
func auditValue(v string) string {
	if v == "" {
		return auditUnset
	}
	return auditSet
}

// redactedSettings are recorded as changed, never with their value.
//
// The username is in here as well as the password. It is half a credential, and
// an operator who set -secret specifically to keep credentials out of a
// readable database would not expect the audit table to hand one back.
var redactedSettings = map[string]bool{
	"username":                true,
	"password":                true,
	"upstream_proxy_user":     true,
	"upstream_proxy_password": true,
}

func initAuditSchema(db *sql.DB) error {
	_, err := db.Exec(`CREATE TABLE IF NOT EXISTS audit (
		id        INTEGER PRIMARY KEY AUTOINCREMENT,
		ts        TEXT NOT NULL,
		source    TEXT,
		actor     TEXT,
		via       TEXT,
		setting   TEXT NOT NULL,
		old_value TEXT,
		new_value TEXT
	);`)
	return err
}

// recordAudit writes one row per changed setting and trims the table, using the
// caller's transaction so the trail and the change it describes commit or roll
// back together. An audit row for a write that failed would be worse than no
// row at all.
func recordAudit(tx *sql.Tx, by Actor, changes []AuditEntry, now time.Time) error {
	if len(changes) == 0 {
		return nil
	}
	stamp := now.UTC().Format(time.RFC3339Nano)
	for _, c := range changes {
		if _, err := tx.Exec(
			`INSERT INTO audit(ts, source, actor, via, setting, old_value, new_value)
			 VALUES(?, ?, ?, ?, ?, ?, ?)`,
			stamp, by.Source, by.User, by.Via, c.Setting, c.OldValue, c.NewValue,
		); err != nil {
			return fmt.Errorf("recording audit entry for %q: %w", c.Setting, err)
		}
	}
	// Trim by id rather than by age: a row count is a hard bound on the table,
	// where a time window is a bound only if changes arrive at the rate you
	// guessed they would.
	_, err := tx.Exec(
		`DELETE FROM audit WHERE id <= (SELECT MAX(id) FROM audit) - ?`, AuditRetention)
	return err
}

// Audit returns the most recent entries, newest first. Read-only: nothing in
// the proxy edits or deletes an entry, and the only removal is the retention
// trim above.
func (s *Store) Audit(limit int) ([]AuditEntry, error) {
	if s == nil || s.db == nil {
		return nil, nil
	}
	if limit <= 0 || limit > AuditRetention {
		limit = 100
	}
	rows, err := s.db.Query(
		`SELECT id, ts, source, actor, via, setting, old_value, new_value
		 FROM audit ORDER BY id DESC LIMIT ?`, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []AuditEntry
	for rows.Next() {
		var e AuditEntry
		var ts string
		var source, actor, via, oldV, newV sql.NullString
		if err := rows.Scan(&e.ID, &ts, &source, &actor, &via, &e.Setting, &oldV, &newV); err != nil {
			return nil, err
		}
		e.At, _ = time.Parse(time.RFC3339Nano, ts)
		e.Source, e.User, e.Via = source.String, actor.String, via.String
		e.OldValue, e.NewValue = oldV.String, newV.String
		out = append(out, e)
	}
	return out, rows.Err()
}
