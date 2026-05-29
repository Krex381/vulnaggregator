import { createClient } from '@libsql/client'
import { config } from '../config.js'

let _client: ReturnType<typeof createClient> | null = null

export function getDb() {
  if (!_client) {
    _client = createClient({
      url: config.TURSO_DB_URL,
      authToken: config.TURSO_DB_TOKEN,
    })
  }
  return _client
}

export async function ensureSchema() {
  const db = getDb()
  const tables = await db.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='vulnerabilities'")
  if (tables.rows.length === 0) {
    await db.execute(`CREATE TABLE vulnerabilities (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      cve_id TEXT NOT NULL DEFAULT '',
      title TEXT NOT NULL DEFAULT '',
      description TEXT NOT NULL DEFAULT '',
      severity TEXT NOT NULL DEFAULT 'UNKNOWN',
      cvss_score REAL,
      vendor TEXT NOT NULL DEFAULT '',
      product TEXT NOT NULL DEFAULT '',
      source TEXT NOT NULL,
      source_url TEXT NOT NULL DEFAULT '',
      published_at TEXT NOT NULL,
      hash TEXT UNIQUE NOT NULL,
      notified INTEGER NOT NULL DEFAULT 0,
      created_at TEXT NOT NULL DEFAULT (datetime('now'))
    )`)
    await db.execute(`CREATE INDEX idx_vulns_cve_id ON vulnerabilities(cve_id)`)
    await db.execute(`CREATE INDEX idx_vulns_severity ON vulnerabilities(severity)`)
    await db.execute(`CREATE INDEX idx_vulns_source ON vulnerabilities(source)`)
    await db.execute(`CREATE INDEX idx_vulns_published_at ON vulnerabilities(published_at)`)
    await db.execute(`CREATE INDEX idx_vulns_notified ON vulnerabilities(notified)`)

    await db.execute(`CREATE TABLE filters (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      name TEXT NOT NULL,
      severity_filter TEXT,
      vendor_filter TEXT,
      keyword_filter TEXT,
      min_cvss REAL,
      cisa_kev_only INTEGER DEFAULT 0,
      enabled INTEGER DEFAULT 1
    )`)
    await db.execute(`CREATE INDEX idx_filters_enabled ON filters(enabled)`)

    await db.execute(`CREATE TABLE alert_log (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      vuln_id INTEGER NOT NULL REFERENCES vulnerabilities(id),
      filter_id INTEGER REFERENCES filters(id),
      delivered INTEGER DEFAULT 0,
      error TEXT,
      attempted_at TEXT NOT NULL DEFAULT (datetime('now'))
    )`)
    await db.execute(`CREATE INDEX idx_alert_log_vuln_id ON alert_log(vuln_id)`)
    await db.execute(`CREATE INDEX idx_alert_log_delivered ON alert_log(delivered)`)
  }
}
