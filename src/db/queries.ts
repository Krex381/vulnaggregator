import { getDb } from './client.js'
import type { NormalizedVuln, FilterRule, AlertLog, Severity } from '../models.js'

export async function markNotifiedBatch(ids: number[]): Promise<void> {
  if (ids.length === 0) return
  const db = getDb()
  const placeholders = ids.map(() => '?').join(',')
  await db.execute({ sql: `UPDATE vulnerabilities SET notified = 1 WHERE id IN (${placeholders})`, args: ids })
}

export async function getVulns(params: {
  severity?: Severity
  vendor?: string
  source?: string
  page: number
  limit: number
}): Promise<{ rows: NormalizedVuln[]; total: number }> {
  const db = getDb()
  const conditions: string[] = []
  const args: (string | number)[] = []

  if (params.severity) { conditions.push('severity = ?'); args.push(params.severity) }
  if (params.vendor) { conditions.push('vendor = ?'); args.push(params.vendor) }
  if (params.source) { conditions.push('source = ?'); args.push(params.source) }

  const where = conditions.length > 0 ? 'WHERE ' + conditions.join(' AND ') : ''
  const offset = (params.page - 1) * params.limit

  const countResult = await db.execute({ sql: `SELECT COUNT(*) as c FROM vulnerabilities ${where}`, args })
  const total = Number(countResult.rows[0]?.c ?? 0)

  const result = await db.execute({
    sql: `SELECT * FROM vulnerabilities ${where} ORDER BY published_at DESC LIMIT ? OFFSET ?`,
    args: [...args, params.limit, offset],
  })

  return { rows: result.rows.map(mapRow), total }
}

export async function getVulnById(id: number): Promise<NormalizedVuln | null> {
  const db = getDb()
  const result = await db.execute({ sql: 'SELECT * FROM vulnerabilities WHERE id = ?', args: [id] })
  return result.rows.length > 0 ? mapRow(result.rows[0]) : null
}

export async function getStats(): Promise<{
  total: number; bySeverity: Record<string, number>; bySource: Record<string, number>; last24h: number; notified: number; pending: number
}> {
  const db = getDb()
  const [totalRes, sevRes, srcRes, recentRes, notifiedRes, pendingRes] = await Promise.all([
    db.execute('SELECT COUNT(*) as c FROM vulnerabilities'),
    db.execute('SELECT severity, COUNT(*) as c FROM vulnerabilities GROUP BY severity'),
    db.execute('SELECT source, COUNT(*) as c FROM vulnerabilities GROUP BY source'),
    db.execute("SELECT COUNT(*) as c FROM vulnerabilities WHERE published_at >= datetime('now', '-1 day')"),
    db.execute('SELECT COUNT(*) as c FROM vulnerabilities WHERE notified = 1'),
    db.execute('SELECT COUNT(*) as c FROM vulnerabilities WHERE notified = 0'),
  ])
  const bySeverity: Record<string, number> = {}
  for (const r of sevRes.rows) bySeverity[r.severity as string] = Number(r.c)
  const bySource: Record<string, number> = {}
  for (const r of srcRes.rows) bySource[r.source as string] = Number(r.c)
  return {
    total: Number(totalRes.rows[0]?.c ?? 0),
    bySeverity,
    bySource,
    last24h: Number(recentRes.rows[0]?.c ?? 0),
    notified: Number(notifiedRes.rows[0]?.c ?? 0),
    pending: Number(pendingRes.rows[0]?.c ?? 0),
  }
}

export async function getEnabledFilters(): Promise<FilterRule[]> {
  const db = getDb()
  const result = await db.execute('SELECT * FROM filters WHERE enabled = 1')
  return result.rows.map(r => ({
    id: Number(r.id),
    name: r.name as string,
    severityFilter: JSON.parse((r.severity_filter as string) ?? '[]'),
    vendorFilter: JSON.parse((r.vendor_filter as string) ?? '[]'),
    keywordFilter: JSON.parse((r.keyword_filter as string) ?? '[]'),
    minCvss: (r.min_cvss as number) ?? null,
    cisaKevOnly: Number(r.cisa_kev_only) === 1,
    enabled: Number(r.enabled),
  }))
}

export async function getFilters(): Promise<FilterRule[]> {
  const db = getDb()
  const result = await db.execute('SELECT * FROM filters ORDER BY id')
  return result.rows.map(r => ({
    id: Number(r.id),
    name: r.name as string,
    severityFilter: JSON.parse((r.severity_filter as string) ?? '[]'),
    vendorFilter: JSON.parse((r.vendor_filter as string) ?? '[]'),
    keywordFilter: JSON.parse((r.keyword_filter as string) ?? '[]'),
    minCvss: (r.min_cvss as number) ?? null,
    cisaKevOnly: Number(r.cisa_kev_only) === 1,
    enabled: Number(r.enabled),
  }))
}

export async function createFilter(f: Omit<FilterRule, 'id'>): Promise<number> {
  const db = getDb()
  const result = await db.execute({
    sql: `INSERT INTO filters (name, severity_filter, vendor_filter, keyword_filter, min_cvss, cisa_kev_only, enabled) VALUES (?, ?, ?, ?, ?, ?, ?)`,
    args: [
      f.name,
      JSON.stringify(f.severityFilter),
      JSON.stringify(f.vendorFilter),
      JSON.stringify(f.keywordFilter),
      f.minCvss,
      f.cisaKevOnly ? 1 : 0,
      f.enabled,
    ],
  })
  return Number(result.lastInsertRowid!)
}

export async function updateFilter(id: number, f: Partial<FilterRule>): Promise<boolean> {
  const db = getDb()
  const sets: string[] = []
  const args: (string | number | null)[] = []
  if (f.name !== undefined) { sets.push('name = ?'); args.push(f.name) }
  if (f.severityFilter !== undefined) { sets.push('severity_filter = ?'); args.push(JSON.stringify(f.severityFilter)) }
  if (f.vendorFilter !== undefined) { sets.push('vendor_filter = ?'); args.push(JSON.stringify(f.vendorFilter)) }
  if (f.keywordFilter !== undefined) { sets.push('keyword_filter = ?'); args.push(JSON.stringify(f.keywordFilter)) }
  if (f.minCvss !== undefined) { sets.push('min_cvss = ?'); args.push(f.minCvss) }
  if (f.cisaKevOnly !== undefined) { sets.push('cisa_kev_only = ?'); args.push(f.cisaKevOnly ? 1 : 0) }
  if (f.enabled !== undefined) { sets.push('enabled = ?'); args.push(f.enabled) }
  if (sets.length === 0) return false
  args.push(id)
  const result = await db.execute({ sql: `UPDATE filters SET ${sets.join(', ')} WHERE id = ?`, args })
  return result.rowsAffected > 0
}

export async function deleteFilter(id: number): Promise<boolean> {
  const db = getDb()
  const result = await db.execute({ sql: 'DELETE FROM filters WHERE id = ?', args: [id] })
  return result.rowsAffected > 0
}

export async function insertAlertLogBatch(logs: { vulnId: number; filterId: number | null; delivered: number; error: string | null }[]): Promise<void> {
  if (logs.length === 0) return
  const db = getDb()
  const batchSize = 100
  for (let i = 0; i < logs.length; i += batchSize) {
    const batch = logs.slice(i, i + batchSize)
    const placeholders = batch.map(() => '(?, ?, ?, ?)').join(', ')
    const args: (string | number | null)[] = []
    for (const log of batch) {
      args.push(log.vulnId, log.filterId, log.delivered, log.error)
    }
    await db.execute({
      sql: `INSERT INTO alert_log (vuln_id, filter_id, delivered, error) VALUES ${placeholders}`,
      args,
    })
  }
}

function mapRow(r: Record<string, unknown>): NormalizedVuln {
  return {
    id: Number(r.id),
    cveId: (r.cve_id as string) ?? '',
    title: (r.title as string) ?? '',
    description: (r.description as string) ?? '',
    severity: (r.severity as string) as Severity,
    cvssScore: (r.cvss_score as number) ?? null,
    vendor: (r.vendor as string) ?? '',
    product: (r.product as string) ?? '',
    source: (r.source as string) ?? '',
    sourceUrl: (r.source_url as string) ?? '',
    publishedAt: (r.published_at as string) ?? '',
    hash: (r.hash as string) ?? '',
    notified: Number(r.notified),
    createdAt: (r.created_at as string) ?? undefined,
  }
}
