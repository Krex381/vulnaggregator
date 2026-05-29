import { Cron } from 'croner'
import { config } from '../config.js'
import { getDb } from '../db/client.js'
import { getEnabledFilters, markNotifiedBatch, insertAlertLogBatch } from '../db/queries.js'
import { computeHash } from '../dedup.js'
import { findMatchingFilters } from '../filter.js'
import { sendDiscordNotification } from '../notifier.js'
import type { RawVuln, PollContext, NormalizedVuln, FilterRule } from '../models.js'
import { parseSeverity } from '../models.js'
import type { SourceAdapter, RegisteredSource } from '../adapters/types.js'

const sources: Map<string, RegisteredSource> = new Map()
const cronJobs: Cron[] = []

export function registerSource(adapter: SourceAdapter): void {
  sources.set(adapter.name, { adapter, lastPollAt: null, consecutiveErrors: 0 })
}

export function getAllSources(): Map<string, RegisteredSource> {
  return sources
}

function normalize(v: RawVuln, sourceName: string): NormalizedVuln {
  return {
    cveId: v.cveId ?? '',
    title: v.title || 'Untitled',
    description: v.description || '',
    severity: parseSeverity(v.severity),
    cvssScore: v.cvssScore ?? null,
    vendor: v.vendor || sourceName,
    product: v.product ?? '',
    source: sourceName,
    sourceUrl: v.sourceUrl || '',
    publishedAt: v.publishedAt instanceof Date && !isNaN(v.publishedAt.getTime())
      ? v.publishedAt.toISOString() : String(v.publishedAt ?? ''),
    hash: computeHash(v),
    notified: 0,
  }
}

async function batchInsertAndReturnIds(vulns: NormalizedVuln[]): Promise<NormalizedVuln[]> {
  if (vulns.length === 0) return []
  const db = getDb()

  const batchSize = 100
  const allHashes: string[] = []

  for (let i = 0; i < vulns.length; i += batchSize) {
    const batch = vulns.slice(i, i + batchSize)
    const placeholders = batch.map(() => '(?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)').join(', ')
    const args: (string | number | null)[] = []

    for (const v of batch) {
      args.push(v.cveId, v.title, v.description, v.severity, v.cvssScore, v.vendor, v.product, v.source, v.sourceUrl, v.publishedAt, v.hash)
      allHashes.push(v.hash)
    }

    await db.execute({
      sql: `INSERT OR IGNORE INTO vulnerabilities
        (cve_id, title, description, severity, cvss_score, vendor, product, source, source_url, published_at, hash)
        VALUES ${placeholders}`,
      args,
    })
  }

  if (allHashes.length === 0) return []

  const hashPlaceholders = allHashes.map(() => '?').join(',')
  const result = await db.execute({
    sql: `SELECT id, cve_id, title, description, severity, cvss_score, vendor, product, source, source_url, published_at, hash, notified
      FROM vulnerabilities WHERE hash IN (${hashPlaceholders})`,
    args: allHashes,
  })

  const hashToRow = new Map<string, Record<string, unknown>>()
  for (const row of result.rows) {
    hashToRow.set(row.hash as string, row)
  }

  const inserted: NormalizedVuln[] = []
  for (const hash of allHashes) {
    const row = hashToRow.get(hash)
    if (!row) continue
    inserted.push({
      id: Number(row.id),
      cveId: (row.cve_id as string) ?? '',
      title: (row.title as string) ?? '',
      description: (row.description as string) ?? '',
      severity: (row.severity as string) as NormalizedVuln['severity'],
      cvssScore: (row.cvss_score as number) ?? null,
      vendor: (row.vendor as string) ?? '',
      product: (row.product as string) ?? '',
      source: (row.source as string) ?? '',
      sourceUrl: (row.source_url as string) ?? '',
      publishedAt: (row.published_at as string) ?? '',
      hash: (row.hash as string) ?? '',
      notified: Number(row.notified),
    })
  }
  return inserted
}

async function processVulns(rawVulns: RawVuln[], sourceName: string, filters: FilterRule[]): Promise<void> {
  if (rawVulns.length === 0) return

  const normalized: NormalizedVuln[] = []
  for (const raw of rawVulns) {
    const n = normalize(raw, sourceName)
    if (!n.cveId && !n.title) continue
    normalized.push(n)
  }

  if (normalized.length === 0) return

  const dbVulns = await batchInsertAndReturnIds(normalized)

  const toNotify = dbVulns.filter(v => {
    if (v.notified) return false
    return findMatchingFilters(v, filters).length > 0
  })

  if (toNotify.length === 0) return

  const alertLogs: { vulnId: number; filterId: number | null; delivered: number; error: string | null }[] = []

  for (const v of toNotify) {
    const result = await sendDiscordNotification(v)
    const matching = findMatchingFilters(v, filters)

    for (const f of matching) {
      alertLogs.push({
        vulnId: v.id!,
        filterId: f.id ?? null,
        delivered: result.ok ? 1 : 0,
        error: result.error ?? null,
      })
    }
  }

  const ids = toNotify.map(v => v.id!).filter(id => id != null)
  if (ids.length > 0) {
    await markNotifiedBatch(ids)
  }

  if (alertLogs.length > 0) {
    await insertAlertLogBatch(alertLogs)
  }
}

async function runAdapter(adapter: SourceAdapter, filters: FilterRule[]): Promise<void> {
  const ctx: PollContext = { lastPollAt: sources.get(adapter.name)?.lastPollAt ?? null }

  try {
    const rawVulns = await adapter.poll(ctx)
    sources.get(adapter.name)!.lastPollAt = new Date()
    sources.get(adapter.name)!.consecutiveErrors = 0
    await processVulns(rawVulns, adapter.name, filters)
  } catch (err) {
    const reg = sources.get(adapter.name)!
    reg.consecutiveErrors++
    console.error(`Adapter ${adapter.name} failed:`, err)
  }
}

async function pollGroup(group: 'fast' | 'medium' | 'slow'): Promise<void> {
  const filters = await getEnabledFilters()
  const groupSources = Array.from(sources.values()).filter(s => s.adapter.group === group)
  await Promise.allSettled(groupSources.map(s => runAdapter(s.adapter, filters)))
}

export function startPoller(): void {
  const fast = new Cron(`*/${config.POLL_FAST_INTERVAL_MIN} * * * *`, () => {
    pollGroup('fast').catch(err => console.error('Fast poll error:', err))
  })
  cronJobs.push(fast)

  const medium = new Cron(`*/${config.POLL_MEDIUM_INTERVAL_MIN} * * * *`, () => {
    pollGroup('medium').catch(err => console.error('Medium poll error:', err))
  })
  cronJobs.push(medium)

  if (config.POLL_SLOW_INTERVAL_MIN >= 60) {
    const hours = Math.floor(config.POLL_SLOW_INTERVAL_MIN / 60)
    const minute = config.POLL_SLOW_INTERVAL_MIN % 60
    const slow = new Cron(`${minute} */${hours} * * *`, () => {
      pollGroup('slow').catch(err => console.error('Slow poll error:', err))
    })
    cronJobs.push(slow)
  } else {
    const slow = new Cron(`*/${config.POLL_SLOW_INTERVAL_MIN} * * * *`, () => {
      pollGroup('slow').catch(err => console.error('Slow poll error:', err))
    })
    cronJobs.push(slow)
  }

  pollGroup('fast').catch(err => console.error('Initial fast poll error:', err))
  pollGroup('medium').catch(err => console.error('Initial medium poll error:', err))
  pollGroup('slow').catch(err => console.error('Initial slow poll error:', err))
}

export function stopPoller(): void {
  for (const job of cronJobs) {
    job.stop()
  }
  cronJobs.length = 0
}
