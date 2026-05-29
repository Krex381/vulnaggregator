export type Severity = 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' | 'NONE' | 'UNKNOWN'

export interface PollContext {
  lastPollAt: Date | null
}

export interface RawVuln {
  sourceId: string
  cveId?: string
  title: string
  description: string
  severity: Severity
  cvssScore?: number
  vendor: string
  product?: string
  publishedAt: Date
  sourceUrl: string
}

export interface NormalizedVuln {
  id?: number
  cveId: string
  title: string
  description: string
  severity: Severity
  cvssScore: number | null
  vendor: string
  product: string
  source: string
  sourceUrl: string
  publishedAt: string
  hash: string
  notified: number
  createdAt?: string
}

export interface FilterRule {
  id?: number
  name: string
  severityFilter: Severity[]
  vendorFilter: string[]
  keywordFilter: string[]
  minCvss: number | null
  cisaKevOnly: boolean
  enabled: number
}

export interface AlertLog {
  id?: number
  vulnId: number
  filterId: number | null
  delivered: number
  error: string | null
  attemptedAt: string
}

export interface HealthStatus {
  status: string
  uptime: number
  sources: { total: number; healthy: number; failing: number }
  version: string
}

export interface StatsResponse {
  total: number
  bySeverity: Record<string, number>
  bySource: Record<string, number>
  last24h: number
  notified: number
  pending: number
}

export const SEVERITY_ORDER: Severity[] = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'NONE', 'UNKNOWN']

export function severityWeight(s: Severity): number {
  const map: Record<Severity, number> = { CRITICAL: 5, HIGH: 4, MEDIUM: 3, LOW: 2, NONE: 1, UNKNOWN: 0 }
  return map[s] ?? 0
}

export function parseSeverity(s: string): Severity {
  const u = s.toUpperCase()
  if (SEVERITY_ORDER.includes(u as Severity)) return u as Severity
  return 'UNKNOWN'
}

export function severityColor(s: Severity): number {
  const map: Record<Severity, number> = {
    CRITICAL: 0xDC2626, HIGH: 0xEA580C, MEDIUM: 0xCA8A04, LOW: 0x16A34A, NONE: 0x6B7280, UNKNOWN: 0x9CA3AF
  }
  return map[s] ?? 0x9CA3AF
}

export function severityEmoji(s: Severity): string {
  const map: Record<Severity, string> = {
    CRITICAL: '\u{1F6A8}', HIGH: '\u{26A1}', MEDIUM: '\u{26D4}', LOW: '\u{2139}', NONE: '\u{2705}', UNKNOWN: '\u{2753}'
  }
  return map[s] ?? ''
}
