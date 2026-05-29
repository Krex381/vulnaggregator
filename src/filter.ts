import type { NormalizedVuln, FilterRule } from './models.js'
import { severityWeight } from './models.js'

export function matchesFilter(vuln: NormalizedVuln, filter: FilterRule): boolean {
  if (!filter.enabled) return false

  if (filter.cisaKevOnly && vuln.source !== 'CISA KEV') return false

  if (filter.minCvss !== null) {
    const score = vuln.cvssScore ?? 0
    if (score < filter.minCvss) return false
  }

  if (filter.severityFilter.length > 0) {
    if (!filter.severityFilter.includes(vuln.severity)) return false
  }

  if (filter.vendorFilter.length > 0) {
    const vl = vuln.vendor.toLowerCase()
    if (!filter.vendorFilter.some(v => vl.includes(v.toLowerCase()))) return false
  }

  if (filter.keywordFilter.length > 0) {
    const text = `${vuln.title} ${vuln.description}`.toLowerCase()
    if (!filter.keywordFilter.some(k => text.includes(k.toLowerCase()))) return false
  }

  return true
}

export function findMatchingFilters(vuln: NormalizedVuln, filters: FilterRule[]): FilterRule[] {
  return filters.filter(f => matchesFilter(vuln, f))
}

export function sortBySeverity(vulns: NormalizedVuln[]): NormalizedVuln[] {
  return [...vulns].sort((a, b) => severityWeight(b.severity) - severityWeight(a.severity))
}
