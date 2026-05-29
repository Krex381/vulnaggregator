import type { SourceAdapter } from './types.js'
import type { RawVuln, PollContext } from '../models.js'

const URL = 'https://security-tracker.debian.org/tracker/data/json'

export const debianAdapter: SourceAdapter = {
  name: 'Debian',
  group: 'medium',

  async poll(ctx: PollContext): Promise<RawVuln[]> {
    const res = await fetch(URL, {
      headers: { 'User-Agent': 'VulnAggregator/1.0' },
    })
    if (!res.ok) throw new Error(`Debian API returned ${res.status}`)

    const data = await res.json() as Record<string, {
      description?: string
      releases?: Record<string, { status?: string; fixed_version?: string; urgency?: string }>
      scope?: string
    }>

    const results: RawVuln[] = []
    const entries = Object.entries(data).slice(0, 200)

    for (const [cveId, entry] of entries) {
      const desc = entry.description ?? ''
      const severity = entry.releases?.['bookworm']?.urgency?.toUpperCase() as RawVuln['severity'] ?? 'UNKNOWN'

      results.push({
        sourceId: cveId,
        cveId,
        title: cveId,
        description: desc.slice(0, 2000),
        severity: severity || 'UNKNOWN',
        vendor: 'Debian',
        product: 'Linux',
        publishedAt: new Date(0),
        sourceUrl: `https://security-tracker.debian.org/tracker/${cveId}`,
      })
    }

    return results
  },
}
