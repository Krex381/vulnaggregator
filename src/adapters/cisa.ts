import type { SourceAdapter } from './types.js'
import type { RawVuln, PollContext } from '../models.js'

interface CisaKevEntry {
  cveID: string
  vendorProject: string
  product: string
  vulnerabilityName: string
  dateAdded: string
  shortDescription: string
  requiredAction: string
  dueDate: string
  knownRansomwareCampaignUse: string
  notes: string
  cwes: string[]
}

const URL = 'https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json'

export const cisaAdapter: SourceAdapter = {
  name: 'CISA KEV',
  group: 'fast',

  async poll(ctx: PollContext): Promise<RawVuln[]> {
    const response = await fetch(URL, { headers: { 'User-Agent': 'VulnAggregator/1.0' } })
    if (!response.ok) throw new Error(`CISA KEV returned ${response.status}`)

    const data = await response.json() as { vulnerabilities: CisaKevEntry[] }
    const results: RawVuln[] = []

    for (const entry of data.vulnerabilities) {
      const added = new Date(entry.dateAdded)
      if (ctx.lastPollAt && added <= ctx.lastPollAt) continue

      results.push({
        sourceId: entry.cveID,
        cveId: entry.cveID,
        title: entry.vulnerabilityName || entry.cveID,
        description: entry.shortDescription?.slice(0, 2000) ?? '',
        severity: 'CRITICAL',
        cvssScore: undefined,
        vendor: entry.vendorProject || 'NVD',
        product: entry.product ?? '',
        publishedAt: added,
        sourceUrl: `https://www.cisa.gov/known-exploited-vulnerabilities-catalog?search_api_fulltext=${entry.cveID}`,
      })
    }

    return results
  },
}
