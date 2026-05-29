import type { SourceAdapter } from './types.js'
import type { RawVuln, PollContext } from '../models.js'

const BASE = 'https://kb.cert.org/vuls/api'

export const certAdapter: SourceAdapter = {
  name: 'CERT/CC',
  group: 'fast',

  async poll(_ctx: PollContext): Promise<RawVuln[]> {
    const res = await fetch(`${BASE}/notes/`, {
      headers: { 'User-Agent': 'VulnAggregator/1.0' },
    })
    if (!res.ok) throw new Error(`CERT/CC returned ${res.status}`)

    const data = await res.json() as {
      results?: {
        idnumber: string
        name?: string
        public: boolean
        dateadded: string
        dateupdated: string
      }[]
    }

    const results: RawVuln[] = []

    for (const note of data.results ?? []) {
      if (!note.public) continue

      const id = note.idnumber
      const detailRes = await fetch(`${BASE}/${id}/`, {
        headers: { 'User-Agent': 'VulnAggregator/1.0' },
      })
      if (!detailRes.ok) continue

      const detail = await detailRes.json() as {
        vuid: string
        name?: string
        keywords?: string
        dateadded?: string
        dateupdated?: string
        url?: string
      }

      const title = detail.name ?? note.name ?? ''
      const description = detail.keywords ?? ''
      const cveMatch = `${title} ${description}`.match(/\bCVE-\d{4}-\d{4,7}\b/i)
      const cveId = cveMatch?.[0]?.toUpperCase()

      const published = detail.dateadded ?? note.dateadded ?? ''

      results.push({
        sourceId: detail.vuid || id,
        cveId,
        title: title || cveId || '',
        description: description.replace(/<[^>]+>/g, '').slice(0, 2000),
        severity: 'HIGH',
        vendor: 'CERT/CC',
        publishedAt: published ? new Date(published) : new Date(0),
        sourceUrl: detail.url || `https://kb.cert.org/vuls/id/${id}`,
      })
    }

    return results
  },
}
