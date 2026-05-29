import type { SourceAdapter } from './types.js'
import type { RawVuln, PollContext } from '../models.js'

const URL = 'https://ubuntu.com/security/notices.json'

export const ubuntuAdapter: SourceAdapter = {
  name: 'Ubuntu',
  group: 'medium',

  async poll(ctx: PollContext): Promise<RawVuln[]> {
    const params = new URLSearchParams({ limit: '20' })
    const res = await fetch(`${URL}?${params}`, {
      headers: { 'User-Agent': 'Mozilla/5.0 (X11; Linux x86_64; rv:128.0) Gecko/20100101 Firefox/128.0' },
    })
    if (!res.ok) throw new Error(`Ubuntu API returned ${res.status}`)

    const data = await res.json() as {
      notices?: {
        id: string
        title: string
        summary: string
        cves: string[]
        published: string
        references: string[]
      }[]
    }

    const results: RawVuln[] = []

    for (const notice of data.notices ?? []) {
      const publishedDate = new Date(notice.published)
      if (ctx.lastPollAt && publishedDate <= ctx.lastPollAt) continue

      const cves = notice.cves?.filter(c => c && c !== '') ?? []
      if (cves.length > 0) {
        for (const cve of cves) {
          results.push({
            sourceId: `${notice.id}-${cve}`,
            cveId: cve,
            title: `${notice.title} - ${cve}`,
            description: notice.summary?.slice(0, 2000) ?? '',
            severity: 'UNKNOWN',
            vendor: 'Canonical',
            product: 'Ubuntu',
            publishedAt: publishedDate,
            sourceUrl: notice.references?.[0] ?? `https://ubuntu.com/security/notices/${notice.id}`,
          })
        }
      } else {
        results.push({
          sourceId: notice.id,
          title: notice.title,
          description: notice.summary?.slice(0, 2000) ?? '',
          severity: 'MEDIUM',
          vendor: 'Canonical',
          product: 'Ubuntu',
          publishedAt: publishedDate,
          sourceUrl: notice.references?.[0] ?? `https://ubuntu.com/security/notices/${notice.id}`,
        })
      }
    }

    return results
  },
}
