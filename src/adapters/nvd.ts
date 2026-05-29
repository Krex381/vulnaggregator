import type { SourceAdapter } from './types.js'
import type { RawVuln, PollContext } from '../models.js'

interface NvdVuln {
  id: string
  sourceIdentifier: string
  published: string
  lastModified: string
  vulnStatus: string
  descriptions: { lang: string; value: string }[]
  metrics?: {
    cvssMetricV31?: { cvssData: { baseScore: number; baseSeverity: string } }[]
    cvssMetricV30?: { cvssData: { baseScore: number; baseSeverity: string } }[]
    cvssMetricV2?: { cvssData: { baseScore: number; baseSeverity: string } }[]
  }
  references: { url: string }[]
  weaknesses: { description: { value: string }[] }[]
}

const BASE = 'https://services.nvd.nist.gov/rest/json/cves/2.0'

function delay(ms: number): Promise<void> {
  return new Promise(r => setTimeout(r, ms))
}

export const nvdAdapter: SourceAdapter = {
  name: 'NVD',
  group: 'fast',

  async poll(ctx: PollContext): Promise<RawVuln[]> {
    const results: RawVuln[] = []
    const resultsPerPage = 2000

    const params = new URLSearchParams({
      resultsPerPage: String(resultsPerPage),
      startIndex: '0',
    })

    if (ctx.lastPollAt) {
      const startDate = new Date(ctx.lastPollAt.getTime() - 60000).toISOString()
      const endDate = new Date().toISOString()
      params.set('lastModStartDate', startDate)
      params.set('lastModEndDate', endDate)
    }

    let totalResults = Infinity
    let fetched = 0

    let rateLimitRetries = 0
    const maxRateLimitRetries = 5

    while (fetched < totalResults) {
      params.set('startIndex', String(fetched))

      const response = await fetch(`${BASE}?${params}`, {
        headers: { 'User-Agent': 'VulnAggregator/1.0' },
      })

      if (response.status === 403 || response.status === 429) {
        rateLimitRetries++
        if (rateLimitRetries > maxRateLimitRetries) {
          throw new Error(`NVD API rate limited after ${maxRateLimitRetries} retries`)
        }
        await delay(6000)
        continue
      }

      if (!response.ok) {
        throw new Error(`NVD API returned ${response.status}`)
      }

      const data = await response.json() as {
        totalResults?: number
        vulnerabilities?: { cve: NvdVuln }[]
        resultsPerPage?: number
      }

      totalResults = data.totalResults ?? 0
      const vulns = data.vulnerabilities ?? []
      const prevFetched = fetched
      fetched += data.resultsPerPage ?? vulns.length
      if (fetched === prevFetched) break

      for (const item of vulns) {
        const cve = item.cve
        const desc = cve.descriptions?.find(d => d.lang === 'en')?.value ?? ''

        let cvssScore: number | undefined
        let severity = 'UNKNOWN'
        if (cve.metrics?.cvssMetricV31?.[0]) {
          cvssScore = cve.metrics.cvssMetricV31[0].cvssData.baseScore
          severity = cve.metrics.cvssMetricV31[0].cvssData.baseSeverity
        } else if (cve.metrics?.cvssMetricV30?.[0]) {
          cvssScore = cve.metrics.cvssMetricV30[0].cvssData.baseScore
          severity = cve.metrics.cvssMetricV30[0].cvssData.baseSeverity
        } else if (cve.metrics?.cvssMetricV2?.[0]) {
          cvssScore = cve.metrics.cvssMetricV2[0].cvssData.baseScore
          severity = cve.metrics.cvssMetricV2[0].cvssData.baseSeverity
        }

        const refUrl = cve.references?.[0]?.url ?? `https://nvd.nist.gov/vuln/detail/${cve.id}`
        const vendor = cve.weaknesses?.[0]?.description?.[0]?.value ?? ''

        results.push({
          sourceId: cve.id,
          cveId: cve.id,
          title: cve.id,
          description: desc.slice(0, 2000),
          severity: severity as RawVuln['severity'],
          cvssScore,
          vendor: vendor || 'NVD',
          publishedAt: new Date(cve.published),
          sourceUrl: refUrl,
        })
      }

      if (fetched < totalResults) {
        await delay(6000)
      }
    }

    return results
  },
}
