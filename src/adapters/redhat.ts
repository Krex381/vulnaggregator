import type { SourceAdapter } from './types.js'
import type { RawVuln, PollContext } from '../models.js'

const URL = 'https://access.redhat.com/hydra/rest/securitydata/cve.json'

export const redhatAdapter: SourceAdapter = {
  name: 'Red Hat',
  group: 'medium',

  async poll(ctx: PollContext): Promise<RawVuln[]> {
    const params = new URLSearchParams({ per_page: '100' })
    if (ctx.lastPollAt) {
      const since = new Date(ctx.lastPollAt.getTime() - 3600000)
      params.set('after', since.toISOString().split('T')[0])
    }

    const res = await fetch(`${URL}?${params}`, {
      headers: { 'User-Agent': 'VulnAggregator/1.0' },
    })
    if (!res.ok) throw new Error(`Red Hat API returned ${res.status}`)

    const data = await res.json() as {
      CVE?: string
      severity?: string
      bugzilla_description?: string
      resource_url?: string
      public_date?: string
      package_state?: { product_name?: string }[]
      cvss3_score?: string
      cvss2_score?: string
    }[]

    return data.map(item => ({
      sourceId: item.CVE ?? '',
      cveId: item.CVE,
      title: item.CVE ?? 'Red Hat Advisory',
      description: (item.bugzilla_description ?? '').slice(0, 2000),
      severity: (item.severity ?? 'UNKNOWN') as RawVuln['severity'],
      cvssScore: item.cvss3_score ? parseFloat(item.cvss3_score) : item.cvss2_score ? parseFloat(item.cvss2_score) : undefined,
      vendor: 'Red Hat',
      product: item.package_state?.[0]?.product_name ?? '',
      publishedAt: new Date(item.public_date ?? Date.now()),
      sourceUrl: item.resource_url ?? `https://access.redhat.com/security/cve/${item.CVE}`,
    }))
  },
}
