import type { SourceAdapter } from './types.js'
import type { RawVuln, PollContext } from '../models.js'

const URL = 'https://kubernetes.io/docs/reference/issues-security/official-cve-feed/'

export const kubernetesAdapter: SourceAdapter = {
  name: 'Kubernetes',
  group: 'medium',

  async poll(_ctx: PollContext): Promise<RawVuln[]> {
    const res = await fetch(URL, { headers: { 'User-Agent': 'VulnAggregator/1.0' } })
    if (!res.ok) throw new Error(`K8s feed returned ${res.status}`)

    const html = await res.text()

    const cveRegex = /CVE-\d{4}-\d{4,7}/g
    const cves = html.match(cveRegex) ?? []
    const uniqueCves = [...new Set(cves)]

    const results: RawVuln[] = []
    const seen = new Set<string>()

    const sections = html.split(/<h[23][^>]*>/i)
    for (const section of sections) {
      for (const cve of uniqueCves) {
        if (seen.has(cve)) continue
        if (!section.includes(cve)) continue

        const titleMatch = section.match(/<h[23][^>]*>(.*?)<\/h[23]>/i)
        const descMatch = section.match(/<p>(.*?)<\/p>/i)

        seen.add(cve)
        results.push({
          sourceId: cve,
          cveId: cve,
          title: `Kubernetes ${cve}`,
          description: (descMatch?.[1] ?? titleMatch?.[1] ?? '').replace(/<[^>]+>/g, '').slice(0, 2000),
          severity: 'HIGH',
          vendor: 'Cloud Native Computing Foundation',
          product: 'Kubernetes',
          publishedAt: new Date(0),
          sourceUrl: `https://kubernetes.io/docs/reference/issues-security/official-cve-feed/#${cve.toLowerCase()}`,
        })
      }
    }

    return results
  },
}
