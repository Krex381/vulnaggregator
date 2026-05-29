import type { SourceAdapter } from './types.js'
import type { RawVuln, PollContext } from '../models.js'

const BASE = 'https://api.msrc.microsoft.com/cvrf/v3.0'

export const msrcAdapter: SourceAdapter = {
  name: 'MSRC',
  group: 'medium',

  async poll(_ctx: PollContext): Promise<RawVuln[]> {
    const results: RawVuln[] = []

    const headers = {
      'User-Agent': 'VulnAggregator/1.0',
      'Accept': 'application/json',
    }

    const listRes = await fetch(`${BASE}/updates`, { headers })
    if (!listRes.ok) throw new Error(`MSRC API returned ${listRes.status}`)
    const data = await listRes.json() as { value?: { ID: string; Title: string; ReleaseDate: string }[] }
    if (!data.value) return results

    const recent = data.value.slice(0, 3)
    const detailResults = await Promise.allSettled(
      recent.map(bulletin =>
        fetch(`${BASE}/cvrf/${bulletin.ID}`, { headers })
          .then(r => r.ok ? r.json() as Promise<any> : null)
      )
    )

    for (let i = 0; i < recent.length; i++) {
      const bulletin = recent[i]
      const detailResult = detailResults[i]
      if (detailResult.status !== 'fulfilled' || !detailResult.value) continue

      const cvrf = detailResult.value
      const vulns: { CVE?: string; Title?: { Value: string }; Notes?: { Value: string }[]; CVSSScoreSets?: { BaseScore: number }[] }[] =
        cvrf.Vulnerability ?? cvrf.vulnerabilities ?? []

      for (const vuln of vulns) {
        const cveId = vuln.CVE ?? ''
        if (!cveId) continue

        results.push({
          sourceId: cveId,
          cveId,
          title: vuln.Title?.Value ?? cveId,
          description: vuln.Notes?.find((n: any) => n.Value)?.Value?.slice(0, 2000) ?? '',
          severity: 'HIGH',
          cvssScore: vuln.CVSSScoreSets?.[0]?.BaseScore,
          vendor: 'Microsoft',
          publishedAt: new Date(bulletin.ReleaseDate),
          sourceUrl: `https://msrc.microsoft.com/update-guide/vulnerability/${cveId}`,
        })
      }
    }

    return results
  },
}
