import type { SourceAdapter } from './types.js'
import type { RawVuln, PollContext } from '../models.js'

const TOKEN_URL = 'https://id.cisco.com/oauth2/default/v1/token'
const API_URL = 'https://api.cisco.com/security/advisories/v2/advisories/cve'
const FALLBACK_URL = 'https://sec.cloudapps.cisco.com/security/center/rss.x?i=44'

export const ciscoAdapter: SourceAdapter = {
  name: 'Cisco',
  group: 'medium',

  async poll(_ctx: PollContext): Promise<RawVuln[]> {
    const clientId = process.env.CISCO_CLIENT_ID
    const clientSecret = process.env.CISCO_CLIENT_SECRET
    let token: string | undefined

    if (clientId && clientSecret) {
      const tokenRes = await fetch(TOKEN_URL, {
        method: 'POST',
        headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
        body: new URLSearchParams({
          grant_type: 'client_credentials',
          client_id: clientId,
          client_secret: clientSecret,
        }),
      })
      if (tokenRes.ok) {
        const tokenData = await tokenRes.json() as { access_token?: string }
        token = tokenData.access_token
      }
    }

    const headers: Record<string, string> = { 'User-Agent': 'VulnAggregator/1.0' }
    if (token) headers['Authorization'] = `Bearer ${token}`

    if (token) {
      const res = await fetch(`${API_URL}/latest/10`, { headers })
      if (res.ok) {
        const data = await res.json() as {
          advisories?: {
            advisoryId?: string; cves?: string[]; title?: string
            sirtSummary?: string; cvssBaseScore?: string
            publishedDateTime?: string; advisoryUrl?: string; firstPublished?: string
          }[]
        }

        return (data.advisories ?? []).map(adv => ({
          sourceId: adv.advisoryId ?? adv.cves?.[0] ?? '',
          cveId: adv.cves?.[0],
          title: adv.title ?? '',
          description: (adv.sirtSummary ?? '').slice(0, 2000),
          severity: 'HIGH' as RawVuln['severity'],
          cvssScore: adv.cvssBaseScore ? (() => { const s = parseFloat(adv.cvssBaseScore); return isNaN(s) ? undefined : s })() : undefined,
          vendor: 'Cisco',
          publishedAt: new Date(adv.publishedDateTime ?? adv.firstPublished ?? Date.now()),
          sourceUrl: adv.advisoryUrl ?? '',
        }))
      }
    }

    const fallbackRes = await fetch(FALLBACK_URL, {
      headers: { 'User-Agent': 'Mozilla/5.0 (compatible; VulnAggregator/1.0)' },
    })
    if (!fallbackRes.ok) throw new Error(`Cisco RSS returned ${fallbackRes.status}`)

    const xml = await fallbackRes.text()
    const results: RawVuln[] = []
    const itemRegex = /<item>[\s\S]*?<\/item>/gi
    let match: RegExpExecArray | null

    while ((match = itemRegex.exec(xml)) !== null) {
      const block = match[0]
      const extract = (tag: string): string | undefined => {
        const m = block.match(new RegExp(`<${tag}[^>]*>(.*?)<\\/${tag}>`, 'is'))
        return m ? m[1].trim() : undefined
      }

      const title = extract('title') ?? ''
      const description = extract('description') ?? ''
      const link = extract('link') ?? ''
      const pubDate = extract('pubDate') ?? ''

      const cveMatch = `${title} ${description}`.match(/\bCVE-\d{4}-\d{4,7}\b/i)
      const cveId = cveMatch?.[0]?.toUpperCase()

      results.push({
        sourceId: link || title,
        cveId,
        title: title.replace(/<[^>]+>/g, '').slice(0, 500),
        description: description.replace(/<[^>]+>/g, '').slice(0, 2000),
        severity: 'HIGH',
        vendor: 'Cisco',
        publishedAt: pubDate ? new Date(pubDate) : new Date(),
        sourceUrl: link,
      })
    }

    return results
  },
}
