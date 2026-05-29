import * as cheerio from 'cheerio'
import type { SourceAdapter } from './types.js'
import type { RawVuln, PollContext } from '../models.js'

interface ScraperConfig {
  name: string
  url: string
  group: 'fast' | 'medium' | 'slow'
  vendor: string
  itemSelector: string
  titleSelector?: string
  descriptionSelector?: string
  dateSelector?: string
  linkSelector?: string
  cveFromText?: boolean
  severity?: RawVuln['severity']
}

export function createScraperAdapter(config: ScraperConfig): SourceAdapter {
  return {
    name: config.name,
    group: config.group,

    async poll(_ctx: PollContext): Promise<RawVuln[]> {
      const res = await fetch(config.url, {
        headers: {
          'User-Agent': 'Mozilla/5.0 (X11; Linux x86_64; rv:128.0) Gecko/20100101 Firefox/128.0',
          'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
          'Accept-Language': 'en-US,en;q=0.5',
        },
      })
      if (!res.ok) throw new Error(`${config.name} scraper returned ${res.status}`)

      const html = await res.text()
      const $ = cheerio.load(html)
      const results: RawVuln[] = []
      const seen = new Set<string>()

      $(config.itemSelector).each((_, el) => {
        const $el = $(el)
        const title = config.titleSelector
          ? $el.find(config.titleSelector).first().text().trim()
          : $el.text().trim().split('\n')[0].trim()

        const description = config.descriptionSelector
          ? $el.find(config.descriptionSelector).first().text().trim()
          : ''

        const dateText = config.dateSelector
          ? $el.find(config.dateSelector).first().text().trim()
          : ''

        const link = config.linkSelector
          ? $el.find(config.linkSelector).first().attr('href') ?? ''
          : ''

        let fullUrl = config.url
        if (link) {
          try {
            fullUrl = new URL(link, config.url).href
          } catch {
            fullUrl = config.url
          }
        }
        const combined = `${title} ${description}`

        const cveMatch = config.cveFromText !== false
          ? combined.match(/\bCVE-\d{4}-\d{4,7}\b/i)
          : null
        const cveId = cveMatch?.[0]?.toUpperCase()

        const dedupKey = cveId || title || link
        if (!dedupKey || seen.has(dedupKey)) return
        seen.add(dedupKey)

        let publishedAt: Date
        if (dateText) {
          publishedAt = new Date(dateText)
          if (isNaN(publishedAt.getTime())) publishedAt = new Date(0)
        } else {
          publishedAt = new Date(0)
        }

        results.push({
          sourceId: dedupKey,
          cveId,
          title: title.slice(0, 500) || 'Untitled',
          description: description.slice(0, 2000),
          severity: config.severity ?? (cveId ? 'UNKNOWN' : 'MEDIUM'),
          vendor: config.vendor,
          publishedAt,
          sourceUrl: fullUrl,
        })
      })

      return results
    },
  }
}
