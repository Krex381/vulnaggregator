import type { SourceAdapter } from './types.js'
import type { RawVuln, PollContext } from '../models.js'

interface RssSourceConfig {
  name: string
  url: string
  group: 'fast' | 'medium' | 'slow'
  vendor: string
  cveRegex?: RegExp
  titlePrefix?: string
  severity?: RawVuln['severity']
  parseDescription?: (text: string) => string
}

export function createRssAdapter(config: RssSourceConfig): SourceAdapter {
  return {
    name: config.name,
    group: config.group,

    async poll(_ctx: PollContext): Promise<RawVuln[]> {
      const response = await fetch(config.url, {
        headers: {
          'User-Agent': 'Mozilla/5.0 (X11; Linux x86_64; rv:128.0) Gecko/20100101 Firefox/128.0',
          'Accept': 'application/rss+xml,application/xml;q=0.9,*/*;q=0.8',
        },
      })
      if (!response.ok) {
        throw new Error(`${config.name} RSS returned ${response.status}`)
      }

      const xml = await response.text()
      const entries = parseRssXml(xml, config)

      return entries
    },
  }
}

interface RssItem {
  title?: string
  link?: string
  description?: string
  pubDate?: string
  guid?: string
  category?: string[]
}

function parseRssXml(xml: string, config: RssSourceConfig): RawVuln[] {
  const results: RawVuln[] = []
  const seen = new Set<string>()

  const items: RssItem[] = []

  const hasItems = /<item>[\s\S]*?<\/item>/i.test(xml)
  const regex = hasItems ? /<item>[\s\S]*?<\/item>/gi : /<entry>[\s\S]*?<\/entry>/gi

  let match: RegExpExecArray | null
  while ((match = regex.exec(xml)) !== null) {
    const block = match[0]
    const extract = (tag: string): string | undefined => {
      const m = block.match(new RegExp(`<(?:\\w+:)?${tag}[^>]*>(.*?)<\\/(?:\\w+:)?${tag}>`, 'is'))
      return m ? m[1].trim() : undefined
    }
    const extractCats = (): string[] => {
      const cats: string[] = []
      const catRe = /<category[^>]*>(.*?)<\/category>/gi
      let cm: RegExpExecArray | null
      while ((cm = catRe.exec(block)) !== null) cats.push(cm[1].trim())
      return cats
    }

    items.push({
      title: extract('title'),
      link: extract('link'),
      description: extract('description'),
      pubDate: extract('pubDate') || extract('published') || extract('updated'),
      guid: extract('guid') || extract('id'),
      category: extractCats(),
    })
  }

  for (const item of items) {
    if (!item.title) continue
    const dedupKey = item.guid || item.link || item.title

    if (seen.has(dedupKey)) continue
    seen.add(dedupKey)

    let cveId: string | undefined
    const combinedText = `${item.title} ${item.description ?? ''} ${item.category?.join(' ') ?? ''}`
    const cveMatch = combinedText.match(/\bCVE-\d{4}-\d{4,7}\b/i)
    if (cveMatch) cveId = cveMatch[0].toUpperCase()

    const title = item.title?.replace(/<[^>]+>/g, '').trim() ?? ''
    const description = item.description?.replace(/<[^>]+>/g, '').trim() ?? ''

    if (!cveId && !config.cveRegex?.test(title)) {
      if (config.severity !== 'CRITICAL' && config.severity !== 'HIGH') continue
    }

    let pubDate: Date
    if (item.pubDate) {
      pubDate = new Date(item.pubDate)
      if (isNaN(pubDate.getTime())) pubDate = new Date()
    } else {
      pubDate = new Date()
    }

    results.push({
      sourceId: dedupKey,
      cveId,
      title: title.slice(0, 500),
      description: description.slice(0, 2000),
      severity: config.severity ?? (cveId ? 'UNKNOWN' : 'MEDIUM'),
      vendor: config.vendor,
      publishedAt: pubDate,
      sourceUrl: item.link ?? '',
    })
  }

  return results
}
