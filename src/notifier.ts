import { config } from './config.js'
import { severityColor, severityEmoji } from './models.js'
import type { NormalizedVuln } from './models.js'

interface DiscordEmbed {
  title: string
  description: string
  color: number
  fields: { name: string; value: string; inline?: boolean }[]
  timestamp: string
  footer?: { text: string }
}

export async function sendDiscordNotification(vuln: NormalizedVuln): Promise<{ ok: boolean; error?: string }> {
  const emoji = severityEmoji(vuln.severity)
  const embed: DiscordEmbed = {
    title: `${emoji} ${vuln.cveId || 'Security Advisory'}: ${vuln.title.slice(0, 200)}`,
    description: vuln.description.slice(0, 400) || 'No description available.',
    color: severityColor(vuln.severity),
    fields: [
      { name: 'Severity', value: vuln.severity, inline: true },
      { name: 'CVSS', value: vuln.cvssScore?.toFixed(1) ?? 'N/A', inline: true },
      { name: 'Vendor', value: vuln.vendor || 'N/A', inline: true },
      { name: 'Source', value: vuln.source, inline: true },
      { name: 'Product', value: vuln.product || 'N/A', inline: true },
      { name: 'Link', value: vuln.sourceUrl || 'N/A' },
    ],
    timestamp: vuln.publishedAt,
    footer: { text: 'Vuln Aggregator' },
  }

  try {
    const res = await fetch(config.DISCORD_WEBHOOK_URL, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ embeds: [embed] }),
    })
    if (!res.ok) {
      const text = await res.text().catch(() => 'unknown')
      return { ok: false, error: `Discord returned ${res.status}: ${text}` }
    }
    return { ok: true }
  } catch (err) {
    return { ok: false, error: String(err) }
  }
}

export async function sendDiscordTest(): Promise<{ ok: boolean; error?: string }> {
  try {
    const res = await fetch(config.DISCORD_WEBHOOK_URL, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        content: '\u2705 **Vuln Aggregator** — Discord webhook is working!',
      }),
    })
    if (!res.ok) {
      const text = await res.text().catch(() => 'unknown')
      return { ok: false, error: `Discord returned ${res.status}: ${text}` }
    }
    return { ok: true }
  } catch (err) {
    return { ok: false, error: String(err) }
  }
}
