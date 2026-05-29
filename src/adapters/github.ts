import type { SourceAdapter } from './types.js'
import type { RawVuln, PollContext } from '../models.js'

interface GhsaResponse {
  data?: {
    securityAdvisories?: {
      nodes: GhsaNode[]
      pageInfo: { hasNextPage: boolean; endCursor: string | null }
    }
  }
  errors?: { message: string }[]
}

interface GhsaNode {
  ghsaId: string
  summary: string
  description: string
  severity: string
  publishedAt: string
  updatedAt: string
  identifiers: { type: string; value: string }[]
  vulnerabilities: { nodes: { package: { ecosystem: string; name: string } }[] }[]
  references: { url: string }[]
}

const QUERY = `
query($after: String, $since: DateTime) {
  securityAdvisories(first: 100, after: $after, updatedSince: $since, classifications: GENERAL) {
    nodes {
      ghsaId
      summary
      description
      severity
      publishedAt
      updatedAt
      identifiers { type value }
      vulnerabilities(first: 5) { nodes { package { ecosystem name } } }
      references(first: 3) { url }
    }
    pageInfo { hasNextPage endCursor }
  }
}`

export const githubAdapter: SourceAdapter = {
  name: 'GitHub Advisory',
  group: 'fast',

  async poll(ctx: PollContext): Promise<RawVuln[]> {
    const results: RawVuln[] = []
    let cursor: string | null = null
    let hasMore = true

    const since = ctx.lastPollAt
      ? new Date(ctx.lastPollAt.getTime() - 60000).toISOString()
      : new Date(Date.now() - 86400000).toISOString()

    while (hasMore) {
      const ghToken = process.env.GITHUB_TOKEN
      if (!ghToken) {
        console.warn('GitHub Advisory: GITHUB_TOKEN not set, skipping')
        break
      }

      const headers: Record<string, string> = {
        'Content-Type': 'application/json',
        'User-Agent': 'Mozilla/5.0 (X11; Linux x86_64; rv:128.0) Gecko/20100101 Firefox/128.0',
        'Authorization': `Bearer ${ghToken}`,
      }
      const res = await fetch('https://api.github.com/graphql', {
        method: 'POST',
        headers,
        body: JSON.stringify({
          query: QUERY,
          variables: { after: cursor, since },
        }),
      })
      if (!res.ok) throw new Error(`GitHub API returned ${res.status}`)

      const body = await res.json() as GhsaResponse
      if (body.errors) throw new Error(`GraphQL error: ${body.errors[0].message}`)
      if (!body.data?.securityAdvisories) break

      const advisories = body.data.securityAdvisories
      for (const node of advisories.nodes) {
        const cveId = node.identifiers?.find(i => i.type === 'CVE')?.value
        const vulnPkg = node.vulnerabilities?.[0]?.nodes?.[0]?.package
        const product = vulnPkg ? `${vulnPkg.ecosystem}:${vulnPkg.name}` : ''

        results.push({
          sourceId: node.ghsaId,
          cveId,
          title: node.summary || node.ghsaId,
          description: (node.description || node.summary || '').slice(0, 2000),
          severity: (node.severity || 'UNKNOWN') as RawVuln['severity'],
          publishedAt: new Date(node.publishedAt),
          vendor: 'GitHub',
          product,
          sourceUrl: node.references?.[0]?.url ?? `https://github.com/advisories/${node.ghsaId}`,
        })
      }

      hasMore = advisories.pageInfo.hasNextPage
      cursor = advisories.pageInfo.endCursor
    }

    return results
  },
}
