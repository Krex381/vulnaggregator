import type { FastifyInstance } from 'fastify'
import { getAllSources } from '../poller/index.js'

export function registerSources(app: FastifyInstance): void {
  app.get('/api/v1/sources', async () => {
    const sources = getAllSources()

    const data = Array.from(sources.entries()).map(([name, reg]) => ({
      name,
      group: reg.adapter.group,
      lastPollAt: reg.lastPollAt?.toISOString() ?? null,
      errorCount: reg.consecutiveErrors,
      status: reg.consecutiveErrors > 3 ? 'failing' : reg.consecutiveErrors > 0 ? 'degraded' : 'healthy',
    }))

    return { data }
  })
}
