import type { FastifyInstance } from 'fastify'
import { getAllSources } from '../poller/index.js'

export function registerHealth(app: FastifyInstance): void {
  app.get('/health', async () => {
    const sources = getAllSources()
    let healthy = 0
    let failing = 0
    for (const [, s] of sources) {
      if (s.consecutiveErrors === 0) healthy++
      else failing++
    }

    return {
      status: 'ok',
      uptime: process.uptime(),
      sources: { total: sources.size, healthy, failing },
      version: '1.0.0',
    }
  })
}
