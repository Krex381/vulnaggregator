import type { FastifyInstance } from 'fastify'
import { registerHealth } from './health.js'
import { registerDashboard } from './dashboard.js'
import { registerVulns } from './vulns.js'
import { registerFilters } from './filters.js'
import { registerSources } from './sources.js'
import { registerStats } from './stats.js'
import { authMiddleware, rateLimitMiddleware } from './auth.js'
import { sendDiscordTest } from '../notifier.js'

export function registerRoutes(app: FastifyInstance): void {
  registerHealth(app)
  registerDashboard(app)

  const publicPaths = ['/health', '/', '/api/v1/sources', '/api/v1/stats']
  app.addHook('onRequest', async (request, reply) => {
    if (publicPaths.includes(request.url)) return
    await rateLimitMiddleware(request, reply)
    await authMiddleware(request, reply)
  })

  registerVulns(app)
  registerFilters(app)
  registerSources(app)
  registerStats(app)

  app.post('/api/v1/webhooks/test', async () => {
    const result = await sendDiscordTest()
    if (!result.ok) return { ok: false, error: result.error }
    return { ok: true, message: 'Discord webhook test sent' }
  })
}
