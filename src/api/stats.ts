import type { FastifyInstance } from 'fastify'
import { getStats } from '../db/queries.js'

export function registerStats(app: FastifyInstance): void {
  app.get('/api/v1/stats', async () => {
    return await getStats()
  })
}
