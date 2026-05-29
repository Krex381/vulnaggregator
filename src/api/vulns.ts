import type { FastifyInstance } from 'fastify'
import { getVulns, getVulnById } from '../db/queries.js'
import type { Severity } from '../models.js'

export function registerVulns(app: FastifyInstance): void {
  app.get('/api/v1/vulns', async (request) => {
    const query = request.query as {
      severity?: string
      vendor?: string
      source?: string
      page?: string
      limit?: string
    }

    const page = Math.max(1, parseInt(query.page ?? '1', 10) || 1)
    const limit = Math.min(100, Math.max(1, parseInt(query.limit ?? '20', 10) || 20))

    const result = await getVulns({
      severity: query.severity as Severity | undefined,
      vendor: query.vendor,
      source: query.source,
      page,
      limit,
    })

    return {
      data: result.rows,
      pagination: {
        page,
        limit,
        total: result.total,
        totalPages: Math.ceil(result.total / limit),
      },
    }
  })

  app.get<{ Params: { id: string } }>('/api/v1/vulns/:id', async (request, reply) => {
    const id = parseInt(request.params.id, 10)
    if (isNaN(id)) {
      reply.code(400).send({ error: 'Invalid ID' })
      return
    }

    const vuln = await getVulnById(id)
    if (!vuln) {
      reply.code(404).send({ error: 'Not found' })
      return
    }

    return { data: vuln }
  })
}
