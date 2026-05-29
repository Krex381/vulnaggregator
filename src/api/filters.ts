import type { FastifyInstance } from 'fastify'
import { getFilters, createFilter, updateFilter, deleteFilter } from '../db/queries.js'
import type { Severity } from '../models.js'

export function registerFilters(app: FastifyInstance): void {
  app.get('/api/v1/filters', async () => {
    const filters = await getFilters()
    return { data: filters }
  })

  app.post('/api/v1/filters', async (request, reply) => {
    const body = request.body as Record<string, unknown>

    if (!body.name || typeof body.name !== 'string') {
      reply.code(400).send({ error: 'name is required' })
      return
    }

    const id = await createFilter({
      name: body.name,
      severityFilter: Array.isArray(body.severityFilter) ? body.severityFilter as Severity[] : [],
      vendorFilter: Array.isArray(body.vendorFilter) ? body.vendorFilter as string[] : [],
      keywordFilter: Array.isArray(body.keywordFilter) ? body.keywordFilter as string[] : [],
      minCvss: typeof body.minCvss === 'number' ? body.minCvss : null,
      cisaKevOnly: body.cisaKevOnly === true,
      enabled: body.enabled !== false ? 1 : 0,
    })

    reply.code(201).send({ id })
  })

  app.put<{ Params: { id: string } }>('/api/v1/filters/:id', async (request, reply) => {
    const id = parseInt(request.params.id, 10)
    if (isNaN(id)) { reply.code(400).send({ error: 'Invalid ID' }); return }

    const body = request.body as Record<string, unknown>

    const ok = await updateFilter(id, {
      name: typeof body.name === 'string' ? body.name : undefined,
      severityFilter: Array.isArray(body.severityFilter) ? body.severityFilter as Severity[] : undefined,
      vendorFilter: Array.isArray(body.vendorFilter) ? body.vendorFilter as string[] : undefined,
      keywordFilter: Array.isArray(body.keywordFilter) ? body.keywordFilter as string[] : undefined,
      minCvss: typeof body.minCvss === 'number' ? body.minCvss : undefined,
      cisaKevOnly: 'cisaKevOnly' in body ? body.cisaKevOnly === true : undefined,
      enabled: body.enabled === false ? 0 : body.enabled === true ? 1 : undefined,
    })

    if (!ok) { reply.code(404).send({ error: 'Not found' }); return }
    return { ok: true }
  })

  app.delete<{ Params: { id: string } }>('/api/v1/filters/:id', async (request, reply) => {
    const id = parseInt(request.params.id, 10)
    if (isNaN(id)) { reply.code(400).send({ error: 'Invalid ID' }); return }

    const ok = await deleteFilter(id)
    if (!ok) { reply.code(404).send({ error: 'Not found' }); return }
    return { ok: true }
  })
}
