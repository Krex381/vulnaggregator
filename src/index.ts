import Fastify, { type FastifyError } from 'fastify'
import { config } from './config.js'
import { ensureSchema } from './db/client.js'
import { registerAllSources } from './adapters/registry.js'
import { startPoller, stopPoller } from './poller/index.js'
import { registerRoutes } from './api/router.js'

async function main() {
  const app = Fastify({ logger: { level: config.LOG_LEVEL } })

  await ensureSchema()

  registerAllSources()

  startPoller()

  registerRoutes(app)

  app.setErrorHandler((error: FastifyError, _request, reply) => {
    app.log.error(error)
    const statusCode = typeof (error as any).statusCode === 'number'
      ? (error as any).statusCode
      : error.statusCode ?? 500
    const message = statusCode >= 500 ? 'Internal Server Error' : error.message
    reply.code(statusCode).send({ error: message })
  })

  try {
    await app.listen({ port: config.PORT, host: config.HOST })
    app.log.info(`Server listening on ${config.HOST}:${config.PORT}`)
  } catch (err) {
    app.log.fatal(err)
    process.exit(1)
  }

  const shutdown = async (signal: string) => {
    app.log.info(`Received ${signal}, shutting down...`)
    stopPoller()
    await app.close()
    process.exit(0)
  }
  process.on('SIGTERM', () => shutdown('SIGTERM'))
  process.on('SIGINT', () => shutdown('SIGINT'))
}

main()
