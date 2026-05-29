import { timingSafeEqual } from 'node:crypto'
import type { FastifyRequest, FastifyReply } from 'fastify'
import { config } from '../config.js'

const buckets = new Map<string, { count: number; resetAt: number }>()
const RATE_LIMIT = 60
const RATE_WINDOW_MS = 60000
const MAX_BUCKETS = 10000

function ipFromRequest(request: FastifyRequest): string {
  return (request.headers['x-forwarded-for'] as string)?.split(',')[0]?.trim()
    || request.ip
    || 'unknown'
}

export async function rateLimitMiddleware(request: FastifyRequest, reply: FastifyReply): Promise<void> {
  const key = ipFromRequest(request)
  const now = Date.now()

  if (!buckets.has(key) && buckets.size >= MAX_BUCKETS) {
    const cutoff = now - RATE_WINDOW_MS
    for (const [k, b] of buckets) {
      if (now > b.resetAt) buckets.delete(k)
    }
  }

  let bucket = buckets.get(key)
  if (!bucket || now > bucket.resetAt) {
    bucket = { count: 0, resetAt: now + RATE_WINDOW_MS }
    buckets.set(key, bucket)
  }

  bucket.count++
  if (bucket.count > RATE_LIMIT) {
    const err = new Error('Too Many Requests') as Error & { statusCode: number }
    err.statusCode = 429
    throw err
  }
}

setInterval(() => {
  const now = Date.now()
  for (const [key, bucket] of buckets) {
    if (now > bucket.resetAt) buckets.delete(key)
  }
}, 60000)

export async function authMiddleware(request: FastifyRequest, _reply: FastifyReply): Promise<void> {
  const key = request.headers['x-api-key'] as string | undefined
  if (!key) {
    const err = new Error('Unauthorized') as Error & { statusCode: number }
    err.statusCode = 401
    throw err
  }

  const expected = config.ADMIN_API_KEY
  if (key.length !== expected.length) {
    const err = new Error('Unauthorized') as Error & { statusCode: number }
    err.statusCode = 401
    throw err
  }

  const keyBuf = Buffer.from(key)
  const expectedBuf = Buffer.from(expected)
  if (!timingSafeEqual(keyBuf, expectedBuf)) {
    const err = new Error('Unauthorized') as Error & { statusCode: number }
    err.statusCode = 401
    throw err
  }
}
