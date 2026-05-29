import 'dotenv/config'
import { z } from 'zod'

const envSchema = z.object({
  TURSO_DB_URL: z.string().url(),
  TURSO_DB_TOKEN: z.string().min(1),
  DISCORD_WEBHOOK_URL: z.string().url(),
  ADMIN_API_KEY: z.string().min(16),
  HOST: z.string().default('127.0.0.1'),
  PORT: z.coerce.number().int().positive().default(8080),
  LOG_LEVEL: z.enum(['fatal', 'error', 'warn', 'info', 'debug', 'trace']).default('info'),
  POLL_FAST_INTERVAL_MIN: z.coerce.number().int().positive().default(15),
  POLL_MEDIUM_INTERVAL_MIN: z.coerce.number().int().positive().default(60),
  POLL_SLOW_INTERVAL_MIN: z.coerce.number().int().positive().default(1440),
})

const parsed = envSchema.safeParse(process.env)
if (!parsed.success) {
  console.error('Invalid environment variables:', parsed.error.flatten().fieldErrors)
  process.exit(1)
}

export const config = parsed.data
