import type { RawVuln, PollContext } from '../models.js'

export interface SourceAdapter {
  name: string
  group: 'fast' | 'medium' | 'slow'
  poll(ctx: PollContext): Promise<RawVuln[]>
}

export interface RegisteredSource {
  adapter: SourceAdapter
  lastPollAt: Date | null
  consecutiveErrors: number
}
