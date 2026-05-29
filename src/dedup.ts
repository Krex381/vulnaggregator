import { createHash } from 'node:crypto'
import type { RawVuln } from './models.js'

export function computeHash(vuln: Pick<RawVuln, 'sourceId' | 'cveId' | 'title'>): string {
  return createHash('sha256')
    .update(`${vuln.sourceId}|${vuln.cveId ?? ''}|${vuln.title}`)
    .digest('hex')
}
