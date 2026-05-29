import type { FastifyInstance } from 'fastify'
import { config } from '../config.js'
import { readFileSync } from 'node:fs'
import { join, dirname } from 'node:path'
import { fileURLToPath } from 'node:url'

const __dir = dirname(fileURLToPath(import.meta.url))
let html: string
try {
  html = readFileSync(join(__dir, '..', '..', 'public', 'index.html'), 'utf-8')
} catch {
  html = `
<!DOCTYPE html>
<html><head><title>VulnAggregator</title>
<meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<style>
*{margin:0;padding:0;box-sizing:border-box}
body{font-family:system-ui,sans-serif;background:#0f172a;color:#e2e8f0;padding:2rem}
h1{font-size:1.5rem;margin-bottom:1rem;color:#38bdf8}
.card{background:#1e293b;border-radius:.5rem;padding:1rem;margin-bottom:1rem}
.card h2{font-size:1rem;color:#94a3b8;margin-bottom:.5rem}
.grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(280px,1fr));gap:1rem}
.stat{font-size:2rem;font-weight:700;color:#38bdf8}
.badge{display:inline-block;padding:.125rem .5rem;border-radius:9999px;font-size:.75rem;font-weight:600}
.badge.ok{background:#166534;color:#86efac}
.badge.fail{background:#7f1d1d;color:#fca5a5}
table{width:100%;border-collapse:collapse;font-size:.875rem}
th,td{text-align:left;padding:.5rem;border-bottom:1px solid #334155}
th{color:#94a3b8;font-weight:600}
tr:hover{background:#334155}
a{color:#38bdf8;text-decoration:none}
a:hover{text-decoration:underline}
.err{color:#fca5a5}
.loading{text-align:center;padding:2rem;color:#64748b}
</style></head><body>
<h1>🔍 VulnAggregator</h1>
<div id="app" class="loading">Loading...</div>
<script>
const API = window.location.origin
async function get(path) {
  const r = await fetch(API+path)
  if(!r.ok) throw new Error(await r.text())
  return r.json()
}
async function load(){
  try {
    const [health, stats, sources] = await Promise.all([
      get('/health'), get('/api/v1/stats'), get('/api/v1/sources')
    ])
    document.getElementById('app').innerHTML = \`
      <div class="grid">
        <div class="card"><h2>Total Vulnerabilities</h2><div class="stat">\${stats.total}</div></div>
        <div class="card"><h2>Sources</h2><div class="stat">\${health.sources.healthy}/\${health.sources.total}</div></div>
        <div class="card"><h2>Uptime</h2><div class="stat">\${Math.floor(health.uptime/3600)}h</div></div>
        <div class="card"><h2>Last 24h</h2><div class="stat">\${stats.last24h}</div></div>
      </div>
      <div class="card"><h2>Severity Breakdown</h2>
        <table><tr><th>Severity</th><th>Count</th></tr>
        \${Object.entries(stats.bySeverity||{}).map(([k,v]) => '<tr><td>'+k+'</td><td>'+v+'</td></tr>').join('')}
        </table>
      </div>
      <div class="card"><h2>Source Status</h2>
        <table><tr><th>Source</th><th>Status</th><th>Errors</th></tr>
        \${sources.data.map(s => '<tr><td>'+s.name+'</td><td><span class="badge '+(s.status==='healthy'?'ok':'fail')+'">'+s.status+'</span></td><td>'+s.errorCount+'</td></tr>').join('')}
        </table>
      </div>
    \`
  } catch(e) {
    document.getElementById('app').innerHTML = '<div class="err">Error: '+e.message+'</div>'
  }
}
load()
</script></body></html>
  `
}

export function registerDashboard(app: FastifyInstance): void {
  app.get('/', async (_request, reply) => {
    reply.type('text/html').send(html)
  })
}
