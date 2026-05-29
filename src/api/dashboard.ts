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
  html = 
    `<!DOCTYPE html>
<html lang="en">
  <head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width,initial-scale=1">
    <title>VulnAggregator</title>
    <style>
      * {
        margin: 0;
        padding: 0;
        box-sizing: border-box
      }

      body {
        font-family: ui-monospace, SFMono-Regular, Menlo, monospace;
        background: #0d1117;
        color: #c9d1d9;
        padding: 2rem;
        font-size: 14px
      }

      h1 {
        font-weight: 400;
        font-size: 1.25rem;
        color: #58a6ff;
        margin-bottom: 1.5rem;
        letter-spacing: -.02em
      }

      h2 {
        font-weight: 400;
        font-size: .75rem;
        color: #8b949e;
        text-transform: uppercase;
        letter-spacing: .05em;
        margin-bottom: .5rem
      }

      .grid {
        display: grid;
        grid-template-columns: repeat(auto-fit, minmax(160px, 1fr));
        gap: 1rem;
        margin-bottom: 1.5rem
      }

      .card {
        background: #161b22;
        border: 1px solid #30363d;
        padding: 1rem
      }

      .card .val {
        font-size: 1.5rem;
        color: #f0f6fc;
        font-weight: 600
      }

      .table-wrap {
        overflow-x: auto;
        margin-bottom: 1.5rem
      }

      table {
        width: 100%;
        border-collapse: collapse;
        font-size: .8125rem
      }

      th {
        text-align: left;
        padding: .5rem .75rem;
        border-bottom: 1px solid #30363d;
        color: #8b949e;
        font-weight: 400;
        white-space: nowrap
      }

      td {
        padding: .5rem .75rem;
        border-bottom: 1px solid #21262d
      }

      tr:hover td {
        background: #161b22
      }

      .ok {
        color: #3fb950
      }

      .fail {
        color: #f85149
      }

      a {
        color: #58a6ff;
        text-decoration: none
      }

      .err {
        padding: 2rem;
        color: #f85149;
        border: 1px solid #30363d
      }

      .footer {
        margin-top: 2rem;
        padding-top: 1rem;
        border-top: 1px solid #21262d;
        font-size: .75rem;
        color: #8b949e
      }

      .footer a {
        color: #8b949e
      }

      .footer a:hover {
        color: #58a6ff
      }
    </style>
  </head>
  <body>
    <h1>VulnAggregator</h1>
    <div id="app">
      <div class="grid">
        <div class="card">
          <h2>Vulnerabilities</h2>
          <div class="val" id="total">-</div>
        </div>
        <div class="card">
          <h2>Sources</h2>
          <div class="val" id="sources">-</div>
        </div>
        <div class="card">
          <h2>Uptime</h2>
          <div class="val" id="uptime">-</div>
        </div>
        <div class="card">
          <h2>24h</h2>
          <div class="val" id="last24h">-</div>
        </div>
      </div>
      <div class="table-wrap">
        <h2>Severity</h2>
        <table id="severity"></table>
      </div>
      <div class="table-wrap">
        <h2>Sources</h2>
        <table id="source-table">
          <thead>
            <tr>
              <th>Source</th>
              <th>Status</th>
              <th>Errors</th>
            </tr>
          </thead>
          <tbody></tbody>
        </table>
      </div>
      <div class="footer">developed by <a href="https://github.com/Krex381/vulnaggregator" target="_blank">Krex</a> &mdash; Open Source &mdash; 2026 </div>
    </div>
    <script>
      const BASE = window.location.origin
      Promise.all([
        fetch(BASE + '/health').then(r => r.json()),
        fetch(BASE + '/api/v1/stats').then(r => r.json()),
        fetch(BASE + '/api/v1/sources').then(r => r.json())
      ]).then(([health, stats, sources]) => {
        document.getElementById('total').textContent = stats.total
        document.getElementById('sources').textContent = health.sources.healthy + '/' + health.sources.total
        document.getElementById('uptime').textContent = Math.floor(health.uptime / 3600) + 'h'
        document.getElementById('last24h').textContent = stats.last24h
        const sevTbody = document.getElementById('severity')
        if (stats.bySeverity) {
          sevTbody.innerHTML = ' < tr > < th > Severity < /th> < th > Count < /th> < /tr>'
          Object.entries(stats.bySeverity).forEach(([k, v]) => {
            sevTbody.innerHTML += ' < tr > < td > '+k+' < /td> < td > '+v+' < /td> < /tr>'
          })
        }
        const tbody = document.querySelector('#source-table tbody')
        sources.data.forEach(s => {
          tbody.innerHTML += ' < tr > < td > '+s.name+' < /td> < td class = "'+(s.status==='healthy'?'ok':'fail')+'" > '+s.status+' < /td> < td > '+s.errorCount+' < /td> < /tr>'
        })
      }).catch(e => {
        document.getElementById('app').innerHTML = ' < div class = "err" > '+e.message+' < /div>'
      })
    </script>
  </body>
</html>`
}

export function registerDashboard(app: FastifyInstance): void {
  app.get('/', async (_request, reply) => {
    reply.type('text/html').send(html)
  })
}
