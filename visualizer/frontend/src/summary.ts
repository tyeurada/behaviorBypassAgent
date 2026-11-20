import type { AgentConfig, Iteration } from './types'

export function escapeHtml(value: unknown): string {
  return String(value ?? '')
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;')
}

interface ParsedSummary {
  status: string
  iterations: string
  outcomeLine: string
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  analysisObj: any
  raw: string
}

export function parseSummaryText(raw: string): ParsedSummary {
  const text = String(raw || '')
  const lines = text.split(/\r?\n/)

  const statusLine = lines.find((l) => l.startsWith('Final Status:')) || ''
  const iterationsLine = lines.find((l) => l.startsWith('Total Iterations:')) || ''
  const status = statusLine.replace('Final Status:', '').trim()
  const iterations = iterationsLine.replace('Total Iterations:', '').trim()
  const outcomeLine = lines.find((l) => l.includes('SUCCESS!') || l.includes('FAILED:')) || ''

  let analysisObj = null
  const marker = 'Final Analysis Report:'
  const markerIdx = text.indexOf(marker)
  if (markerIdx >= 0) {
    const jsonCandidate = text.slice(markerIdx + marker.length).trim()
    try {
      analysisObj = JSON.parse(jsonCandidate)
    } catch {
      analysisObj = null
    }
  } else {
    try {
      analysisObj = JSON.parse(text.trim())
    } catch {
      analysisObj = null
    }
  }

  return { status, iterations, outcomeLine, analysisObj, raw: text }
}

function renderSimpleList(items: unknown): string {
  if (!Array.isArray(items) || items.length === 0) {
    return '<p style="color: var(--text-secondary); margin: 0;">None</p>'
  }
  const li = items.map((x) => `<li>${escapeHtml(x)}</li>`).join('')
  return `<ul class="summary-list">${li}</ul>`
}

function renderPersistentRules(items: unknown): string {
  if (!Array.isArray(items) || items.length === 0) {
    return '<p style="color: var(--text-secondary); margin: 0;">None</p>'
  }
  const li = items
    .map((entry) => {
      if (Array.isArray(entry) && entry.length >= 2) {
        return `<li>${escapeHtml(entry[0])} <span style="color: var(--text-secondary)">(x${escapeHtml(entry[1])})</span></li>`
      }
      return `<li>${escapeHtml(entry)}</li>`
    })
    .join('')
  return `<ul class="summary-list">${li}</ul>`
}

function renderActiveRulesContext(activeRules: unknown): string {
  if (!Array.isArray(activeRules) || activeRules.length === 0) {
    return '<p style="color: var(--text-secondary); margin: 0;">None</p>'
  }

  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  return activeRules
    .map((rule: any, idx: number) => {
      const apiCalls: string[] = Array.isArray(rule?.detection_patterns?.api_calls)
        ? rule.detection_patterns.api_calls
        : []
      const filePaths: string[] = Array.isArray(rule?.detection_patterns?.file_paths)
        ? rule.detection_patterns.file_paths
        : []
      const behaviors: string[] = Array.isArray(rule?.detection_patterns?.behaviors)
        ? rule.detection_patterns.behaviors
        : []
      const name = rule?.name || `Rule ${idx + 1}`
      const id = rule?.rule_id || 'n/a'

      const apiPreview = apiCalls.length ? apiCalls.slice(0, 8).join(', ') : 'n/a'
      const pathPreview = filePaths.length ? filePaths.slice(0, 4).join(', ') : 'n/a'
      const behaviorPreview = behaviors.length ? behaviors.join(', ') : 'n/a'
      const query = rule?.query ? `<pre>${escapeHtml(rule.query)}</pre>` : ''

      return `
        <details class="summary-rule">
            <summary>${idx + 1}. ${escapeHtml(name)}</summary>
            <div class="summary-rule-body">
                <div><strong>Rule ID:</strong> <code>${escapeHtml(id)}</code></div>
                <div><strong>Version:</strong> ${escapeHtml(rule?.version || 'n/a')}</div>
                <div><strong>Description:</strong> ${escapeHtml(rule?.description || 'n/a')}</div>
                <div><strong>API Calls:</strong> ${escapeHtml(apiPreview)}</div>
                <div><strong>Paths:</strong> ${escapeHtml(pathPreview)}</div>
                <div><strong>Behaviors:</strong> ${escapeHtml(behaviorPreview)}</div>
                ${query}
            </div>
        </details>
      `
    })
    .join('')
}

function extractIterationInfo(
  iter: Iteration,
  nextIter: Iteration | null,
  isLast: boolean,
  summaryText: string,
): { technique: string; result: string } {
  let technique = 'Unknown'
  let result = 'Unknown'

  if (iter.analysis_response) {
    const match = iter.analysis_response.match(/\*\*Technique\*\*:\s*(.+)/i)
    if (match) technique = match[1].trim()
  }
  if (technique === 'Unknown' && (iter.response_text || iter.response)) {
    const text = iter.response_text || iter.response
    const match = text.match(/### TECHNIQUES_USED\s*([\s\S]*?)(?=###|$)/i)
    if (match) {
      technique = match[1]
        .split('\n')
        .map((l) => l.replace(/^-/, '').trim())
        .filter((l) => l)
        .join(', ')
    }
  }
  if (!technique || technique === 'Unknown') {
    technique = 'Baseline / Initial Attempt'
  }

  if (nextIter && nextIter.analysis_prompt) {
    const promptText = nextIter.analysis_prompt
    if (promptText.includes('COMPILE FAILED:')) {
      result = 'Compile Error'
    } else if (promptText.includes('EXECUTION FAILED:')) {
      result = 'Execution Failed'
      const errMatch =
        promptText.match(/STDERR:\s*([\s\S]+?)(?=\n\s*##|$)/i) ||
        promptText.match(/EXECUTION FAILED:\s*([\s\S]+?)(?=\n\n|$)/i)
      if (errMatch && errMatch[1].trim()) {
        const snippet = errMatch[1].trim().replace(/\n/g, ' ')
        result += `: ${snippet.length > 80 ? snippet.substring(0, 80) + '...' : snippet}`
      }
    } else if (promptText.includes('Triggered Rules:')) {
      const rulesMatch = promptText.match(/Triggered Rules:\s*([\s\S]+?)(?=\n|$)/i)
      if (rulesMatch && rulesMatch[1].trim()) {
        result = 'Detected: ' + rulesMatch[1].trim()
      } else {
        result = 'Detected by EDR'
      }
    } else if (promptText.includes('DETECTED BY RULES:')) {
      const rulesMatch = promptText.match(/DETECTED BY RULES:\s*([\s\S]+?)(?=\n\n|$)/i)
      if (rulesMatch && rulesMatch[1].trim()) {
        result = 'Detected: ' + rulesMatch[1].trim().replace(/\n/g, ', ')
      } else {
        result = 'Detected by EDR'
      }
    } else if (promptText.match(/Status:\s*detected/i)) {
      result = 'Detected by EDR'
    } else {
      result = 'Failed (Unknown Reason)'
    }
  } else if (isLast) {
    if (summaryText && summaryText.includes('SUCCESS!')) {
      result = 'Success (EEDR Bypass Achieved)'
    } else if (summaryText && summaryText.includes('FAILED:')) {
      const failMatch = summaryText.match(/FAILED:\s*([\s\S]+?)(?=\n|$)/i)
      result = failMatch ? `Failed: ${failMatch[1].trim()}` : 'Failed (Final)'
    } else {
      result = 'Final Iteration (Result Unknown)'
    }
  } else {
    result = 'Result Unknown'
  }

  return { technique, result }
}

export function formatSummaryForDisplay(
  rawSummary: string,
  iterations: Iteration[],
  config: AgentConfig,
): string {
  const parsed = parseSummaryText(rawSummary)
  if (!parsed.raw.trim()) {
    return '<p style="color: var(--text-secondary); margin: 0;">No summary available.</p>'
  }

  const cards = `
      <div class="summary-grid">
          <div class="summary-card">
              <div class="summary-label">Final Status</div>
              <div class="summary-value">${escapeHtml(parsed.status || 'n/a')}</div>
          </div>
          <div class="summary-card">
              <div class="summary-label">Total Iterations</div>
              <div class="summary-value">${escapeHtml(parsed.iterations || 'n/a')}</div>
          </div>
          <div class="summary-card">
              <div class="summary-label">Outcome</div>
              <div class="summary-value">${escapeHtml(parsed.outcomeLine || 'n/a')}</div>
          </div>
      </div>
  `

  let iterTableHtml = ''
  if (iterations && iterations.length > 0) {
    iterTableHtml = `
      <div class="summary-section">
          <h3>Iteration History</h3>
          <table style="width: 100%; border-collapse: collapse; margin-top: 10px; font-size: 0.9rem;">
              <thead>
                  <tr style="background: rgba(0, 0, 0, 0.05); text-align: left; border-bottom: 1px solid var(--border);">
                      <th style="padding: 8px;">Iter</th>
                      <th style="padding: 8px;">Technique</th>
                      <th style="padding: 8px;">Result</th>
                  </tr>
              </thead>
              <tbody>
      `

    iterations.forEach((iter, idx) => {
      const isLast = idx === iterations.length - 1
      const nextIter = isLast ? null : iterations[idx + 1]
      const info = extractIterationInfo(iter, nextIter, isLast, rawSummary)

      let resultColor = 'var(--text-secondary)'
      if (info.result.includes('Success')) resultColor = '#10b981'
      else if (info.result.includes('Detected')) resultColor = '#ef4444'
      else if (info.result.includes('Error') || info.result.includes('Failed')) resultColor = '#f59e0b'

      iterTableHtml += `
              <tr style="border-bottom: 1px solid var(--border);">
                  <td style="padding: 8px; color: var(--accent);">${iter.iteration}</td>
                  <td style="padding: 8px; color: var(--text-primary); word-break: break-word;">${escapeHtml(info.technique)}</td>
                  <td style="padding: 8px; color: ${resultColor}; word-break: break-word;">${escapeHtml(info.result)}</td>
              </tr>
          `
    })

    iterTableHtml += `
              </tbody>
          </table>
      </div>
      `
  }

  let configHtml = ''
  if (config && Object.keys(config).length > 0) {
    const ai = config.ai || {}
    const provider = ai.provider || 'unknown'
    const model = ai[provider]?.model || 'unknown'
    const temp = ai[provider]?.temperature || 'unknown'
    const compiler = config.compiler || {}
    const lang = compiler.language || 'unknown'
    const evasion = config.evasion_techniques || {}
    const preferredTech = Array.isArray(evasion.preferred_techniques)
      ? evasion.preferred_techniques.join(', ')
      : 'None'

    configHtml = `
      <div class="summary-section">
          <h3>Configuration</h3>
          <table style="width: 100%; border-collapse: collapse; margin-top: 10px; font-size: 0.9rem;">
              <tbody>
                  <tr style="border-bottom: 1px solid var(--border);">
                      <td style="padding: 8px; color: var(--text-secondary); width: 30%;">AI Provider</td>
                      <td style="padding: 8px; color: var(--text-primary);">${escapeHtml(provider)}</td>
                  </tr>
                  <tr style="border-bottom: 1px solid var(--border);">
                      <td style="padding: 8px; color: var(--text-secondary);">Model</td>
                      <td style="padding: 8px; color: var(--text-primary);">${escapeHtml(model)}</td>
                  </tr>
                  <tr style="border-bottom: 1px solid var(--border);">
                      <td style="padding: 8px; color: var(--text-secondary);">Temperature</td>
                      <td style="padding: 8px; color: var(--text-primary);">${escapeHtml(String(temp))}</td>
                  </tr>
                  <tr style="border-bottom: 1px solid var(--border);">
                      <td style="padding: 8px; color: var(--text-secondary);">Target Language</td>
                      <td style="padding: 8px; color: var(--text-primary);">${escapeHtml(lang)}</td>
                  </tr>
                  <tr style="border-bottom: 1px solid var(--border);">
                      <td style="padding: 8px; color: var(--text-secondary);">Preferred Evasion Techniques</td>
                      <td style="padding: 8px; color: var(--text-primary);">${escapeHtml(preferredTech)}</td>
                  </tr>
              </tbody>
          </table>
      </div>
      `
  }

  if (!parsed.analysisObj || typeof parsed.analysisObj !== 'object') {
    return (
      cards +
      configHtml +
      iterTableHtml +
      `<div class="summary-section"><h3>Raw Summary</h3><pre>${escapeHtml(parsed.raw)}</pre></div>`
    )
  }

  const report = parsed.analysisObj
  const sections = `
      <div class="summary-section">
          <h3>Solved Rules (${Array.isArray(report.solved_rules) ? report.solved_rules.length : 0})</h3>
          ${renderSimpleList(report.solved_rules)}
      </div>
      <div class="summary-section">
          <h3>Persistent Rules (${Array.isArray(report.persistent_rules) ? report.persistent_rules.length : 0})</h3>
          ${renderPersistentRules(report.persistent_rules)}
      </div>
      <div class="summary-section">
          <h3>New Rules (${Array.isArray(report.new_rules) ? report.new_rules.length : 0})</h3>
          ${renderSimpleList(report.new_rules)}
      </div>
      <div class="summary-section">
          <h3>Flags</h3>
          <div><strong>Last Failure Reason:</strong> ${escapeHtml(report.last_failure_reason ?? 'n/a')}</div>
          <div><strong>Generic Malware Alert:</strong> ${escapeHtml(report.generic_malware_alert ?? 'n/a')}</div>
          <div><strong>Generic Malware Rule:</strong> ${escapeHtml(report.generic_malware_alert_rule_name ?? 'n/a')}</div>
      </div>
      <div class="summary-section">
          <h3>Active Rules Context (${Array.isArray(report.active_rules_context) ? report.active_rules_context.length : 0})</h3>
          ${renderActiveRulesContext(report.active_rules_context)}
      </div>
  `

  return cards + configHtml + iterTableHtml + sections
}
