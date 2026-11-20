import type { AgentConfig, Iteration } from '../types'
import { formatSummaryForDisplay } from '../summary'
import { CopyButton } from './CopyButton'

interface Props {
  summary: string
  iterations: Iteration[]
  config: AgentConfig
}

export function SummaryView({ summary, iterations, config }: Props) {
  return (
    <div id="phaseSummary" className="panel" style={{ flex: 1, minHeight: 0 }}>
      <div className="panel-header" style={{ color: '#d97706', borderBottom: '1px solid #d97706' }}>
        <span>FINAL SUMMARY</span>
        <CopyButton text={summary} />
      </div>
      <div className="panel-content">
        <div
          className="markdown-body"
          dangerouslySetInnerHTML={{ __html: formatSummaryForDisplay(summary, iterations, config) }}
        />
      </div>
    </div>
  )
}
