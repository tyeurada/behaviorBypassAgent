import { useEffect, useRef } from 'react'
import type { Iteration } from '../types'
import { renderAnalysisMarkdown, renderMarkdown } from '../markdown'
import { CopyButton } from './CopyButton'

// Wrap markdown-rendered <pre> code blocks and rule-logic blocks in
// collapsible <details> elements (ported from index.html).
function applyCollapsibleCode(root: HTMLElement | null) {
  if (!root) return
  const containers = root.querySelectorAll('.markdown-body')
  containers.forEach((container) => {
    const preElements = container.querySelectorAll('pre')
    preElements.forEach((pre) => {
      const parent = pre.parentNode as HTMLElement | null
      if (!parent) return
      if (parent.classList.contains('summary-rule-body') || parent.classList.contains('code-block-wrapper')) return

      let isCodeBlock = false
      const isRuleLogic = pre.classList.contains('rule-logic')
      let codeLabel = 'Code / Data Block'

      const codeEl = pre.querySelector('code')
      if (codeEl && codeEl.className && codeEl.className.match(/language-(\w+)/)) {
        isCodeBlock = true
        const langMatch = codeEl.className.match(/language-(\w+)/)
        codeLabel = `Code Block (${langMatch![1]})`
      }
      if (isRuleLogic) {
        codeLabel = 'Rule Logic Definition'
      }
      if (!isCodeBlock && !isRuleLogic) {
        return
      }

      const details = document.createElement('details')
      details.className = 'summary-rule'

      const summary = document.createElement('summary')
      summary.innerHTML = `<strong>${codeLabel}</strong> <span style="font-size: 0.8em; color: var(--text-secondary);">(Click to expand/collapse)</span>`

      const body = document.createElement('div')
      body.className = 'summary-rule-body code-block-wrapper'

      parent.insertBefore(details, pre)
      details.appendChild(summary)
      body.appendChild(pre)
      details.appendChild(body)
    })
  })
}

interface Props {
  data: Iteration
}

export function PhasePanels({ data }: Props) {
  const rootRef = useRef<HTMLDivElement>(null)

  useEffect(() => {
    applyCollapsibleCode(rootRef.current)
  }, [data])

  const hasAnalysis = !!(data.analysis_prompt || data.analysis_response)
  const hasReviewPrompt =
    typeof data.review_prompt === 'string' && data.review_prompt.trim().length > 0
  const hasReviewResponse =
    typeof data.review_response === 'string' && data.review_response.trim().length > 0
  const hasReview = hasReviewPrompt || hasReviewResponse

  const analysisPrompt = data.analysis_prompt || '(No analysis prompt)'
  const analysisResponse = data.analysis_response || '(No analysis response yet)'
  const prompt = data.prompt || '(No prompt file)'
  const responseText = data.response_parsed ? data.response_text || '' : data.response || '(No response file)'
  const reviewPrompt = hasReviewPrompt ? data.review_prompt! : '(No review prompt yet)'
  const reviewResponse = hasReviewResponse ? data.review_response! : '(No review response yet/Empty)'

  return (
    <div ref={rootRef} className="content-view" id="contentView" style={{ flexDirection: 'column', paddingBottom: 50 }}>
      {/* PHASE 1: ANALYSIS (Top) */}
      <div
        id="phaseAnalysis"
        className="phase-container"
        style={{
          display: hasAnalysis ? 'flex' : 'none',
          borderBottom: '2px solid var(--border)',
          minHeight: 400,
          flexShrink: 0,
        }}
      >
        <div className="panel">
          <div className="panel">
            <div className="panel-header" style={{ color: '#7c3aed', borderBottom: '1px solid #7c3aed' }}>
              <span>PHASE 1: ANALYSIS PROMPT</span>
              <CopyButton text={data.analysis_prompt || ''} />
            </div>
            <div className="panel-content">
              <div
                className="markdown-body"
                dangerouslySetInnerHTML={{ __html: renderAnalysisMarkdown(analysisPrompt) }}
              />
            </div>
          </div>

          <div className="panel">
            <div className="panel-header" style={{ color: '#7c3aed', borderBottom: '1px solid #7c3aed' }}>
              <span>PHASE 1: STRATEGY PLAN</span>
              <CopyButton text={data.analysis_response || ''} />
            </div>
            <div className="panel-content">
              <div
                className="markdown-body"
                dangerouslySetInnerHTML={{ __html: renderAnalysisMarkdown(analysisResponse) }}
              />
            </div>
          </div>
        </div>
      </div>

      {/* PHASE 2: CODE GEN */}
      <div id="phaseCodeGen" style={{ flex: 1, display: 'flex', minHeight: 0, flexDirection: 'column' }}>
        <div style={{ flex: 1, display: 'flex', minHeight: 200, borderBottom: '2px solid var(--border)' }}>
          {/* Code Gen Prompt */}
          <div className="panel">
            <div className="panel-header" style={{ color: 'var(--accent)' }}>
              <span>
                PHASE 2: CODE GEN PROMPT <span className="badge">{data.prompt ? data.prompt.length : 0} chars</span>
              </span>
              <CopyButton text={data.prompt || ''} />
            </div>
            <div className="panel-content">
              <div className="markdown-body" dangerouslySetInnerHTML={{ __html: renderMarkdown(prompt) }} />
            </div>
          </div>

          {/* Code Gen Response */}
          <div className="panel">
            <div className="panel-header" style={{ color: 'var(--accent)' }}>
              <span>
                PHASE 2: CODE GEN RESPONSE{' '}
                <span className="badge">{responseText.length} chars</span>
              </span>
              <CopyButton text={responseText} />
            </div>
            <div className="panel-content">
              {data.response_parsed ? (
                <>
                  <div className="markdown-body" dangerouslySetInnerHTML={{ __html: renderMarkdown(responseText) }} />
                  {data.response_extras && Object.keys(data.response_extras).length > 0 && (
                    <div className="extras-container">
                      <div className="extras-title">Extras</div>
                      <pre className="extras-content">{JSON.stringify(data.response_extras, null, 2)}</pre>
                    </div>
                  )}
                </>
              ) : (
                <pre>{responseText}</pre>
              )}
            </div>
          </div>
        </div>

        {/* ROW 2: REVIEW AGENT */}
        <div id="phaseReview" style={{ flex: 1, display: hasReview ? 'flex' : 'none', minHeight: 200 }}>
          <div className="panel">
            <div className="panel-header" style={{ color: '#db2777' }}>
              <span>
                PHASE 3: REVIEW PROMPT <span className="badge">{reviewPrompt.length} chars</span>
              </span>
              <CopyButton text={reviewPrompt} />
            </div>
            <div className="panel-content">
              <div className="markdown-body" dangerouslySetInnerHTML={{ __html: renderMarkdown(reviewPrompt) }} />
            </div>
          </div>

          <div className="panel">
            <div className="panel-header" style={{ color: '#db2777' }}>
              <span>PHASE 3: REVIEW FEEDBACK</span>
              <CopyButton text={reviewResponse} />
            </div>
            <div className="panel-content">
              <div className="markdown-body" dangerouslySetInnerHTML={{ __html: renderMarkdown(reviewResponse) }} />
            </div>
          </div>
        </div>
      </div>
    </div>
  )
}
