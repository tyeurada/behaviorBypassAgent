import { useRef } from 'react'
import type { Iteration } from '../types'

const DROPDOWN_THRESHOLD = 6

interface Props {
  iterations: Iteration[]
  hasSummary: boolean
  selectedIndex: number | null
  summarySelected: boolean
  onSelectIteration: (index: number) => void
  onSelectSummary: () => void
}

export function IterationNav({
  iterations,
  hasSummary,
  selectedIndex,
  summarySelected,
  onSelectIteration,
  onSelectSummary,
}: Props) {
  const navRef = useRef<HTMLDivElement>(null)

  // Translate vertical wheel into horizontal scroll so the button row is
  // scrollable with a plain mouse wheel / trackpad.
  const onWheel = (e: React.WheelEvent<HTMLDivElement>) => {
    const el = navRef.current
    if (!el) return
    if (Math.abs(e.deltaY) > Math.abs(e.deltaX)) {
      el.scrollLeft += e.deltaY
    }
  }

  const showDropdown = iterations.length > DROPDOWN_THRESHOLD
  const selectValue = summarySelected ? 'summary' : selectedIndex !== null ? String(selectedIndex) : ''

  return (
    <div className="iteration-nav" id="iterNav" ref={navRef} onWheel={onWheel}>
      {iterations.length === 0 ? (
        <div style={{ color: 'var(--text-secondary)' }}>No iterations found in this session</div>
      ) : (
        iterations.map((iter, index) => (
          <button
            key={iter.iteration}
            className={`iter-btn${!summarySelected && selectedIndex === index ? ' active' : ''}`}
            onClick={() => onSelectIteration(index)}
          >
            Iteration {iter.iteration}
          </button>
        ))
      )}
      {hasSummary && (
        <button
          className={`iter-btn${summarySelected ? ' active' : ''}`}
          id="btn-summary"
          onClick={onSelectSummary}
        >
          Summary
        </button>
      )}
      {showDropdown && (
        <select
          className="iter-jump"
          value={selectValue}
          onChange={(e) => {
            if (e.target.value === 'summary') {
              onSelectSummary()
            } else if (e.target.value !== '') {
              onSelectIteration(Number(e.target.value))
            }
          }}
        >
          <option value="" disabled>
            Jump to…
          </option>
          {iterations.map((iter, index) => (
            <option key={iter.iteration} value={index}>
              Iteration {iter.iteration}
            </option>
          ))}
          {hasSummary && <option value="summary">Summary</option>}
        </select>
      )}
    </div>
  )
}
