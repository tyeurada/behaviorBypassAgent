import { useCallback, useRef, useState } from 'react'
import type { SessionEntry } from '../types'

const MIN_WIDTH = 180
const MAX_WIDTH = 520
const DEFAULT_WIDTH = 250

interface Props {
  sessions: SessionEntry[]
  currentSession: string | null
  controlPanelActive: boolean
  onSelectSession: (id: string) => void
  onToggleControlPanel: () => void
}

export function Sidebar({ sessions, currentSession, controlPanelActive, onSelectSession, onToggleControlPanel }: Props) {
  const [width, setWidth] = useState(DEFAULT_WIDTH)
  const dragState = useRef<{ startX: number; startWidth: number } | null>(null)

  const onResizeStart = useCallback(
    (e: React.MouseEvent) => {
      e.preventDefault()
      dragState.current = { startX: e.clientX, startWidth: width }
      document.body.style.cursor = 'col-resize'
      document.body.style.userSelect = 'none'

      const onMove = (ev: MouseEvent) => {
        if (!dragState.current) return
        const next = dragState.current.startWidth + ev.clientX - dragState.current.startX
        setWidth(Math.min(MAX_WIDTH, Math.max(MIN_WIDTH, next)))
      }
      const onUp = () => {
        dragState.current = null
        document.body.style.cursor = ''
        document.body.style.userSelect = ''
        document.removeEventListener('mousemove', onMove)
        document.removeEventListener('mouseup', onUp)
      }
      document.addEventListener('mousemove', onMove)
      document.addEventListener('mouseup', onUp)
    },
    [width],
  )

  return (
    <div className="sidebar" style={{ width, minWidth: MIN_WIDTH, maxWidth: MAX_WIDTH }}>
      <div className="sidebar-header">Agent Sessions</div>
      <div style={{ padding: '0 0.5rem 0.5rem 0.5rem', borderBottom: '1px solid var(--border)' }}>
        <button
          id="btnControlPanel"
          className={`control-panel-toggle-btn${controlPanelActive ? ' active' : ''}`}
          onClick={onToggleControlPanel}
        >
          Control Panel & Config
        </button>
      </div>
      <div className="session-list" id="sessionList">
        {sessions.length === 0 ? (
          <div style={{ padding: '1rem', textAlign: 'center', color: 'var(--text-secondary)' }}>
            Loading...
          </div>
        ) : (
          sessions.map((s) => (
            <div
              key={s.id}
              className={`session-item${currentSession === s.id && !controlPanelActive ? ' active' : ''}`}
              title={s.id}
              onClick={() => onSelectSession(s.id)}
            >
              {s.id}
            </div>
          ))
        )}
      </div>
      <div
        className="sidebar-resizer"
        role="separator"
        aria-orientation="vertical"
        aria-label="Resize sidebar"
        onMouseDown={onResizeStart}
      />
    </div>
  )
}
