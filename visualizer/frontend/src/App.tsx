import { useCallback, useEffect, useState } from 'react'
import { getSessionDetails, getSessions } from './api'
import { Sidebar } from './components/Sidebar'
import { IterationNav } from './components/IterationNav'
import { PhasePanels } from './components/PhasePanels'
import { SummaryView } from './components/SummaryView'
import { ControlPanel } from './components/ControlPanel'
import type { SessionDetails, SessionEntry } from './types'

export default function App() {
  const [sessions, setSessions] = useState<SessionEntry[]>([])
  const [currentSession, setCurrentSession] = useState<string | null>(null)
  const [details, setDetails] = useState<SessionDetails | null>(null)
  const [selectedIter, setSelectedIter] = useState<number | null>(null)
  const [summarySelected, setSummarySelected] = useState(false)
  const [controlPanelOpen, setControlPanelOpen] = useState(false)

  const loadSessions = useCallback(
    async (autoSelect = false) => {
      try {
        const list = await getSessions()
        setSessions(list)
        if (autoSelect && list.length > 0 && !currentSession) {
          selectSession(list[0].id)
        }
      } catch (e) {
        console.error(e)
      }
    },
    // eslint-disable-next-line react-hooks/exhaustive-deps
    [currentSession],
  )

  const selectSession = useCallback(async (sessionId: string) => {
    setControlPanelOpen(false)
    setCurrentSession(sessionId)
    setSummarySelected(false)

    const data = await getSessionDetails(sessionId)
    setDetails(data)
    // Auto select last iteration (usually most interesting)
    setSelectedIter(data.iterations.length > 0 ? data.iterations.length - 1 : null)
  }, [])

  const toggleControlPanel = useCallback(() => {
    setControlPanelOpen(true)
  }, [])

  useEffect(() => {
    loadSessions(true)
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [])

  const iterations = details?.iterations ?? []
  const summary = details?.final_summary ?? ''
  const runConfig = details?.config ?? {}

  return (
    <div className="app">
      <Sidebar
        sessions={sessions}
        currentSession={currentSession}
        controlPanelActive={controlPanelOpen}
        onSelectSession={selectSession}
        onToggleControlPanel={toggleControlPanel}
      />

      <div className="main">
        {!controlPanelOpen && (
          <IterationNav
            iterations={iterations}
            hasSummary={!!summary}
            selectedIndex={selectedIter}
            summarySelected={summarySelected}
            onSelectIteration={(i) => {
              setSelectedIter(i)
              setSummarySelected(false)
            }}
            onSelectSummary={() => setSummarySelected(true)}
          />
        )}

        {!controlPanelOpen &&
          details !== null &&
          (summarySelected ? (
            <SummaryView summary={summary} iterations={iterations} config={runConfig} />
          ) : (
            selectedIter !== null && <PhasePanels data={iterations[selectedIter]} />
          ))}

        {!controlPanelOpen && details === null && (
          <div className="iteration-nav" style={{ borderBottom: 'none' }}>
            <div style={{ color: 'var(--text-secondary)' }}>Select a session to view iterations</div>
          </div>
        )}

        {controlPanelOpen && <ControlPanel onSessionsChanged={() => loadSessions(false)} />}
      </div>
    </div>
  )
}
