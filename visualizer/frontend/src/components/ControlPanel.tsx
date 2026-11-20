import { useCallback, useEffect, useRef, useState } from 'react'
import { getRunStatus, getSessionLogs, startRun, stopRun } from '../api'
import { ConfigEditor } from './ConfigEditor'
import { CopyButton } from './CopyButton'

interface Props {
  onSessionsChanged: () => void
}

export function ControlPanel({ onSessionsChanged }: Props) {
  const [shellcodePath, setShellcodePath] = useState('tests/calc.bin')
  const [iterations, setIterations] = useState(4)
  const [runStatus, setRunStatus] = useState<string>('idle')
  const [consoleLogs, setConsoleLogs] = useState(
    'Console logs will stream here in real time during agent run...',
  )

  const consoleRef = useRef<HTMLPreElement>(null)
  const logIntervalRef = useRef<number | null>(null)
  const statusIntervalRef = useRef<number | null>(null)

  const pollConsoleLogs = useCallback(async (sessionId: string | null) => {
    if (!sessionId) return
    try {
      const data = await getSessionLogs(sessionId)
      if (data.logs) {
        const pre = consoleRef.current
        const isAtBottom = pre
          ? pre.scrollHeight - pre.clientHeight <= pre.scrollTop + 50
          : false
        setConsoleLogs(data.logs)
        // Restore autoscroll after DOM updates
        requestAnimationFrame(() => {
          const el = consoleRef.current
          if (el && isAtBottom) el.scrollTop = el.scrollHeight
        })
      }
    } catch (e) {
      console.error('Error polling logs:', e)
    }
  }, [])

  const stopPolling = useCallback(() => {
    if (logIntervalRef.current) {
      clearInterval(logIntervalRef.current)
      logIntervalRef.current = null
    }
    if (statusIntervalRef.current) {
      clearInterval(statusIntervalRef.current)
      statusIntervalRef.current = null
    }
  }, [])

  const updateRunStatusUI = useCallback(
    (status: string, sessionId: string | null) => {
      setRunStatus(status)

      if (status === 'running') {
        if (!logIntervalRef.current) {
          logIntervalRef.current = window.setInterval(() => pollConsoleLogs(sessionId), 1500)
        }
        if (!statusIntervalRef.current) {
          statusIntervalRef.current = window.setInterval(checkRunStatus, 2000)
        }
      } else {
        stopPolling()
        // Perform one final log fetch and reload session list to pick up the new run
        if (sessionId) {
          pollConsoleLogs(sessionId)
          onSessionsChanged()
        }
      }
    },
    // eslint-disable-next-line react-hooks/exhaustive-deps
    [pollConsoleLogs, stopPolling, onSessionsChanged],
  )

  // eslint-disable-next-line react-hooks/exhaustive-deps
  async function checkRunStatus() {
    try {
      const data = await getRunStatus()
      updateRunStatusUI(data.status, data.session_id)
    } catch (e) {
      console.error('Error checking status:', e)
    }
  }

  // Fetch current status once when the panel opens
  useEffect(() => {
    checkRunStatus()
    return stopPolling
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [])

  const startAgentRun = async () => {
    const shellcode = shellcodePath.trim()
    if (!shellcode) {
      alert('Please specify a shellcode file path.')
      return
    }

    setConsoleLogs('Starting execution agent in background...\n')
    setRunStatus('running')

    try {
      const data = await startRun(shellcode, iterations)
      updateRunStatusUI('running', data.session_id)
      pollConsoleLogs(data.session_id)
    } catch (e) {
      alert('Error launching agent: ' + e)
      updateRunStatusUI('idle', null)
    }
  }

  const stopAgentRun = async () => {
    if (!confirm('Are you sure you want to stop the agent run?')) return
    try {
      await stopRun()
      updateRunStatusUI('idle', null)
      alert('Agent execution terminated.')
      onSessionsChanged()
    } catch (e) {
      alert('Error stopping agent: ' + e)
    }
  }

  const isRunning = runStatus === 'running'
  const badgeColor =
    runStatus === 'running'
      ? '#10b981'
      : runStatus === 'completed'
        ? '#0284c7'
        : runStatus === 'failed'
          ? '#ef4444'
          : '#475569'

  return (
    <div
      id="controlPanel"
      className="panel"
      style={{
        display: 'flex',
        padding: '1.5rem',
        paddingBottom: 0,
        background: 'var(--bg-primary)',
        minHeight: 0,
        overflow: 'hidden',
      }}
    >
      <h2 style={{ color: 'var(--accent)', marginTop: 0, display: 'flex', alignItems: 'center', gap: 10 }}>
        Agent Control Panel & Settings
      </h2>

      <div
        style={{
          display: 'grid',
          gridTemplateColumns: 'repeat(auto-fit, minmax(450px, 1fr))',
          gap: '1.5rem',
          minHeight: 0,
          flex: 1,
        }}
      >
        {/* Left Side: Run Command & Real-time Console */}
        <div
          style={{
            display: 'flex',
            flexDirection: 'column',
            gap: '1rem',
            minHeight: 0,
            overflowY: 'auto',
            paddingBottom: '1.5rem',
          }}
        >
          <div
            style={{
              background: 'var(--bg-secondary)',
              border: '1px solid var(--border)',
              padding: '1.25rem',
              borderRadius: 8,
              boxShadow: '0 4px 6px -1px rgba(0, 0, 0, 0.1)',
            }}
          >
            <h3
              style={{
                color: '#d97706',
                marginTop: 0,
                display: 'flex',
                alignItems: 'center',
                gap: 8,
                fontSize: '1.1rem',
                marginBottom: '1rem',
              }}
            >
              Launch New Execution
            </h3>

            <div style={{ marginBottom: '0.85rem' }}>
              <label
                style={{
                  display: 'block',
                  fontSize: '0.8rem',
                  color: 'var(--text-secondary)',
                  marginBottom: '0.35rem',
                  fontWeight: 600,
                }}
              >
                Shellcode File Path
              </label>
              <input
                type="text"
                value={shellcodePath}
                placeholder="e.g. tests/calc.bin"
                onChange={(e) => setShellcodePath(e.target.value)}
                style={{
                  width: '100%',
                  padding: '0.55rem',
                  background: 'var(--bg-primary)',
                  border: '1px solid var(--border)',
                  borderRadius: 4,
                  color: 'var(--text-primary)',
                  boxSizing: 'border-box',
                  fontFamily: 'monospace',
                  fontSize: '0.85rem',
                }}
              />
            </div>

            <div style={{ marginBottom: '1rem' }}>
              <label
                style={{
                  display: 'block',
                  fontSize: '0.8rem',
                  color: 'var(--text-secondary)',
                  marginBottom: '0.35rem',
                  fontWeight: 600,
                }}
              >
                Max Iterations
              </label>
              <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
                <input
                  type="range"
                  min={1}
                  max={30}
                  value={iterations}
                  style={{ flex: 1, accentColor: 'var(--accent)' }}
                  onChange={(e) => setIterations(Number(e.target.value))}
                />
                <input
                  type="number"
                  min={1}
                  max={30}
                  value={iterations}
                  style={{
                    width: 55,
                    padding: '0.35rem',
                    background: 'var(--bg-primary)',
                    border: '1px solid var(--border)',
                    borderRadius: 4,
                    color: 'var(--text-primary)',
                    textAlign: 'center',
                    fontSize: '0.85rem',
                  }}
                  onChange={(e) => setIterations(Number(e.target.value))}
                />
              </div>
            </div>

            <div style={{ display: 'flex', gap: '1rem' }}>
              <button
                onClick={startAgentRun}
                disabled={isRunning}
                style={{
                  flex: 1,
                  padding: '0.65rem',
                  background: 'linear-gradient(135deg, #10b981 0%, #059669 100%)',
                  border: '1px solid #34d399',
                  borderRadius: 4,
                  color: 'white',
                  cursor: 'pointer',
                  fontWeight: 'bold',
                  transition: 'all 0.3s ease',
                  fontSize: '0.85rem',
                  opacity: isRunning ? 0.5 : 1,
                }}
              >
                Start Agent
              </button>
              <button
                onClick={stopAgentRun}
                disabled={!isRunning}
                style={{
                  flex: 1,
                  padding: '0.65rem',
                  background: 'linear-gradient(135deg, #ef4444 0%, #dc2626 100%)',
                  border: '1px solid #f87171',
                  borderRadius: 4,
                  color: 'white',
                  cursor: 'pointer',
                  fontWeight: 'bold',
                  transition: 'all 0.3s ease',
                  fontSize: '0.85rem',
                  opacity: isRunning ? 1 : 0.5,
                }}
              >
                Stop Agent
              </button>
            </div>
          </div>

          {/* Console Log Output */}
          <div
            style={{
              flex: 1,
              display: 'flex',
              flexDirection: 'column',
              background: 'var(--code-bg)',
              border: '1px solid var(--border)',
              borderRadius: 8,
              overflow: 'hidden',
              minHeight: 280,
            }}
          >
            <div
              style={{
                background: 'var(--bg-secondary)',
                padding: '0.5rem 1rem',
                borderBottom: '1px solid var(--border)',
                display: 'flex',
                justifyContent: 'space-between',
                alignItems: 'center',
                fontSize: '0.85rem',
                fontWeight: 600,
              }}
            >
              <span style={{ color: 'var(--accent)' }}>Agent Terminal Console Output</span>
              <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
                <span
                  id="runStatusBadge"
                  className="badge"
                  style={{ background: badgeColor, color: 'white', fontWeight: 'bold', padding: '3px 8px' }}
                >
                  {runStatus.toUpperCase()}
                </span>
                <CopyButton
                  text={consoleLogs}
                  label="Copy Log"
                  style={{ margin: 0, padding: '2px 6px' }}
                />
              </div>
            </div>
            <pre
              ref={consoleRef}
              id="consoleLogs"
              style={{
                flex: 1,
                padding: '1rem',
                margin: 0,
                overflowY: 'auto',
                fontFamily: "'Consolas', 'Courier New', monospace",
                fontSize: '0.85rem',
                color: '#34d399',
                background: '#020617',
                whiteSpace: 'pre-wrap',
                lineHeight: 1.4,
                textShadow: '0 0 2px rgba(52, 211, 153, 0.3)',
              }}
            >
              {consoleLogs}
            </pre>
          </div>
        </div>

        {/* Right Side: Configuration Editor */}
        <div
          style={{
            background: 'var(--bg-secondary)',
            border: '1px solid var(--border)',
            padding: '1.25rem',
            borderRadius: 8,
            display: 'flex',
            flexDirection: 'column',
            gap: '1rem',
            flex: 1,
            minHeight: 0,
            overflow: 'hidden',
            marginBottom: '1.5rem',
            boxShadow: '0 4px 6px -1px rgba(0, 0, 0, 0.1)',
          }}
        >
          <ConfigEditor />
        </div>
      </div>
    </div>
  )
}
