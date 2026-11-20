import type { AgentConfig, RunStatus, SessionDetails, SessionEntry } from './types'

async function fetchJson<T>(url: string, init?: RequestInit): Promise<T> {
  const res = await fetch(url, init)
  const data = await res.json()
  if (!res.ok) {
    throw new ApiError(res.status, data?.error ?? `HTTP ${res.status}`)
  }
  return data as T
}

export class ApiError extends Error {
  status: number

  constructor(status: number, message: string) {
    super(message)
    this.status = status
  }
}

export function getSessions(): Promise<SessionEntry[]> {
  return fetchJson('/api/sessions')
}

export function getSessionDetails(sessionId: string): Promise<SessionDetails> {
  return fetchJson(`/api/sessions/${sessionId}?ts=${Date.now()}`)
}

export function getSessionLogs(sessionId: string): Promise<{ logs?: string; error?: string }> {
  return fetchJson(`/api/sessions/${sessionId}/logs`)
}

export function getConfig(): Promise<AgentConfig> {
  return fetchJson('/api/config')
}

export function saveConfig(config: AgentConfig): Promise<{ status: string }> {
  return fetchJson('/api/config', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(config),
  })
}

export function startRun(shellcodePath: string, iterations: number): Promise<{ status: string; session_id: string }> {
  return fetchJson('/api/run', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ shellcode_path: shellcodePath, iterations }),
  })
}

export function stopRun(): Promise<{ status: string }> {
  return fetchJson('/api/run/stop', { method: 'POST' })
}

export function getRunStatus(): Promise<RunStatus> {
  return fetchJson('/api/run/status')
}
