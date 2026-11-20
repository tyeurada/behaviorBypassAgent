export interface SessionEntry {
  id: string
  path: string
}

export interface Iteration {
  iteration: number
  prompt: string
  response: string
  code: string
  has_prompt: boolean
  has_response: boolean
  has_code: boolean
  response_parsed: boolean
  response_data: Record<string, unknown>
  response_text?: string
  response_extras?: Record<string, unknown>
  analysis_prompt?: string
  analysis_response?: string
  review_prompt?: string | null
  review_response?: string | null
}

// config.yaml is a free-form YAML mapping; keep it loosely typed.
// eslint-disable-next-line @typescript-eslint/no-explicit-any
export type AgentConfig = Record<string, any>

export interface SessionDetails {
  session_id: string
  iterations: Iteration[]
  final_summary: string
  config: AgentConfig
}

export interface RunStatus {
  status: 'idle' | 'running' | 'completed' | 'failed' | string
  session_id: string | null
}
