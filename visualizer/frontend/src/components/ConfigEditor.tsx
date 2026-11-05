import { useEffect, useState } from 'react'
import type { AgentConfig } from '../types'
import { getConfig, saveConfig } from '../api'

const PROVIDERS = [
  { value: 'gemini', label: 'Google Gemini (Recommended)' },
  { value: 'openai', label: 'OpenAI GPT' },
  { value: 'anthropic', label: 'Anthropic Claude' },
  { value: 'deepseek', label: 'DeepSeek' },
  { value: 'openai_compatible', label: 'Custom Endpoint (OpenAI-compatible)' },
]

const DEFAULT_GEMINI_MODELS = [
  'models/gemini-2.5-flash',
  'models/gemini-2.5-pro',
  'models/gemini-flash-latest',
  'models/gemini-1.5-pro-latest',
]

function normalizeConfig(config: AgentConfig): AgentConfig {
  const draft = structuredClone(config ?? {})
  draft.ai = draft.ai ?? {}
  draft.ai.provider = draft.ai.provider ?? 'gemini'
  draft.ai.gemini = draft.ai.gemini ?? {}
  draft.compiler = draft.compiler ?? {}
  draft.compiler.msvc = draft.compiler.msvc ?? {}
  draft.compiler.mingw = draft.compiler.mingw ?? {}
  draft.execution = draft.execution ?? {}
  draft.execution.success_criteria = draft.execution.success_criteria ?? {}
  draft.execution.success_criteria.process = draft.execution.success_criteria.process ?? {}
  draft.execution.success_criteria.network = draft.execution.success_criteria.network ?? {}
  draft.execution.success_criteria.file = draft.execution.success_criteria.file ?? {}
  draft.evasion_techniques = draft.evasion_techniques ?? {}
  draft.evasion_techniques.memory = draft.evasion_techniques.memory ?? []
  draft.evasion_techniques.preferred_techniques = draft.evasion_techniques.preferred_techniques ?? []
  return draft
}

// eslint-disable-next-line @typescript-eslint/no-explicit-any
function setPath(obj: Record<string, any>, path: string[], value: unknown) {
  let cur = obj
  for (let i = 0; i < path.length - 1; i++) {
    cur = cur[path[i]] = cur[path[i]] ?? {}
  }
  cur[path[path.length - 1]] = value
}

export function ConfigEditor() {
  const [draft, setDraft] = useState<AgentConfig | null>(null)
  const [error, setError] = useState<string | null>(null)
  const [saving, setSaving] = useState(false)

  useEffect(() => {
    getConfig()
      .then((cfg) => setDraft(normalizeConfig(cfg)))
      .catch((e) => setError(String(e)))
  }, [])

  const update = (path: string[], value: unknown) => {
    setDraft((prev) => {
      if (!prev) return prev
      const next = structuredClone(prev)
      setPath(next, path, value)
      return next
    })
  }

  const save = async () => {
    if (!draft) return
    setSaving(true)
    try {
      await saveConfig(draft)
      alert('Settings saved successfully! Evasion techniques and configuration updated.')
      const cfg = await getConfig()
      setDraft(normalizeConfig(cfg))
    } catch (e) {
      alert('Error saving settings: ' + e)
    } finally {
      setSaving(false)
    }
  }

  if (error) {
    return <div style={{ color: '#ef4444', padding: '1rem' }}>Failed to load config: {error}</div>
  }
  if (!draft) {
    return <div style={{ color: 'var(--text-secondary)', textAlign: 'center', padding: '2rem' }}>Loading configuration...</div>
  }

  const ai = draft.ai
  const provider: string = ai.provider || 'gemini'
  const providerCfg = ai[provider] ?? {}
  const gemini = ai.gemini ?? {}
  const availableModels: string[] = gemini.available_models || DEFAULT_GEMINI_MODELS
  const compiler = draft.compiler
  const currentLang: string = compiler.language || 'c'
  const successCriteria = draft.execution.success_criteria
  const successType: string = successCriteria.type || 'process'
  const evasion = draft.evasion_techniques
  const memoryTech: { name?: string; description?: string; trigger?: string; enabled?: boolean }[] =
    evasion.memory || []
  const preferred: string[] = evasion.preferred_techniques || []

  const toggleTechEnabled = (name: string, enabled: boolean) => {
    setDraft((prev) => {
      if (!prev) return prev
      const next = structuredClone(prev)
      const tech = next.evasion_techniques.memory.find(
        (t: { name?: string }) => t.name === name,
      )
      if (tech) tech.enabled = enabled
      return next
    })
  }

  const togglePreferred = (name: string, on: boolean) => {
    setDraft((prev) => {
      if (!prev) return prev
      const next = structuredClone(prev)
      const list: string[] = next.evasion_techniques.preferred_techniques ?? []
      next.evasion_techniques.preferred_techniques = on
        ? [...list.filter((n) => n !== name), name]
        : list.filter((n) => n !== name)
      return next
    })
  }

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: '1rem', flex: 1, minHeight: 0 }}>
      <div
        style={{
          display: 'flex',
          justifyContent: 'space-between',
          alignItems: 'center',
          borderBottom: '1px solid var(--border)',
          paddingBottom: '0.5rem',
          marginBottom: '0.25rem',
        }}
      >
        <h3 style={{ color: 'var(--text-primary)', margin: 0, fontSize: '1.1rem', display: 'flex', alignItems: 'center', gap: 6 }}>
          Config Settings
        </h3>
        <button
          onClick={save}
          disabled={saving}
          style={{
            padding: '0.45rem 1rem',
            background: 'linear-gradient(135deg, #0284c7 0%, #0369a1 100%)',
            border: '1px solid #38bdf8',
            borderRadius: 4,
            color: 'white',
            cursor: 'pointer',
            fontWeight: 'bold',
            fontSize: '0.85rem',
            boxShadow: '0 2px 4px rgba(56, 189, 248, 0.2)',
          }}
        >
          {saving ? 'Saving...' : 'Save Settings'}
        </button>
      </div>

      <div
        id="configForm"
        style={{
          display: 'flex',
          flexDirection: 'column',
          gap: '1rem',
          overflowY: 'auto',
          paddingRight: '0.25rem',
          flex: 1,
          minHeight: 0,
        }}
      >
        {/* 1. AI Settings */}
        <details className="config-card" open style={{ order: 1 }}>
          <summary className="config-card-title">AI Model & Provider</summary>
          <div className="config-group">
            <label className="config-label">AI Provider</label>
            <select
              className="config-input"
              value={provider}
              onChange={(e) => update(['ai', 'provider'], e.target.value)}
            >
              {PROVIDERS.map((p) => (
                <option key={p.value} value={p.value}>
                  {p.label}
                </option>
              ))}
            </select>
          </div>
          {provider === 'gemini' && (
            <div className="config-group">
              <label className="config-label">Gemini Model</label>
              <select
                className="config-input"
                value={gemini.model || 'models/gemini-2.5-flash'}
                onChange={(e) => update(['ai', 'gemini', 'model'], e.target.value)}
              >
                {availableModels.map((m) => (
                  <option key={m} value={m}>
                    {m}
                  </option>
                ))}
              </select>
            </div>
          )}
          {provider !== 'gemini' && (
            <div className="config-group">
              <label className="config-label">Model</label>
              <input
                type="text"
                className="config-input"
                value={providerCfg.model || ''}
                placeholder="e.g. gpt-4o, deepseek-chat, qwen3:14b"
                onChange={(e) => update(['ai', provider, 'model'], e.target.value)}
              />
            </div>
          )}
          {(provider === 'openai_compatible' || provider === 'deepseek') && (
            <div className="config-group">
              <label className="config-label">Base URL</label>
              <input
                type="text"
                className="config-input"
                value={providerCfg.base_url || ''}
                placeholder="http://localhost:11434/v1 (Ollama) or https://your-endpoint/v1"
                onChange={(e) => update(['ai', provider, 'base_url'], e.target.value)}
              />
            </div>
          )}
          {provider === 'openai_compatible' && (
            <div className="config-group">
              <label className="config-label">API Key Env Var Name</label>
              <input
                type="text"
                className="config-input"
                value={providerCfg.api_key_env || 'OPENAI_COMPATIBLE_API_KEY'}
                placeholder="OPENAI_COMPATIBLE_API_KEY"
                onChange={(e) => update(['ai', provider, 'api_key_env'], e.target.value)}
              />
            </div>
          )}
          <div className="config-group">
            <label className="config-label">Temperature</label>
            <input
              type="number"
              step={0.1}
              min={0}
              max={2}
              className="config-input"
              value={providerCfg.temperature ?? 0.7}
              onChange={(e) =>
                update(['ai', provider, 'temperature'], parseFloat(e.target.value) || 0.7)
              }
            />
          </div>
        </details>

        {/* 2. Compiler Settings */}
        <details className="config-card" style={{ order: 3 }}>
          <summary className="config-card-title">Compiler & Programming Language</summary>
          <div className="config-group">
            <label className="config-label">Target Programming Language</label>
            <select
              className="config-input"
              value={currentLang === '.net' ? 'csharp' : currentLang}
              onChange={(e) => update(['compiler', 'language'], e.target.value)}
            >
              <option value="c">C / C++ (Native Binary)</option>
              <option value="csharp">C# / .NET Source</option>
              <option value="python">Python Script</option>
            </select>
          </div>
          {currentLang === 'c' && (
            <>
              <div className="config-group" style={{ display: 'flex' }}>
                <label className="config-label">Compiler Type (C/C++)</label>
                <select
                  className="config-input"
                  value={compiler.type || 'msvc'}
                  onChange={(e) => update(['compiler', 'type'], e.target.value)}
                >
                  <option value="msvc">MSVC (cl.exe)</option>
                  <option value="mingw">MinGW (gcc)</option>
                </select>
              </div>
              <div className="config-group" style={{ display: 'flex' }}>
                <label className="config-label">MSVC vcvars64.bat Path</label>
                <input
                  type="text"
                  className="config-input"
                  value={compiler.msvc?.vcvars_path || ''}
                  onChange={(e) => update(['compiler', 'msvc', 'vcvars_path'], e.target.value)}
                />
              </div>
            </>
          )}
        </details>

        {/* 3. Execution Settings */}
        <details className="config-card" style={{ order: 4 }}>
          <summary className="config-card-title">Execution & Success Criteria</summary>
          <div className="config-group">
            <label className="config-checkbox-container">
              <input
                type="checkbox"
                checked={!!successCriteria.enabled}
                onChange={(e) =>
                  update(['execution', 'success_criteria', 'enabled'], e.target.checked)
                }
              />
              Enable Success Verification Criteria
            </label>
          </div>
          <div className="config-group">
            <label className="config-label">Verification Type</label>
            <select
              className="config-input"
              value={successType}
              onChange={(e) => update(['execution', 'success_criteria', 'type'], e.target.value)}
            >
              <option value="process">Process Spawning (e.g. calc.exe)</option>
              <option value="network">Network Outbound Callback</option>
              <option value="file">File Creation</option>
            </select>
          </div>
          {successType === 'process' && (
            <div className="config-group">
              <label className="config-label">Target Process Name</label>
              <input
                type="text"
                className="config-input"
                value={successCriteria.process?.name || 'calc.exe'}
                onChange={(e) =>
                  update(['execution', 'success_criteria', 'process', 'name'], e.target.value)
                }
              />
            </div>
          )}
          {successType === 'network' && (
            <div className="config-group">
              <label className="config-label">C2 Host / Port</label>
              <div style={{ display: 'flex', gap: 8 }}>
                <input
                  type="text"
                  className="config-input"
                  placeholder="Host"
                  value={successCriteria.network?.host || '10.0.1.101'}
                  onChange={(e) =>
                    update(['execution', 'success_criteria', 'network', 'host'], e.target.value)
                  }
                />
                <input
                  type="number"
                  className="config-input"
                  placeholder="Port"
                  style={{ width: 100 }}
                  value={successCriteria.network?.port ?? 80}
                  onChange={(e) =>
                    update(
                      ['execution', 'success_criteria', 'network', 'port'],
                      parseInt(e.target.value) || 80,
                    )
                  }
                />
              </div>
            </div>
          )}
          {successType === 'file' && (
            <div className="config-group">
              <label className="config-label">Target File Path</label>
              <input
                type="text"
                className="config-input"
                value={successCriteria.file?.path || ''}
                onChange={(e) =>
                  update(['execution', 'success_criteria', 'file', 'path'], e.target.value)
                }
              />
            </div>
          )}
        </details>

        {/* 4. Evasion Techniques Customizer */}
        <details className="config-card" open style={{ order: 2 }}>
          <summary className="config-card-title">
            <span>Evasion Techniques Customizer</span>
          </summary>
          <div
            style={{
              display: 'flex',
              flexDirection: 'column',
              background: 'rgba(0, 0, 0, 0.04)',
              borderRadius: 6,
              border: '1px solid var(--border)',
              maxHeight: 400,
              overflowY: 'auto',
            }}
          >
            {memoryTech.map((tech, idx) => {
              const name = tech.name || `Tech ${idx}`
              const isPreferred = preferred.includes(name)
              return (
                <div key={name} className="tech-list-item">
                  <div className="tech-checkboxes">
                    <label className="switch" title="Enable/Disable this technique in the AI's available arsenal">
                      <input
                        type="checkbox"
                        checked={tech.enabled === true}
                        onChange={(e) => toggleTechEnabled(name, e.target.checked)}
                      />
                      <span className="slider-round" />
                    </label>
                    <label
                      title="Set as Preferred Technique"
                      style={{
                        display: 'flex',
                        alignItems: 'center',
                        gap: 4,
                        fontSize: '0.7rem',
                        color: 'var(--text-secondary)',
                        cursor: 'pointer',
                        marginTop: 4,
                      }}
                    >
                      <input
                        type="checkbox"
                        checked={isPreferred}
                        onChange={(e) => togglePreferred(name, e.target.checked)}
                      />
                      Prefer
                    </label>
                  </div>
                  <div className="tech-info">
                    <div className="tech-name">{name}</div>
                    <div className="tech-desc">{tech.description || ''}</div>
                    {tech.trigger ? <div className="tech-trigger">Trigger: {tech.trigger}</div> : null}
                  </div>
                </div>
              )
            })}
          </div>
        </details>
      </div>
    </div>
  )
}
