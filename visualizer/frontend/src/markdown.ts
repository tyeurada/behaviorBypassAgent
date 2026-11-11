import { marked } from 'marked'

// Escape markdown metacharacters that break elastic rule display (*, \, [, ])
// Preserves ** for bold. Use before marked.parse() for analysis prompt/response.
export function escapeMarkdownForRules(text: string): string {
  if (typeof text !== 'string') return text
  return text
    .replace(/\\/g, '\\\\') // backslash (paths)
    .replace(/(?<!\*)\*(?!\*)/g, '\\*') // single * not part of ** (wildcards)
    .replace(/\[/g, '\\[')
    .replace(/\]/g, '\\]') // brackets (e.g. [Sanitized_Hash_List])
}

export function htmlEscape(s: string): string {
  if (typeof s !== 'string') return s
  const div = document.createElement('div')
  div.textContent = s
  return div.innerHTML
}

// Clean up improperly indented markdown containing python multiline f-string whitespace
export function cleanMarkdown(text: string): string {
  if (typeof text !== 'string') return text
  return text
    .replace(/^[ \t]+(```)/gm, '$1')
    .replace(/^[ \t]+(#+ )/gm, '$1')
    .replace(/^[ \t]+(\* )/gm, '$1')
    .replace(/^[ \t]+(- )/gm, '$1')
}

// Wrap "Logic:" continuation blocks in <pre> so rule text isn't parsed as markdown.
// Truncates list line at "| Logic:" and puts the rest + following lines in a <pre> block.
export function preprocessAnalysisContent(text: string): string {
  if (typeof text !== 'string') return text
  const lines = text.split(/\r?\n/)
  const out: string[] = []
  let i = 0
  while (i < lines.length) {
    const line = lines[i]
    const listMatch = line.match(/^(\s*-\s+Rule:[^|]*\| APIs:[^|]*)\|\s*Logic:\s*(.*)$/)
    if (listMatch) {
      const prefix = listMatch[1] + ' | Logic:'
      const restOfLine = listMatch[2]
      out.push(escapeMarkdownForRules(prefix))
      const preLines = [restOfLine]
      i++
      while (i < lines.length) {
        const next = lines[i]
        if (/^\s*-\s+Rule:/.test(next) || /^\s*#{1,3}\s/.test(next)) break
        if (next.trim() === '' && i + 1 < lines.length && /^\s*#{1,3}\s/.test(lines[i + 1])) break
        preLines.push(next)
        i++
      }
      const preContent = preLines.join('\n').trim()
      if (preContent) {
        out.push('<pre class="rule-logic">' + htmlEscape(preContent) + '</pre>')
      }
      continue
    }
    // Trim leading whitespace from header lines so they parse as markdown headers
    const toPush = /^\s*#{1,3}\s/.test(line) ? line.trim() : line
    out.push(escapeMarkdownForRules(toPush))
    i++
  }
  return out.join('\n')
}

export function renderMarkdown(text: string): string {
  return marked.parse(cleanMarkdown(text ?? ''), { async: false }) as string
}

export function renderAnalysisMarkdown(text: string): string {
  return marked.parse(cleanMarkdown(preprocessAnalysisContent(text ?? '')), {
    async: false,
  }) as string
}
