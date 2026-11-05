import { useState } from 'react'

interface Props {
  text: string
  style?: React.CSSProperties
  label?: string
}

export function CopyButton({ text, style, label = 'Copy' }: Props) {
  const [copied, setCopied] = useState(false)

  const onClick = () => {
    navigator.clipboard
      .writeText(text)
      .then(() => {
        setCopied(true)
        setTimeout(() => setCopied(false), 2000)
      })
      .catch((err) => console.error('Failed to copy: ', err))
  }

  return (
    <button className="copy-btn" style={style} onClick={onClick}>
      {copied ? 'Copied!' : label}
    </button>
  )
}
