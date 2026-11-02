import { clsx } from 'clsx'
import { twMerge } from 'tailwind-merge'
import { legacyTailwind } from '../styles/legacyTailwind.js'

const classCache = new Map()

/**
 * Tailwind migration bridge.
 *
 * Existing semantic class tokens stay in the DOM as stable selector hooks, while
 * their former stylesheet rules are expanded into statically discoverable
 * Tailwind utilities. New code can use Tailwind classes directly in the same
 * className value.
 */
export function twc(...inputs) {
  const raw = clsx(inputs)
  if (!raw) return ''

  const cached = classCache.get(raw)
  if (cached) return cached

  const expanded = raw
    .split(/\s+/)
    .filter(Boolean)
    .flatMap((token) => {
      const mapped = legacyTailwind[token]
      return mapped ? [token, mapped] : [token]
    })
    .join(' ')

  const merged = twMerge(expanded)

  if (classCache.size > 1000) classCache.clear()
  classCache.set(raw, merged)

  return merged
}
