import { useEffect, useState } from 'react'

function Transition({
  show,
  tag = 'div',
  children,
  className = '',
  enter = '',
  enterStart = '',
  enterEnd = '',
  leave = '',
  leaveStart = '',
  leaveEnd = '',
  ...rest
}) {
  const [shouldRender, setShouldRender] = useState(show)
  const [transitionClass, setTransitionClass] = useState('')

  useEffect(() => {
    let frameId
    let timeoutId

    if (show) {
      setShouldRender(true)
      setTransitionClass(`${enter} ${enterStart}`.trim())

      frameId = requestAnimationFrame(() => {
        setTransitionClass(`${enter} ${enterEnd}`.trim())
      })
    } else if (shouldRender) {
      setTransitionClass(`${leave} ${leaveStart}`.trim())

      frameId = requestAnimationFrame(() => {
        setTransitionClass(`${leave} ${leaveEnd}`.trim())
      })

      timeoutId = setTimeout(() => {
        setShouldRender(false)
      }, 200)
    }

    return () => {
      if (frameId) cancelAnimationFrame(frameId)
      if (timeoutId) clearTimeout(timeoutId)
    }
  }, [show])

  if (!shouldRender) return null

  const Component = tag

  return (
    <Component className={`${className} ${transitionClass}`.trim()} {...rest}>
      {children}
    </Component>
  )
}

export default Transition
