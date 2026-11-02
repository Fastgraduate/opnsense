import { twc } from "./twc";
import { useEffect, useState } from 'react';
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
  const [shouldRender, setShouldRender] = useState(show);
  const [transitionClass, setTransitionClass] = useState('');
  useEffect(() => {
    let frameId;
    let timeoutId;
    if (show) {
      frameId = requestAnimationFrame(() => {
        setShouldRender(true);
        setTransitionClass(`${enter} ${enterStart}`.trim());
        requestAnimationFrame(() => {
          setTransitionClass(`${enter} ${enterEnd}`.trim());
        });
      });
    } else if (shouldRender) {
      frameId = requestAnimationFrame(() => {
        setTransitionClass(`${leave} ${leaveStart}`.trim());
        requestAnimationFrame(() => {
          setTransitionClass(`${leave} ${leaveEnd}`.trim());
        });
        timeoutId = setTimeout(() => {
          setShouldRender(false);
        }, 200);
      });
    }
    return () => {
      if (frameId) cancelAnimationFrame(frameId);
      if (timeoutId) clearTimeout(timeoutId);
    };
  }, [show]);
  if (!shouldRender) return null;
  const Component = tag;
  return <Component className={twc(`${className} ${transitionClass}`.trim())} {...rest}>
      {children}
    </Component>;
}
export default Transition;
