import { twc } from "../../lib/twc";
import { useCallback, useEffect, useRef, useState } from 'react';
import { ModalContext } from './modalContext';
const toneStyles = {
  info: {
    icon: 'i',
    iconClass: 'border-sky-300/50 bg-sky-400/15 text-sky-700 dark:text-sky-200',
    buttonClass: 'border-sky-300/40 bg-sky-500 text-white shadow-lg shadow-sky-500/20'
  },
  success: {
    icon: '✓',
    iconClass: 'border-emerald-300/50 bg-emerald-400/15 text-emerald-700 dark:text-emerald-200',
    buttonClass: 'border-emerald-300/40 bg-emerald-500 text-white shadow-lg shadow-emerald-500/20'
  },
  warning: {
    icon: '!',
    iconClass: 'border-amber-300/50 bg-amber-400/15 text-amber-700 dark:text-amber-200',
    buttonClass: 'border-amber-300/40 bg-amber-500 text-white shadow-lg shadow-amber-500/20'
  },
  danger: {
    icon: '!',
    iconClass: 'border-rose-300/50 bg-rose-400/15 text-rose-700 dark:text-rose-200',
    buttonClass: 'border-rose-300/40 bg-rose-500 text-white shadow-lg shadow-rose-500/20'
  }
};
export function ModalProvider({
  children
}) {
  const [modal, setModal] = useState(null);
  const resolverRef = useRef(null);
  const close = useCallback((accepted = false) => {
    setModal(null);
    resolverRef.current?.(accepted);
    resolverRef.current = null;
  }, []);
  const confirm = useCallback(options => {
    const normalized = typeof options === 'string' ? {
      message: options
    } : options;
    return new Promise(resolve => {
      resolverRef.current = resolve;
      setModal({
        type: 'confirm',
        title: '작업을 확인해주세요',
        tone: 'warning',
        confirmText: '확인',
        cancelText: '취소',
        ...normalized
      });
    });
  }, []);
  const notify = useCallback(options => {
    const normalized = typeof options === 'string' ? {
      message: options
    } : options;
    return new Promise(resolve => {
      resolverRef.current = resolve;
      setModal({
        type: 'notice',
        title: '알림',
        tone: 'info',
        confirmText: '확인',
        ...normalized
      });
    });
  }, []);
  useEffect(() => {
    if (!modal) return undefined;
    const onKeyDown = event => {
      if (event.key === 'Escape') close(false);
      if (event.key === 'Enter' && modal.type === 'notice') close(true);
    };
    document.addEventListener('keydown', onKeyDown);
    document.body.style.overflow = 'hidden';
    return () => {
      document.removeEventListener('keydown', onKeyDown);
      document.body.style.overflow = '';
    };
  }, [close, modal]);
  const styles = toneStyles[modal?.tone] || toneStyles.info;
  return <ModalContext.Provider value={{
    confirm,
    notify
  }}>
      {children}
      {modal ? <div className={twc("fixed inset-0 z-[100] flex items-center justify-center bg-slate-950/55 p-4 backdrop-blur-md animate-modal-backdrop")} role="presentation" onMouseDown={event => {
      if (event.target === event.currentTarget) close(false);
    }}>
          <section role="dialog" aria-modal="true" aria-labelledby="global-modal-title" className={twc("relative w-full max-w-[460px] overflow-hidden rounded-[26px] border border-slate-200/80 bg-white/95 shadow-[0_26px_80px_rgba(15,23,42,.32)] backdrop-blur-2xl dark:border-white/10 dark:bg-slate-900/95 animate-modal-panel")}>
            <div className={twc("max-h-[calc(100dvh-2rem)] overflow-y-auto p-5 sm:p-6")}>
              <div className={twc("flex items-start gap-4")}>
                <div className={twc(`flex h-11 w-11 shrink-0 items-center justify-center rounded-2xl border text-lg font-black ${styles.iconClass}`)}>
                  {styles.icon}
                </div>
                <div className={twc("min-w-0 flex-1 text-left")}>
                  <p className={twc("mb-1 text-[11px] font-black uppercase tracking-[.18em] text-violet-600 dark:text-violet-300")}>
                    Security Console
                  </p>
                  <h2 id="global-modal-title" className={twc("m-0 text-xl font-black tracking-tight text-slate-950 dark:text-white")}>
                    {modal.title}
                  </h2>
                  <p className={twc("mt-3 whitespace-pre-line break-words text-sm font-semibold leading-6 text-slate-700 dark:text-slate-200")}>
                    {modal.message}
                  </p>
                  {modal.detail ? <div className={twc("mt-4 max-h-48 overflow-auto rounded-2xl border border-slate-200/80 bg-slate-950/[.035] px-4 py-3 text-xs font-bold leading-5 text-slate-600 dark:border-white/10 dark:bg-white/[.035] dark:text-slate-300")}>
                      {modal.detail}
                    </div> : null}
                </div>
              </div>

              <div className={twc("mt-6 flex flex-col-reverse gap-2 sm:flex-row sm:justify-end")}>
                {modal.type === 'confirm' ? <button type="button" className={twc("h-10 rounded-xl border border-slate-300/80 bg-white px-4 font-[var(--font-body)] text-[13px] font-extrabold text-slate-700 dark:border-white/10 dark:bg-slate-800 dark:text-slate-200")} onClick={() => close(false)}>
                    {modal.cancelText}
                  </button> : null}
                <button type="button" className={twc(`h-10 rounded-xl border px-4 font-[var(--font-body)] text-[13px] font-extrabold ${styles.buttonClass}`)} onClick={() => close(true)} autoFocus>
                  {modal.confirmText}
                </button>
              </div>
            </div>
          </section>
        </div> : null}
    </ModalContext.Provider>;
}
