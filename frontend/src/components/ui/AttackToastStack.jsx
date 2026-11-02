import { useEffect } from 'react';
import { twc } from '../../lib/twc';

const LOG_TIME_ZONE = 'Asia/Seoul';

function displayText(value, fallback = '—') {
  if (value == null || value === '') return fallback;
  return String(value);
}

function formatAttackTime(value) {
  if (!value) return '';
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return '';
  return new Intl.DateTimeFormat('ko-KR', {
    timeZone: LOG_TIME_ZONE,
    month: '2-digit',
    day: '2-digit',
    hour: '2-digit',
    minute: '2-digit',
    second: '2-digit',
    hour12: false,
  }).format(date);
}

function attackType(attack) {
  const ml = attack?.ml || {};
  const display = displayText(ml.main_result_display, '');
  if (display) return display.split('·')[0].trim();
  return displayText(ml.detected_class || ml.prediction || attack?.category || attack?.event_type, '공격 이벤트');
}

function AttackToast({ attack, onOpen, onDismiss }) {
  useEffect(() => {
    const timer = window.setTimeout(() => onDismiss(attack.toastId), 8000);
    return () => window.clearTimeout(timer);
  }, [attack.toastId, onDismiss]);

  const source = displayText(attack.source_ip);
  const destination = displayText(attack.destination_ip);
  const signature = displayText(attack.rule || attack.signature, '탐지 시그니처 없음');

  return <article className={twc("pointer-events-auto relative overflow-hidden rounded-2xl border border-rose-300/70 bg-white/95 shadow-[0_18px_55px_rgba(15,23,42,.24)] backdrop-blur-2xl dark:border-rose-400/25 dark:bg-slate-950/94 animate-modal-panel") }>
      <button
        type="button"
        className={twc("group block w-full p-4 pr-11 text-left outline-none transition hover:bg-rose-50/60 focus-visible:ring-2 focus-visible:ring-rose-400/70 dark:hover:bg-rose-400/[.06]")}
        onClick={() => onOpen(attack)}
        aria-label={`${attackType(attack)} 공격 탐지 알림. 실시간 공격 탐지 페이지로 이동`}
      >
        <div className={twc("flex items-start gap-3") }>
          <span className={twc("mt-0.5 flex h-10 w-10 shrink-0 items-center justify-center rounded-xl border border-rose-300/70 bg-rose-50 text-rose-600 dark:border-rose-400/25 dark:bg-rose-400/10 dark:text-rose-300") } aria-hidden="true">
            <svg viewBox="0 0 24 24" className={twc("h-5 w-5 fill-current") }>
              <path d="M12 2 1 21h22L12 2Zm0 4.3L19.3 19H4.7L12 6.3ZM11 10h2v5h-2v-5Zm0 6h2v2h-2v-2Z" />
            </svg>
          </span>

          <div className={twc("min-w-0 flex-1") }>
            <div className={twc("flex min-w-0 items-center gap-2") }>
              <strong className={twc("truncate text-[13px] font-black text-rose-600 dark:text-rose-300")}>새 공격 탐지</strong>
              {attack.timestamp ? <time className={twc("ml-auto shrink-0 text-[10px] font-bold text-slate-400 dark:text-slate-500")}>{formatAttackTime(attack.timestamp)}</time> : null}
            </div>
            <h3 className={twc("mt-1 truncate text-[15px] font-black tracking-[-.02em] text-slate-950 dark:text-white")}>{attackType(attack)}</h3>
            <p className={twc("mt-1 truncate text-[12px] font-bold text-slate-600 dark:text-slate-300")}>{source} → {destination}</p>
            <p className={twc("mt-2 line-clamp-2 text-[11px] font-semibold leading-4 text-slate-500 dark:text-slate-400")}>{signature}</p>
            <span className={twc("mt-3 inline-flex items-center gap-1 text-[11px] font-black text-violet-600 dark:text-violet-300")}>실시간 공격 탐지로 이동 <span aria-hidden="true">→</span></span>
          </div>
        </div>
      </button>

      <button
        type="button"
        aria-label="알림 닫기"
        className={twc("absolute right-2 top-2 flex h-8 w-8 items-center justify-center rounded-lg text-lg font-bold text-slate-400 transition hover:bg-slate-100 hover:text-slate-700 focus-visible:ring-2 focus-visible:ring-violet-400 dark:hover:bg-white/10 dark:hover:text-white")}
        onClick={() => onDismiss(attack.toastId)}
      >
        ×
      </button>
    </article>;
}

export default function AttackToastStack({ attacks, onOpen, onDismiss }) {
  if (!attacks.length) return null;

  return <aside
      className={twc("pointer-events-none fixed right-4 top-[86px] z-[90] flex w-[min(390px,calc(100vw-32px))] flex-col gap-3 max-[640px]:right-3 max-[640px]:top-[74px] max-[640px]:w-[calc(100vw-24px)]")}
      aria-live="assertive"
      aria-label="실시간 공격 알림"
    >
      {attacks.map(attack => <AttackToast key={attack.toastId} attack={attack} onOpen={onOpen} onDismiss={onDismiss} />)}
    </aside>;
}
