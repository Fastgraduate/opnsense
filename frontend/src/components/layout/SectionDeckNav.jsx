import { twc } from "../../lib/twc";

export default function SectionDeckNav({
  section,
  currentPage,
  onMove,
  onSelect
}) {
  const currentIndex = Math.max(0, section.pages.findIndex(page => page.id === currentPage));
  const current = section.pages[currentIndex];

  return <header className={twc("section-deck-toolbar liquid-control-island")}> 
      <div className={twc("deck-current-view")} aria-live="polite">
        <small>{section.eyebrow} {currentIndex + 1} / {section.pages.length}</small>
        <strong>{current.label}</strong>
      </div>

      <div className={twc("deck-dots")} role="tablist" aria-label={`${section.label} 화면 선택`}>
        {section.pages.map((page, index) => <button
          key={page.id}
          type="button"
          role="tab"
          aria-selected={page.id === currentPage}
          aria-label={`${index + 1}. ${page.label}`}
          className={twc(page.id === currentPage ? 'active' : '')}
          onClick={() => onSelect(page.id, index)}
        />)}
      </div>

      <div className={twc("deck-arrow-controls")}>
        <button type="button" onClick={() => onMove(-1)} aria-label="이전 세부 화면">‹</button>
        <button type="button" onClick={() => onMove(1)} aria-label="다음 세부 화면">›</button>
      </div>
    </header>;
}
