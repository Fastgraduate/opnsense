export const SECTION_DECKS = [
  {
    id: 'rules',
    eyebrow: 'Firewall policy',
    label: '룰 관리',
    pages: [
      { id: 'rules', label: '전체 룰' },
      { id: 'interfaceRules', label: '인터페이스별 룰' },
    ],
  },
  {
    id: 'security',
    eyebrow: 'Live detections',
    label: '실시간 공격 탐지',
    pages: [
      { id: 'securityAlerts', label: '공격 탐지' },
      { id: 'eventLogIndex', label: '공격 로그 인덱싱' },
      { id: 'eventLogSqlSearch', label: '공격 로그 SQL 검색' },
    ],
  },
  { id: 'blocks', eyebrow: 'Blocked addresses', label: '차단 IP 목록', pages: [
    { id: 'blockedIps', label: '수동 차단 목록' },
    { id: 'automaticBlockedIps', label: '자동 차단 목록' },
  ] },
  {
    id: 'opnsense',
    eyebrow: 'OPNsense logs',
    label: 'OPNsense 로그 파일',
    pages: [
      { id: 'opnsenseLogOverview', label: '장비 로그 개요' },
      { id: 'opnsenseLogs', label: '실시간 로그' },
    ],
  },
]

export const SECTION_DECKS_BY_ID = Object.fromEntries(
  SECTION_DECKS.map((section) => [section.id, section]),
)

export function getSectionForPage(pageId) {
  return SECTION_DECKS.find((section) =>
    section.pages.some((page) => page.id === pageId),
  ) || null
}
