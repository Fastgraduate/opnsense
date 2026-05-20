import { useEffect, useMemo, useState } from 'react'

const LOG_PAGE_SIZE = 30

function LogsPage({ logs = [], setLogs }) {
  const [currentPage, setCurrentPage] = useState(1)

  const normalizeLevel = (level) => {
    const value = String(level || 'INFO').toUpperCase()

    if (value === 'ERROR') return 'ERROR'
    if (value === 'WARN' || value === 'WARNING') return 'WARN'
    if (value === 'SUCCESS') return 'SUCCESS'

    return 'INFO'
  }

  const getLevelLabel = (level) => {
    const value = normalizeLevel(level)

    if (value === 'ERROR') return 'ERROR'
    if (value === 'WARN') return 'WARN'
    if (value === 'SUCCESS') return 'SUCCESS'

    return 'INFO'
  }

  const totalPages = Math.max(1, Math.ceil(logs.length / LOG_PAGE_SIZE))

  const pagedLogs = useMemo(() => {
    const safePage = Math.min(currentPage, totalPages)
    const start = (safePage - 1) * LOG_PAGE_SIZE

    return logs.slice(start, start + LOG_PAGE_SIZE)
  }, [logs, currentPage, totalPages])

  useEffect(() => {
    if (currentPage > totalPages) {
      setCurrentPage(totalPages)
    }
  }, [currentPage, totalPages])

  useEffect(() => {
    setCurrentPage(1)
  }, [logs.length])

  const handleClearLogs = () => {
    setLogs([])
    setCurrentPage(1)
  }

  const pageNumbers = Array.from(
    { length: totalPages },
    (_, index) => index + 1,
  ).filter((page) => {
    if (totalPages <= 7) return true
    if (page === 1 || page === totalPages) return true
    return Math.abs(page - currentPage) <= 2
  })

  return (
    <div className="app-logs-page">
      <section className="app-logs-panel">
        <div className="app-logs-header">
          <div>
            <p className="app-logs-eyebrow">Application Logs</p>
            <h2>앱 로그</h2>
            <span>
              대시보드 동작, 방화벽 요청, 오류 발생 내역을 확인합니다.
            </span>
          </div>

          <div className="app-logs-header-actions">
            <div className="app-logs-count-chip">총 {logs.length}개</div>

            <button
              type="button"
              className="app-logs-clear-btn"
              onClick={handleClearLogs}
              disabled={logs.length === 0}
            >
              로그 비우기
            </button>
          </div>
        </div>

        {logs.length === 0 ? (
          <div className="app-logs-empty">
            <div className="app-logs-empty-icon">L</div>
            <h3>로그가 없습니다.</h3>
            <p>앱에서 발생한 이벤트가 있으면 이곳에 표시됩니다.</p>
          </div>
        ) : (
          <>
            <div className="app-logs-list">
              {pagedLogs.map((log) => {
                const level = normalizeLevel(log.level)

                return (
                  <article className="app-log-item" key={log.id}>
                    <div className={`app-log-badge ${level.toLowerCase()}`}>
                      {getLevelLabel(level)}
                    </div>

                    <div className="app-log-content">
                      <div className="app-log-message">{log.message}</div>
                      <div className="app-log-time">{log.time}</div>
                    </div>
                  </article>
                )
              })}
            </div>

            <div className="app-logs-footer">
              <div className="app-logs-page-info">
                페이지당 {LOG_PAGE_SIZE}개 표시 / {currentPage} / {totalPages}{' '}
                페이지
              </div>

              <div className="app-logs-pagination">
                <button
                  type="button"
                  onClick={() => setCurrentPage(1)}
                  disabled={currentPage === 1}
                >
                  처음
                </button>

                <button
                  type="button"
                  onClick={() =>
                    setCurrentPage((prev) => Math.max(1, prev - 1))
                  }
                  disabled={currentPage === 1}
                >
                  이전
                </button>

                {pageNumbers.map((page, index, arr) => {
                  const prevPage = arr[index - 1]
                  const showEllipsis = prevPage && page - prevPage > 1

                  return (
                    <span key={page} className="app-logs-page-group">
                      {showEllipsis ? (
                        <span className="app-logs-ellipsis">...</span>
                      ) : null}

                      <button
                        type="button"
                        className={currentPage === page ? 'active' : ''}
                        onClick={() => setCurrentPage(page)}
                        disabled={currentPage === page}
                      >
                        {page}
                      </button>
                    </span>
                  )
                })}

                <button
                  type="button"
                  onClick={() =>
                    setCurrentPage((prev) => Math.min(totalPages, prev + 1))
                  }
                  disabled={currentPage === totalPages}
                >
                  다음
                </button>

                <button
                  type="button"
                  onClick={() => setCurrentPage(totalPages)}
                  disabled={currentPage === totalPages}
                >
                  마지막
                </button>
              </div>
            </div>
          </>
        )}
      </section>
    </div>
  )
}

export default LogsPage
