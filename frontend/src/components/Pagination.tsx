type Props = {
  page: number
  pages: number
  total: number
  pageSize: number
  onPage: (p: number) => void
}

export default function Pagination({ page, pages, total, pageSize, onPage }: Props) {
  if (pages <= 1) return null
  const start = (page - 1) * pageSize + 1
  const end = Math.min(page * pageSize, total)
  return (
    <div className="pagination">
      <span className="pagination-info">
        {start}–{end} of {total}
      </span>
      <div className="pagination-controls">
        <button
          className="page-btn"
          onClick={() => onPage(1)}
          disabled={page <= 1}
          title="First page"
        >
          «
        </button>
        <button
          className="page-btn"
          onClick={() => onPage(page - 1)}
          disabled={page <= 1}
          title="Previous page"
        >
          ‹
        </button>
        <span className="page-current">
          {page} / {pages}
        </span>
        <button
          className="page-btn"
          onClick={() => onPage(page + 1)}
          disabled={page >= pages}
          title="Next page"
        >
          ›
        </button>
        <button
          className="page-btn"
          onClick={() => onPage(pages)}
          disabled={page >= pages}
          title="Last page"
        >
          »
        </button>
      </div>
    </div>
  )
}
