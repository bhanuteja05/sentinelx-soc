export default function ErrorBanner({ message }: { message: string }) {
  return (
    <div className="error-banner" role="alert">
      <span className="error-banner-icon">⚠</span>
      {message}
    </div>
  )
}
