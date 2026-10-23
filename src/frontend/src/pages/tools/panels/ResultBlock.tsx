export function ResultBlock({ value }: { value: unknown }) {
  if (value === null || value === undefined) return null
  return (
    <pre className="mt-3 max-h-80 overflow-auto rounded-md border bg-muted/40 p-3 text-xs whitespace-pre-wrap break-all">
      {typeof value === 'string' ? value : JSON.stringify(value, null, 2)}
    </pre>
  )
}
