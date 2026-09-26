export function csvCell(value: unknown): string {
  const text = String(value ?? '')
  // Prevent spreadsheet formula execution when exporting untrusted service names.
  return `"${(/^[=+@\-\t\r]/.test(text) ? "'" + text : text).replaceAll('"', '""')}"`
}
export function downloadCsv(rows: unknown[][], filename: string) {
  const blob = new Blob([rows.map(row=>row.map(csvCell).join(',')).join('\r\n')], { type: 'text/csv;charset=utf-8;' })
  const url = URL.createObjectURL(blob)
  const link = document.createElement('a'); link.href = url; link.download = filename; link.click()
  setTimeout(()=>URL.revokeObjectURL(url), 1000)
}
