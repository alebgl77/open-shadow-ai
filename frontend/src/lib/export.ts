export function csvCell(value: unknown): string {
  const text = String(value ?? '')
  // Mirror the API's formula and control prefixes, including full-width variants.
  return `"${(/^[=+@\-\t\r\n\uff1d\uff0b\uff0d\uff20]/.test(text) ? "'" + text : text).replaceAll('"', '""')}"`
}
export function downloadBlob(blob: Blob, filename: string) {
  const url = URL.createObjectURL(blob)
  const link = document.createElement('a'); link.href = url; link.download = filename; link.click()
  setTimeout(()=>URL.revokeObjectURL(url), 1000)
}
export function downloadCsv(rows: unknown[][], filename: string) {
  downloadBlob(new Blob([rows.map(row=>row.map(csvCell).join(',')).join('\r\n')], { type: 'text/csv;charset=utf-8;' }), filename)
}
