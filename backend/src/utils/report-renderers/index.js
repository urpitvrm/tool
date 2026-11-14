import { csvCell } from '../csv.js';
import { formatCell } from './format.js';
import { renderPdf } from './pdf.js';
import { renderXlsx } from './xlsx.js';

export const FORMAT_META = {
  pdf: { extension: 'pdf', mime: 'application/pdf' },
  xlsx: { extension: 'xlsx', mime: 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet' },
  csv: { extension: 'csv', mime: 'text/csv; charset=utf-8' },
};

/** CSV holds one table: the detail rows, or the report's primary/first section when it has none. */
export function renderCsv(document) {
  const table = document.details
    || document.sections.find((section) => section.primary)
    || document.sections[0]
    || { columns: [], rows: [] };
  const lines = [
    table.columns.map((column) => csvCell(column.label)).join(','),
    ...table.rows.map((row) => table.columns.map((column) => csvCell(formatCell(row[column.key], document.timezone))).join(',')),
  ];
  return Buffer.from(`﻿${lines.join('\r\n')}\r\n`, 'utf8');
}

export async function renderReport(document, format) {
  if (format === 'pdf') return renderPdf(document);
  if (format === 'xlsx') return renderXlsx(document);
  if (format === 'csv') return renderCsv(document);
  throw Object.assign(new Error(`Unsupported format: ${format}`), { status: 422 });
}
