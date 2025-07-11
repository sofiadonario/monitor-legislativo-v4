// Date parsing utility for Brazilian legislative documents
export function parseBrazilianDate(dateStr: string | null | undefined): Date | null {
  if (!dateStr || dateStr.trim() === '') {
    return null;
  }

  // Remove any extra whitespace
  const cleanDate = dateStr.trim();

  // Try different date formats
  const formats = [
    // ISO format: YYYY-MM-DD
    /^(\d{4})-(\d{2})-(\d{2})$/,
    // Brazilian format: DD/MM/YYYY
    /^(\d{2})\/(\d{2})\/(\d{4})$/,
    // Brazilian format with dots: DD.MM.YYYY
    /^(\d{2})\.(\d{2})\.(\d{4})$/,
    // US format: MM/DD/YYYY
    /^(\d{2})\/(\d{2})\/(\d{4})$/,
  ];

  // Try ISO format first
  if (formats[0].test(cleanDate)) {
    const date = new Date(cleanDate);
    if (!isNaN(date.getTime())) {
      return date;
    }
  }

  // Try Brazilian format DD/MM/YYYY
  const brFormat = cleanDate.match(/^(\d{2})\/(\d{2})\/(\d{4})$/);
  if (brFormat) {
    const [_, day, month, year] = brFormat;
    const date = new Date(parseInt(year), parseInt(month) - 1, parseInt(day));
    if (!isNaN(date.getTime())) {
      return date;
    }
  }

  // Try Brazilian format with dots DD.MM.YYYY
  const brDotFormat = cleanDate.match(/^(\d{2})\.(\d{2})\.(\d{4})$/);
  if (brDotFormat) {
    const [_, day, month, year] = brDotFormat;
    const date = new Date(parseInt(year), parseInt(month) - 1, parseInt(day));
    if (!isNaN(date.getTime())) {
      return date;
    }
  }

  // Try parsing with Date constructor as last resort
  const date = new Date(cleanDate);
  if (!isNaN(date.getTime())) {
    return date;
  }

  // Log failed parsing for debugging
  console.warn(`Failed to parse date: "${cleanDate}"`);
  return null;
}

// Format date for display
export function formatDateForDisplay(date: Date | string | null | undefined): string {
  if (!date) {
    return 'Data não disponível';
  }

  let dateObj: Date;
  if (typeof date === 'string') {
    dateObj = parseBrazilianDate(date) || new Date(date);
  } else {
    dateObj = date;
  }

  if (isNaN(dateObj.getTime())) {
    return 'Data inválida';
  }

  // Format as DD/MM/YYYY
  return dateObj.toLocaleDateString('pt-BR');
}

// Get year from date string or Date object
export function getYearFromDate(date: Date | string | null | undefined): number | null {
  if (!date) {
    return null;
  }

  let dateObj: Date;
  if (typeof date === 'string') {
    dateObj = parseBrazilianDate(date) || new Date(date);
  } else {
    dateObj = date;
  }

  if (isNaN(dateObj.getTime())) {
    return null;
  }

  return dateObj.getFullYear();
}