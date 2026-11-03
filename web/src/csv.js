import Papa from "papaparse";

const DESCRIPTION_PATTERNS = [
  /^cve[-_ ]?description([-_ ]?normalized)?$/i,
  /^description$/i,
  /^summary$/i,
  /^details?$/i,
  /^vulnerability[-_ ]?description$/i,
  /^cve[-_ ]?summary$/i,
  /^text$/i,
  /^desc$/i,
];

const ID_PATTERNS = [
  /^cve[-_ ]?id$/i,
  /^cveid$/i,
  /^cve$/i,
  /^id$/i,
  /^identifier$/i,
];

function parseConfig() {
  return {
    header: true,
    skipEmptyLines: "greedy",
    transformHeader: (header) => String(header).replace(/^\uFEFF/, "").trim(),
  };
}

function normaliseResult(result, fileName) {
  const fields = (result.meta?.fields ?? []).filter(
    (field) => field && field !== "__parsed_extra",
  );
  const rows = (result.data ?? []).filter((row) =>
    fields.some((field) => String(row[field] ?? "").trim() !== ""),
  );
  if (!fields.length) {
    throw new Error("No columns were found. Is this a CSV file with a header row?");
  }
  if (!rows.length) {
    throw new Error("The CSV has a header but no data rows.");
  }
  return {
    fileName,
    headers: fields,
    rows,
    errors: result.errors ?? [],
  };
}

export function parseCsvFile(file) {
  return new Promise((resolve, reject) => {
    Papa.parse(file, {
      ...parseConfig(),
      complete: (result) => {
        try {
          resolve(normaliseResult(result, file.name));
        } catch (error) {
          reject(error);
        }
      },
      error: (error) => reject(error),
    });
  });
}

export function parseCsvText(text, fileName = "sample.csv") {
  const result = Papa.parse(text, parseConfig());
  return normaliseResult(result, fileName);
}

function scoreHeader(header, patterns) {
  return patterns.reduce((score, pattern, index) => {
    if (!pattern.test(header)) return score;
    return Math.max(score, 100 - index * 10);
  }, 0);
}

function sampleLength(rows, header) {
  let longest = 0;
  for (let i = 0; i < Math.min(rows.length, 8); i += 1) {
    longest = Math.max(longest, String(rows[i][header] ?? "").length);
  }
  return longest;
}

export function detectColumns(headers, rows) {
  let descriptionColumn = null;
  let descriptionScore = -1;
  let idColumn = null;
  let idScore = -1;

  for (const header of headers) {
    const descScore = scoreHeader(header, DESCRIPTION_PATTERNS) + sampleLength(rows, header) / 1000;
    if (descScore > descriptionScore) {
      descriptionScore = descScore;
      descriptionColumn = header;
    }

    const identifierScore = scoreHeader(header, ID_PATTERNS);
    if (identifierScore > idScore && identifierScore > 0) {
      idScore = identifierScore;
      idColumn = header;
    }
  }

  return { descriptionColumn, idColumn };
}

export function getCell(row, column) {
  if (!column) return "";
  const value = row[column];
  return value === null || value === undefined ? "" : String(value);
}

function formatScore(value) {
  return Number.isFinite(value) ? value.toFixed(4) : "";
}

export function buildExportRows(results, topK) {
  return results.map((result) => {
    const top = result.cwe;
    const row = {
      row: result.rowNumber,
      cve_id: result.cveId ?? "",
      cve_description: result.description ?? "",
      status: result.status,
      predicted_cwe: top ? top.label : "",
      cwe_title: top ? top.title : "",
      cwe_description: top ? top.description : "",
      cwe_extended_description: top ? top.extendedDescription ?? "" : "",
      similarity: result.score !== null && result.score !== undefined
        ? formatScore(result.score)
        : "",
      category: result.category ? result.category.label : "",
      category_title: result.category ? result.category.title : "",
      category_similarity:
        result.category && result.category.score !== null
          ? formatScore(result.category.score)
          : "",
    };

    for (let i = 0; i < topK; i += 1) {
      const alternative = result.alternatives?.[i];
      row[`top_${i + 1}_cwe`] = alternative?.label ?? "";
      row[`top_${i + 1}_title`] = alternative?.title ?? "";
      row[`top_${i + 1}_score`] = alternative ? formatScore(alternative.score) : "";
    }

    row.alternatives_json = JSON.stringify(
      (result.alternatives ?? []).map((alternative) => ({
        cwe: alternative.label,
        title: alternative.title,
        score: Number(formatScore(alternative.score)),
        category: alternative.categoryLabel ?? "",
        url: alternative.url,
      })),
    );
    return row;
  });
}

export function downloadCsv(filename, rows) {
  const csv = Papa.unparse(rows);
  const blob = new Blob(["\uFEFF", csv], { type: "text/csv;charset=utf-8" });
  const url = URL.createObjectURL(blob);
  const anchor = document.createElement("a");
  anchor.href = url;
  anchor.download = filename;
  document.body.appendChild(anchor);
  anchor.click();
  anchor.remove();
  URL.revokeObjectURL(url);
}
