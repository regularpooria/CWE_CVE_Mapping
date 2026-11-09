import "./styles.css";
import {
  BEAM,
  INDEX_VERSION,
  MAX_LENGTH,
  MODEL_DTYPE,
  MODEL_ID,
  MODEL_REVISION,
} from "./config.js";
import { buildCweIndex, cweLabel } from "./cwe.js";
import { dbClear, dbGet, dbPut } from "./db.js";
import {
  buildExportRows,
  detectColumns,
  downloadCsv,
  getCell,
  parseCsvFile,
  parseCsvText,
} from "./csv.js";
import { rankCwes } from "./match.js";
import { ModelClient } from "./modelClient.js";

const CWE_JSON_URL = new URL("data/CWE_SOFTWARE.json", document.baseURI).href;
const CWE_INDEX_URL = new URL("data/cwe_index.json", document.baseURI).href;
const SAMPLE_CSV_URL = new URL("data/sample_cves.csv", document.baseURI).href;
const MODEL_ROOT_URL = new URL("", document.baseURI).href;
const INDEX_BATCH = 16;
const MAP_BATCH = 8;
const EXAMPLE_TEXT =
  "The product does not neutralize special elements used in an SQL command, allowing an attacker to inject SQL and execute arbitrary database queries.";

const $ = (id) => document.getElementById(id);

const els = {
  statusCard: $("status-card"),
  statusLabel: $("status-label"),
  statusDetail: $("status-detail"),
  statusPercent: $("status-percent"),
  progressTrack: $("progress-track"),
  progressBar: $("progress-bar"),
  cacheNote: $("cache-note"),
  retryModel: $("retry-model"),
  rebuildIndex: $("rebuild-index"),
  errorBanner: $("error-banner"),
  cweCounts: $("cwe-counts"),
  textQuery: $("text-query"),
  textTopK: $("text-top-k"),
  textSearchButton: $("text-search-button"),
  textStatus: $("text-status"),
  textResults: $("text-results"),
  textExample: $("text-example"),
  dropZone: $("drop-zone"),
  fileInput: $("file-input"),
  browseButton: $("browse-button"),
  sampleButton: $("sample-button"),
  fileMeta: $("file-meta"),
  columnControls: $("column-controls"),
  descriptionColumn: $("description-column"),
  idColumn: $("id-column"),
  previewWrap: $("preview-wrap"),
  previewTable: $("preview-table"),
  topK: $("top-k"),
  mapButton: $("map-button"),
  cancelButton: $("cancel-button"),
  mapStatus: $("map-status"),
  resultsCard: $("results-card"),
  resultsSummary: $("results-summary"),
  resultsBody: $("results-body"),
  resultsTable: $("results-table"),
  idHeader: $("id-header"),
  exportButton: $("export-button"),
  clearResults: $("clear-results"),
};

const state = {
  cwe: null,
  cweHash: "",
  vectors: null,
  modelClient: null,
  modelReady: false,
  modelLoading: false,
  indexReady: false,
  indexBuilding: false,
  indexSource: null,
  csv: null,
  results: [],
  isMapping: false,
  cancelRequested: false,
  textSearching: false,
  textMessage: "",
  modelFiles: new Map(),
};

function escapeHtml(value) {
  return String(value ?? "").replace(/[&<>"']/g, (character) => {
    switch (character) {
      case "&":
        return "&amp;";
      case "<":
        return "&lt;";
      case ">":
        return "&gt;";
      case '"':
        return "&quot;";
      default:
        return "&#39;";
    }
  });
}

function formatScore(score) {
  return Number.isFinite(score) ? score.toFixed(3) : "—";
}

function formatBytes(bytes) {
  if (!Number.isFinite(bytes) || bytes <= 0) return "0 B";
  const units = ["B", "KB", "MB", "GB"];
  const exponent = Math.min(Math.floor(Math.log(bytes) / Math.log(1024)), units.length - 1);
  const value = bytes / 1024 ** exponent;
  return `${value >= 10 || exponent === 0 ? value.toFixed(0) : value.toFixed(1)} ${units[exponent]}`;
}

function hashString(text) {
  let hash = 2166136261;
  for (let i = 0; i < text.length; i += 1) {
    hash ^= text.charCodeAt(i);
    hash = Math.imul(hash, 16777619);
  }
  return (hash >>> 0).toString(16);
}

function arraysEqual(a, b) {
  if (!a || !b || a.length !== b.length) return false;
  for (let i = 0; i < a.length; i += 1) {
    if (String(a[i]) !== String(b[i])) return false;
  }
  return true;
}

function setProgress({ label, detail = "", percent = null, status = "loading" }) {
  els.statusLabel.textContent = label;
  els.statusDetail.textContent = detail;
  els.statusPercent.textContent = percent === null ? "" : `${Math.round(percent)}%`;
  els.progressBar.style.width = percent === null ? "" : `${Math.max(0, Math.min(100, percent))}%`;
  els.progressTrack.classList.toggle("indeterminate", percent === null);
  els.statusCard.dataset.status = status;
}

function showError(message) {
  els.errorBanner.textContent = message;
  els.errorBanner.hidden = false;
}

function clearError() {
  els.errorBanner.textContent = "";
  els.errorBanner.hidden = true;
}

function setCacheNote(text) {
  els.cacheNote.textContent = text;
}

function updateControls() {
  const hasCsv = Boolean(state.csv?.rows?.length);
  const canMap =
    state.modelReady &&
    state.indexReady &&
    hasCsv &&
    Boolean(els.descriptionColumn.value) &&
    !state.isMapping &&
    !state.textSearching;
  const canSearchText =
    state.modelReady &&
    state.indexReady &&
    Boolean(els.textQuery.value.trim()) &&
    !state.isMapping &&
    !state.textSearching;

  els.mapButton.disabled = !canMap;
  els.mapButton.textContent = state.isMapping ? "Mapping…" : "Map CVE descriptions";
  els.cancelButton.hidden = !state.isMapping;
  if (!state.isMapping) {
    els.cancelButton.disabled = false;
    els.cancelButton.textContent = "Cancel";
  }
  els.textSearchButton.disabled = !canSearchText;
  els.textSearchButton.textContent = state.textSearching
    ? "Searching…"
    : "Find closest CWE descriptions";
  els.textQuery.disabled = state.textSearching;
  els.textTopK.disabled = state.textSearching || state.isMapping;
  els.textExample.disabled = state.textSearching;
  els.exportButton.disabled = state.results.length === 0 || state.isMapping;
  els.clearResults.disabled = state.results.length === 0 || state.isMapping;
  els.rebuildIndex.disabled =
    state.modelLoading || state.indexBuilding || state.isMapping || state.textSearching;
  els.topK.disabled = state.isMapping || state.textSearching;
  els.descriptionColumn.disabled = state.isMapping || state.textSearching;
  els.idColumn.disabled = state.isMapping || state.textSearching;
  els.fileInput.disabled = state.isMapping || state.textSearching;
  els.browseButton.disabled = state.isMapping || state.textSearching;
  els.sampleButton.disabled = state.isMapping || state.textSearching;
  els.retryModel.hidden = !(els.statusCard.dataset.status === "error");

  if (!state.cwe) {
    els.mapStatus.textContent = "Loading the CWE taxonomy…";
  } else if (!state.modelReady) {
    els.mapStatus.textContent = state.modelLoading
      ? "Waiting for the model to load…"
      : "The model is not ready.";
  } else if (!state.indexReady) {
    els.mapStatus.textContent = state.indexBuilding
      ? "Preparing the CWE index in your browser…"
      : "Preparing the CWE index…";
  } else if (!hasCsv) {
    els.mapStatus.textContent = "Choose a CSV file to get started.";
  } else {
    els.mapStatus.textContent = `Ready to map ${state.csv.rows.length.toLocaleString()} row${
      state.csv.rows.length === 1 ? "" : "s"
    }.`;
  }

  if (state.textSearching) {
    els.textStatus.textContent = "Embedding the text and ranking CWE definitions…";
  } else if (!state.cwe) {
    els.textStatus.textContent = "Loading the CWE taxonomy…";
  } else if (!state.modelReady) {
    els.textStatus.textContent = state.modelLoading
      ? "Waiting for the model to load…"
      : "The model is not ready.";
  } else if (!state.indexReady) {
    els.textStatus.textContent = state.indexBuilding
      ? "Preparing the CWE index in your browser…"
      : "Preparing the CWE index…";
  } else if (state.textMessage) {
    els.textStatus.textContent = state.textMessage;
  } else {
    els.textStatus.textContent = "Type a description to search the CWE definitions.";
  }
}

async function loadCweData() {
  setProgress({
    label: "Loading CWE taxonomy",
    detail: "Reading CWE_SOFTWARE.json…",
    percent: 5,
    status: "loading",
  });
  const response = await fetch(CWE_JSON_URL, { cache: "no-cache" });
  if (!response.ok) {
    throw new Error(`Could not load CWE_SOFTWARE.json (HTTP ${response.status}).`);
  }
  const text = await response.text();
  const data = JSON.parse(text);
  state.cweHash = hashString(text);
  state.cwe = buildCweIndex(data);
  els.cweCounts.textContent = `${state.cwe.categories.length} categories · ${state.cwe.children.length} child CWEs`;
  setProgress({
    label: "CWE taxonomy loaded",
    detail: `${state.cwe.categories.length} categories and ${state.cwe.children.length} child CWEs.`,
    percent: 100,
    status: "loading",
  });
}

function cacheKey() {
  return `${MODEL_ID}@${MODEL_REVISION}:${MODEL_DTYPE}:${MAX_LENGTH}:v${INDEX_VERSION}:${state.cweHash}`;
}

function isValidCachedIndex(cached) {
  return Boolean(
    cached &&
      cached.version === INDEX_VERSION &&
      cached.modelId === MODEL_ID &&
      cached.revision === MODEL_REVISION &&
      cached.dtype === MODEL_DTYPE &&
      cached.maxLength === MAX_LENGTH &&
      cached.cweHash === state.cweHash &&
      cached.dim > 0 &&
      cached.categoryVectors instanceof Float32Array &&
      cached.childVectors instanceof Float32Array &&
      arraysEqual(cached.categoryIds, state.cwe.categoryIds) &&
      arraysEqual(cached.childIds, state.cwe.childIds) &&
      cached.categoryVectors.length === cached.categoryIds.length * cached.dim &&
      cached.childVectors.length === cached.childIds.length * cached.dim,
  );
}

function decodeFloat32Base64(base64, expectedLength) {
  const binary = atob(base64);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i += 1) {
    bytes[i] = binary.charCodeAt(i);
  }
  const vectors = new Float32Array(bytes.buffer);
  if (vectors.length !== expectedLength) {
    throw new Error(
      `Precomputed vector length mismatch: expected ${expectedLength}, got ${vectors.length}.`,
    );
  }
  return vectors;
}

async function loadPrecomputedIndex() {
  const response = await fetch(CWE_INDEX_URL, { cache: "no-cache" });
  if (!response.ok) {
    if (response.status === 404) return null;
    throw new Error(`Could not load the precomputed CWE index (HTTP ${response.status}).`);
  }

  const data = await response.json();
  const valid =
    data &&
    data.version === INDEX_VERSION &&
    data.modelId === MODEL_ID &&
    data.revision === MODEL_REVISION &&
    data.dtype === MODEL_DTYPE &&
    data.maxLength === MAX_LENGTH &&
    data.cweHash === state.cweHash &&
    data.dim > 0 &&
    Array.isArray(data.categoryIds) &&
    Array.isArray(data.childIds) &&
    typeof data.categoryVectors === "string" &&
    typeof data.childVectors === "string" &&
    arraysEqual(data.categoryIds, state.cwe.categoryIds) &&
    arraysEqual(data.childIds, state.cwe.childIds);

  if (!valid) {
    console.warn("Precomputed CWE index is stale or malformed; recomputing in the browser.");
    return null;
  }

  return {
    version: data.version,
    modelId: data.modelId,
    revision: data.revision,
    dtype: data.dtype,
    maxLength: data.maxLength,
    cweHash: data.cweHash,
    dim: data.dim,
    categoryIds: data.categoryIds,
    categoryVectors: decodeFloat32Base64(
      data.categoryVectors,
      data.categoryIds.length * data.dim,
    ),
    childIds: data.childIds,
    childVectors: decodeFloat32Base64(data.childVectors, data.childIds.length * data.dim),
  };
}

async function saveIndexToDatabase(vectors, source) {
  try {
    await dbPut(cacheKey(), vectors);
    state.indexSource = "database";
    setCacheNote(
      source === "precomputed"
        ? "CWE index loaded from the precomputed file and saved to the browser database (IndexedDB)."
        : "CWE index saved to the browser database (IndexedDB).",
    );
  } catch (error) {
    state.indexSource = source;
    setCacheNote(
      source === "precomputed"
        ? "CWE index loaded from the precomputed file (IndexedDB is unavailable)."
        : "CWE index is in memory only — IndexedDB could not be written.",
    );
    console.warn("Could not save the CWE index to IndexedDB:", error);
  }
}

async function embedAll(texts, { label, offset, total }) {
  const chunks = [];
  let dim = 0;

  for (let start = 0; start < texts.length; start += INDEX_BATCH) {
    const batch = texts.slice(start, start + INDEX_BATCH);
    const output = await state.modelClient.embed(batch);
    dim = output.dims[1];
    chunks.push(output.data);

    const done = Math.min(start + INDEX_BATCH, texts.length);
    setProgress({
      label,
      detail: `${done.toLocaleString()} / ${texts.length.toLocaleString()} texts`,
      percent: ((offset + done) / total) * 100,
      status: "loading",
    });
    await new Promise((resolve) => setTimeout(resolve, 0));
  }

  const data = new Float32Array(texts.length * dim);
  let cursor = 0;
  for (const chunk of chunks) {
    data.set(chunk, cursor);
    cursor += chunk.length;
  }
  return { data, dim };
}

async function computeIndex() {
  const total = state.cwe.categoryTexts.length + state.cwe.childTexts.length;

  const categories = await embedAll(state.cwe.categoryTexts, {
    label: "Embedding CWE categories",
    offset: 0,
    total,
  });
  const children = await embedAll(state.cwe.childTexts, {
    label: "Embedding CWE definitions",
    offset: state.cwe.categoryTexts.length,
    total,
  });

  const vectors = {
    version: INDEX_VERSION,
    modelId: MODEL_ID,
    revision: MODEL_REVISION,
    dtype: MODEL_DTYPE,
    maxLength: MAX_LENGTH,
    cweHash: state.cweHash,
    dim: categories.dim,
    categoryIds: [...state.cwe.categoryIds],
    categoryVectors: categories.data,
    childIds: [...state.cwe.childIds],
    childVectors: children.data,
  };

  await saveIndexToDatabase(vectors, "computed");
  return vectors;
}

async function prepareIndex() {
  if (!state.cwe || !state.modelReady || state.indexBuilding) return;
  state.indexBuilding = true;
  state.indexReady = false;
  state.vectors = null;
  updateControls();

  try {
    let cached = null;
    try {
      cached = await dbGet(cacheKey());
    } catch (error) {
      console.warn("Could not read the CWE index from IndexedDB:", error);
    }

    if (isValidCachedIndex(cached)) {
      state.vectors = cached;
      state.indexSource = "database";
      setCacheNote("CWE index loaded from the browser database (IndexedDB).");
      setProgress({
        label: "CWE index ready",
        detail: "Loaded the cached vectors from your browser database.",
        percent: 100,
        status: "ready",
      });
    } else {
      let precomputed = null;
      try {
        precomputed = await loadPrecomputedIndex();
      } catch (error) {
        console.warn("Could not use the precomputed CWE index:", error);
      }

      if (precomputed) {
        state.vectors = precomputed;
        await saveIndexToDatabase(precomputed, "precomputed");
        setProgress({
          label: "CWE index ready",
          detail: "Loaded the precomputed CWE vectors and cached them in your browser.",
          percent: 100,
          status: "ready",
        });
      } else {
        setCacheNote("Computing the CWE index in your browser…");
        setProgress({
          label: "Preparing CWE index",
          detail: "Embedding the CWE taxonomy in your browser…",
          percent: 0,
          status: "loading",
        });
        state.vectors = await computeIndex();
        setProgress({
          label: "CWE index ready",
          detail: "The CWE taxonomy is embedded and ready.",
          percent: 100,
          status: "ready",
        });
      }
    }

    state.indexReady = true;
  } catch (error) {
    state.indexReady = false;
    console.error("Could not prepare the CWE index", error);
    setProgress({
      label: "Could not prepare the CWE index",
      detail: error.message,
      percent: null,
      status: "error",
    });
    showError(`Could not prepare the CWE index: ${error.message}`);
  } finally {
    state.indexBuilding = false;
    updateControls();
  }
}

function handleModelProgress(progress) {
  if (progress.status === "initiate") {
    setProgress({
      label: "Loading HiCWE-MiniLM-L12",
      detail: progress.file ? `Preparing ${progress.file}…` : "Preparing the model…",
      percent: 0,
      status: "loading",
    });
    return;
  }

  if (progress.status === "progress") {
    const file = progress.file ?? "model";
    state.modelFiles.set(file, {
      loaded: progress.loaded ?? 0,
      total: progress.total ?? 0,
      progress: progress.progress ?? 0,
    });

    const files = [...state.modelFiles.values()];
    const totalBytes = files.reduce((sum, item) => sum + item.total, 0);
    const loadedBytes = files.reduce((sum, item) => sum + item.loaded, 0);
    const percent = totalBytes > 0
      ? (loadedBytes / totalBytes) * 100
      : files.reduce((sum, item) => sum + item.progress, 0) / files.length;

    setProgress({
      label: "Loading model files",
      detail: totalBytes > 0
        ? `${shortFileName(file)} · ${formatBytes(loadedBytes)} / ${formatBytes(totalBytes)}`
        : shortFileName(file),
      percent,
      status: "loading",
    });
    return;
  }

  if (progress.status === "done") {
    setProgress({
      label: "Loading model",
      detail: "Initialising the ONNX runtime…",
      percent: 100,
      status: "loading",
    });
  }
}

function shortFileName(file) {
  return String(file).replace(/^onnx\//, "").replace(/^.*\//, "");
}

async function initModel() {
  if (state.modelLoading) return;
  state.modelLoading = true;
  state.modelReady = false;
  state.indexReady = false;
  state.modelFiles.clear();
  clearError();
  setProgress({
    label: "Loading HiCWE-MiniLM-L12",
    detail: "Opening the local model files…",
    percent: 0,
    status: "loading",
  });
  updateControls();

  if (state.modelClient) state.modelClient.terminate();
  state.modelClient = new ModelClient({
    onProgress: handleModelProgress,
    onWorkerError: (error) => {
      showError(`The model worker reported an error: ${error.message}`);
    },
  });

  try {
    await state.modelClient.load(MODEL_ROOT_URL);
    state.modelReady = true;
    setProgress({
      label: "Model ready",
      detail: "HiCWE-MiniLM-L12 is loaded. Preparing the CWE index…",
      percent: 100,
      status: "ready",
    });
    updateControls();
    await prepareIndex();
  } catch (error) {
    state.modelReady = false;
    console.error("Could not load the model", error);
    setProgress({
      label: "Model failed to load",
      detail: error.message,
      percent: null,
      status: "error",
    });
    showError(`Could not load the model: ${error.message}`);
  } finally {
    state.modelLoading = false;
    updateControls();
  }
}

function renderColumnOptions(parsed) {
  const detected = detectColumns(parsed.headers, parsed.rows);
  const descriptionValue = detected.descriptionColumn ?? parsed.headers[0];

  els.descriptionColumn.innerHTML = parsed.headers
    .map((header) => `<option value="${escapeHtml(header)}">${escapeHtml(header)}</option>`)
    .join("");
  els.descriptionColumn.value = descriptionValue;

  els.idColumn.innerHTML =
    '<option value="">— none —</option>' +
    parsed.headers
      .map((header) => `<option value="${escapeHtml(header)}">${escapeHtml(header)}</option>`)
      .join("");
  els.idColumn.value = detected.idColumn ?? "";
}

function renderPreview() {
  if (!state.csv) {
    els.previewWrap.hidden = true;
    return;
  }

  const descriptionColumn = els.descriptionColumn.value;
  const previewRows = state.csv.rows.slice(0, 4);
  const headers = state.csv.headers;

  const headerCells = headers
    .map(
      (header) =>
        `<th class="${header === descriptionColumn ? "selected-column" : ""}">${escapeHtml(
          header,
        )}</th>`,
    )
    .join("");

  const bodyRows = previewRows
    .map(
      (row, index) => `
        <tr>
          <th scope="row">${index + 1}</th>
          ${headers
            .map(
              (header) =>
                `<td class="${header === descriptionColumn ? "selected-column" : ""}">${escapeHtml(
                  getCell(row, header),
                )}</td>`,
            )
            .join("")}
        </tr>`,
    )
    .join("");

  els.previewTable.innerHTML = `
    <thead><tr><th scope="col">#</th>${headerCells}</tr></thead>
    <tbody>${bodyRows}</tbody>
  `;
  els.previewWrap.hidden = false;
}

function setCsv(parsed) {
  state.csv = parsed;
  state.results = [];
  els.resultsBody.innerHTML = "";
  els.resultsCard.hidden = true;
  els.exportButton.disabled = true;
  els.clearResults.disabled = true;
  els.fileMeta.textContent = `${parsed.fileName} · ${parsed.rows.length.toLocaleString()} rows · ${parsed.headers.length} columns`;
  els.columnControls.hidden = false;
  renderColumnOptions(parsed);
  els.resultsTable.classList.toggle("has-id", Boolean(els.idColumn.value));
  els.idHeader.hidden = !els.idColumn.value;
  renderPreview();
  clearError();
  updateControls();
}

async function handleFile(file) {
  if (!file) return;
  clearError();
  try {
    const parsed = await parseCsvFile(file);
    setCsv(parsed);
  } catch (error) {
    showError(`Could not read the CSV: ${error.message}`);
  }
}

async function loadSample() {
  clearError();
  try {
    const response = await fetch(SAMPLE_CSV_URL, { cache: "no-cache" });
    if (!response.ok) throw new Error(`HTTP ${response.status}`);
    const text = await response.text();
    setCsv(parseCsvText(text, "sample_cves.csv"));
  } catch (error) {
    showError(`Could not load the sample CSV: ${error.message}`);
  }
}

function metaForChild(id) {
  return state.cwe.childrenById.get(String(id)) ?? null;
}

function buildResult(item, ranked) {
  const alternatives = ranked.children.map((child) => {
    const meta = metaForChild(child.id);
    return {
      id: child.id,
      label: cweLabel(child.id),
      title: meta?.title ?? "",
      description: meta?.description ?? "",
      extendedDescription: meta?.extended_description ?? null,
      url: meta?.url ?? "",
      score: child.score,
      categoryId: child.categoryId,
      categoryLabel: child.categoryId ? cweLabel(child.categoryId) : "",
      categoryTitle: child.categoryTitle ?? "",
      categoryScore: child.categoryScore,
    };
  });

  const top = alternatives[0] ?? null;
  return {
    rowNumber: item.rowNumber,
    cveId: item.cveId,
    description: item.description,
    status: "mapped",
    score: top ? top.score : null,
    cwe: top,
    category: top
      ? {
          id: top.categoryId,
          label: top.categoryLabel,
          title: top.categoryTitle,
          score: top.categoryScore,
        }
      : null,
    alternatives,
  };
}

function resultRowHtml(result) {
  if (result.status === "skipped") {
    return `
      <td class="col-index">${result.rowNumber}</td>
      <td class="col-id">${escapeHtml(result.cveId)}</td>
      <td class="col-description"><span class="empty-value">No description</span></td>
      <td class="col-cwe"><span class="skipped-label">Skipped</span></td>
      <td class="col-score">—</td>
      <td class="col-category">—</td>
      <td class="col-details"><span class="muted">${escapeHtml(result.reason ?? "Empty row")}</span></td>
    `;
  }

  const top = result.cwe;
  const topUrl = top?.url ?? "#";
  const alternatives = result.alternatives ?? [];
  const score = result.score;
  const scoreWidth = Number.isFinite(score)
    ? Math.max(0, Math.min(100, score * 100))
    : 0;

  const alternativeItems = alternatives
    .map(
      (alternative, index) => `
        <li>
          <div class="alt-head">
            <span class="alt-rank">#${index + 1}</span>
            <a href="${escapeHtml(alternative.url)}" target="_blank" rel="noopener noreferrer">${escapeHtml(
              alternative.label,
            )}</a>
            <span class="alt-score">${formatScore(alternative.score)}</span>
          </div>
          <div class="alt-title">${escapeHtml(alternative.title)}</div>
          <p class="alt-description">${escapeHtml(alternative.description || "No short description.")}</p>
          ${
            alternative.categoryLabel
              ? `<div class="alt-category">${escapeHtml(alternative.categoryLabel)} · ${escapeHtml(
                  alternative.categoryTitle,
                )}</div>`
              : ""
          }
        </li>`,
    )
    .join("");

  const extended = top?.extendedDescription
    ? `<details class="extended"><summary>Extended CWE description</summary><p>${escapeHtml(
        top.extendedDescription,
      )}</p></details>`
    : "";

  return `
    <td class="col-index">${result.rowNumber}</td>
    <td class="col-id">${escapeHtml(result.cveId)}</td>
    <td class="col-description"><span class="description-clamp">${escapeHtml(result.description)}</span></td>
    <td class="col-cwe">
      <a class="cwe-link" href="${escapeHtml(topUrl)}" target="_blank" rel="noopener noreferrer">${escapeHtml(
        top?.label ?? "—",
      )}</a>
      <span class="cwe-title">${escapeHtml(top?.title ?? "")}</span>
    </td>
    <td class="col-score">
      <span class="score-value">${formatScore(score)}</span>
      <span class="score-bar"><i style="width:${scoreWidth}%"></i></span>
    </td>
    <td class="col-category">
      ${
        result.category
          ? `<span class="category-id">${escapeHtml(result.category.label)}</span><span class="category-title">${escapeHtml(
              result.category.title,
            )}</span>`
          : "—"
      }
    </td>
    <td class="col-details">
      <details>
        <summary>Top ${alternatives.length}</summary>
        <div class="detail-panel">
          <p class="full-description">${escapeHtml(result.description)}</p>
          <ol class="alternatives">${alternativeItems}</ol>
          ${extended}
        </div>
      </details>
    </td>
  `;
}

function appendResultRow(result) {
  const row = document.createElement("tr");
  row.innerHTML = resultRowHtml(result);
  els.resultsBody.appendChild(row);
}

function updateSummary(durationMs) {
  const mapped = state.results.filter((result) => result.status === "mapped").length;
  const skipped = state.results.filter((result) => result.status === "skipped").length;
  const counts = new Map();
  for (const result of state.results) {
    if (result.status !== "mapped" || !result.cwe) continue;
    counts.set(result.cwe.label, (counts.get(result.cwe.label) ?? 0) + 1);
  }
  const topCounts = [...counts.entries()]
    .sort((a, b) => b[1] - a[1])
    .slice(0, 5)
    .map(([label, count]) => `${label} (${count})`)
    .join(" · ");

  els.resultsSummary.innerHTML = `
    <div>
      <strong>${mapped.toLocaleString()}</strong> mapped${
        skipped ? ` · <strong>${skipped.toLocaleString()}</strong> skipped` : ""
      } · ${(durationMs / 1000).toFixed(1)}s
    </div>
    ${topCounts ? `<div class="summary-distribution">Most frequent: ${escapeHtml(topCounts)}</div>` : ""}
  `;
}

function clearResults() {
  state.results = [];
  els.resultsBody.innerHTML = "";
  els.resultsCard.hidden = true;
  els.exportButton.disabled = true;
  els.clearResults.disabled = true;
  updateControls();
}

async function mapRows() {
  if (
    state.isMapping ||
    state.textSearching ||
    !state.modelReady ||
    !state.indexReady ||
    !state.csv
  ) {
    return;
  }

  const descriptionColumn = els.descriptionColumn.value;
  const idColumn = els.idColumn.value;
  if (!descriptionColumn) {
    showError("Choose the CSV column that contains the CVE descriptions.");
    return;
  }

  clearError();
  state.isMapping = true;
  state.cancelRequested = false;
  state.results = [];
  els.resultsBody.innerHTML = "";
  els.resultsCard.hidden = false;
  els.resultsSummary.textContent = "Mapping…";
  updateControls();

  const rows = state.csv.rows;
  const topK = Number(els.topK.value);
  const started = performance.now();
  let failed = false;

  try {
    for (let start = 0; start < rows.length; start += MAP_BATCH) {
      if (state.cancelRequested) break;

      const chunk = rows.slice(start, start + MAP_BATCH);
      const items = chunk.map((row, offset) => ({
        rowNumber: start + offset + 1,
        cveId: idColumn ? getCell(row, idColumn).trim() : "",
        description: getCell(row, descriptionColumn).trim(),
        chunkIndex: offset,
      }));

      const valid = items.filter((item) => item.description !== "");
      let vectors = null;
      let dim = 0;

      if (valid.length) {
        const output = await state.modelClient.embed(valid.map((item) => item.description));
        vectors = output.data;
        dim = output.dims[1];
      }

      for (const item of items) {
        if (!item.description) {
          const result = {
            rowNumber: item.rowNumber,
            cveId: item.cveId,
            description: "",
            status: "skipped",
            reason: "Empty description",
            score: null,
            cwe: null,
            category: null,
            alternatives: [],
          };
          state.results.push(result);
          appendResultRow(result);
          continue;
        }

        const vectorIndex = valid.findIndex((candidate) => candidate.chunkIndex === item.chunkIndex);
        const query = vectors.subarray(vectorIndex * dim, (vectorIndex + 1) * dim);
        const ranked = rankCwes(query, state.cwe, state.vectors, { topK, beam: BEAM });
        const result = buildResult(item, ranked);
        state.results.push(result);
        appendResultRow(result);
      }

      const done = Math.min(start + MAP_BATCH, rows.length);
      setProgress({
        label: "Mapping CVE descriptions",
        detail: `${done.toLocaleString()} / ${rows.length.toLocaleString()} rows`,
        percent: (done / rows.length) * 100,
        status: "mapping",
      });
      await new Promise((resolve) => setTimeout(resolve, 0));
    }
  } catch (error) {
    failed = true;
    showError(`Mapping stopped: ${error.message}`);
    setProgress({
      label: "Mapping failed",
      detail: error.message,
      percent: null,
      status: "error",
    });
  } finally {
    const cancelled = state.cancelRequested;
    state.isMapping = false;
    state.cancelRequested = false;
    updateControls();
    updateSummary(performance.now() - started);

    if (!failed) {
      setProgress({
        label: cancelled ? "Mapping cancelled" : "Mapping complete",
        detail: `${state.results.length.toLocaleString()} of ${rows.length.toLocaleString()} rows processed.`,
        percent: cancelled ? null : 100,
        status: cancelled ? "loading" : "ready",
      });
    }
  }
}

function renderTextResults(text, ranked) {
  const items = ranked.children.map((child, index) => {
    const meta = metaForChild(child.id);
    return {
      rank: index + 1,
      label: cweLabel(child.id),
      title: meta?.title ?? "",
      description: meta?.description ?? "",
      extended: meta?.extended_description ?? null,
      url: meta?.url ?? "#",
      score: child.score,
      categoryLabel: child.categoryId ? cweLabel(child.categoryId) : "",
      categoryTitle: child.categoryTitle ?? "",
    };
  });

  if (!items.length) {
    els.textResults.innerHTML = '<p class="muted">No CWE definitions matched that text.</p>';
    els.textResults.hidden = false;
    return;
  }

  const cards = items
    .map((item) => {
      const scoreWidth = Number.isFinite(item.score)
        ? Math.max(0, Math.min(100, item.score * 100))
        : 0;
      return `
        <li class="text-result">
          <div class="text-result-head">
            <span class="text-rank">#${item.rank}</span>
            <a href="${escapeHtml(item.url)}" target="_blank" rel="noopener noreferrer">${escapeHtml(
              item.label,
            )}</a>
            <span class="text-result-score">${formatScore(item.score)}</span>
          </div>
          <div class="text-result-title">${escapeHtml(item.title)}</div>
          <div class="text-score-bar"><i style="width:${scoreWidth}%"></i></div>
          <p class="text-result-description">${escapeHtml(
            item.description || "No short description.",
          )}</p>
          ${
            item.categoryLabel
              ? `<div class="text-result-meta">${escapeHtml(item.categoryLabel)} · ${escapeHtml(
                  item.categoryTitle,
                )}</div>`
              : ""
          }
          ${
            item.extended
              ? `<details class="extended"><summary>Extended CWE description</summary><p>${escapeHtml(
                  item.extended,
                )}</p></details>`
              : ""
          }
        </li>`;
    })
    .join("");

  els.textResults.innerHTML = `
    <div class="text-results-head">
      <div>
        <h3>Closest CWE definitions</h3>
        <p class="text-query-preview">${escapeHtml(text)}</p>
      </div>
      <span class="muted">${items.length} result${items.length === 1 ? "" : "s"}</span>
    </div>
    <ol class="text-result-list">${cards}</ol>
  `;
  els.textResults.hidden = false;
}

async function runTextSearch() {
  const text = els.textQuery.value.trim();
  if (!text || state.textSearching || !state.modelReady || !state.indexReady) return;

  state.textSearching = true;
  state.textMessage = "";
  els.textResults.hidden = true;
  clearError();
  updateControls();

  try {
    const output = await state.modelClient.embed([text]);
    const dim = output.dims[1];
    const query = output.data.subarray(0, dim);
    const ranked = rankCwes(query, state.cwe, state.vectors, {
      topK: Number(els.textTopK.value),
      // A beam that covers every category turns the hierarchical search into a
      // flat search over all child CWE descriptions.
      beam: state.cwe.categories.length,
    });
    renderTextResults(text, ranked);
    state.textMessage = `Top ${ranked.children.length} closest CWE definition${
      ranked.children.length === 1 ? "" : "s"
    } by cosine similarity.`;
  } catch (error) {
    showError(`Text search failed: ${error.message}`);
    state.textMessage = "Search failed.";
  } finally {
    state.textSearching = false;
    updateControls();
  }
}

async function rebuildIndex() {
  if (
    state.indexBuilding ||
    state.isMapping ||
    state.textSearching ||
    !state.modelReady
  ) {
    return;
  }
  clearError();
  try {
    await dbClear();
  } catch (error) {
    console.warn("Could not clear IndexedDB:", error);
  }
  state.indexReady = false;
  state.vectors = null;
  state.indexSource = null;
  setCacheNote("Rebuilding the CWE index from scratch…");
  await prepareIndex();
}

function wireEvents() {
  els.textQuery.addEventListener("input", () => {
    state.textMessage = "";
    els.textResults.hidden = true;
    updateControls();
  });
  els.textQuery.addEventListener("keydown", (event) => {
    if ((event.metaKey || event.ctrlKey) && event.key === "Enter") {
      event.preventDefault();
      runTextSearch();
    }
  });
  els.textExample.addEventListener("click", () => {
    els.textQuery.value = EXAMPLE_TEXT;
    state.textMessage = "";
    els.textResults.hidden = true;
    updateControls();
    els.textQuery.focus();
  });
  els.textSearchButton.addEventListener("click", runTextSearch);
  els.textTopK.addEventListener("change", () => {
    state.textMessage = "";
    els.textResults.hidden = true;
    updateControls();
  });

  els.fileInput.addEventListener("change", (event) => {
    handleFile(event.target.files?.[0]);
  });

  els.browseButton.addEventListener("click", () => els.fileInput.click());
  els.sampleButton.addEventListener("click", loadSample);

  els.dropZone.addEventListener("dragover", (event) => {
    event.preventDefault();
    els.dropZone.classList.add("dragging");
  });
  els.dropZone.addEventListener("dragleave", () => {
    els.dropZone.classList.remove("dragging");
  });
  els.dropZone.addEventListener("drop", (event) => {
    event.preventDefault();
    els.dropZone.classList.remove("dragging");
    handleFile(event.dataTransfer?.files?.[0]);
  });

  els.descriptionColumn.addEventListener("change", () => {
    renderPreview();
    updateControls();
  });
  els.idColumn.addEventListener("change", () => {
    els.resultsTable.classList.toggle("has-id", Boolean(els.idColumn.value));
    els.idHeader.hidden = !els.idColumn.value;
    updateControls();
  });
  els.topK.addEventListener("change", () => {
    if (state.results.length) {
      els.mapStatus.textContent = "Re-map to apply the new top-k value.";
    }
  });

  els.mapButton.addEventListener("click", mapRows);
  els.cancelButton.addEventListener("click", () => {
    state.cancelRequested = true;
    els.cancelButton.disabled = true;
    els.cancelButton.textContent = "Cancelling…";
  });
  els.exportButton.addEventListener("click", () => {
    const rows = buildExportRows(state.results, Number(els.topK.value));
    const date = new Date().toISOString().slice(0, 10);
    downloadCsv(`cwe_mapping_${date}.csv`, rows);
  });
  els.clearResults.addEventListener("click", clearResults);
  els.retryModel.addEventListener("click", initModel);
  els.rebuildIndex.addEventListener("click", rebuildIndex);
}

async function init() {
  wireEvents();
  els.resultsTable.classList.toggle("has-id", Boolean(els.idColumn.value));
  els.idHeader.hidden = !els.idColumn.value;
  updateControls();
  setProgress({
    label: "Starting",
    detail: "Loading the CWE taxonomy and the HiCWE model…",
    percent: 0,
    status: "loading",
  });

  try {
    await loadCweData();
  } catch (error) {
    showError(error.message);
    setProgress({
      label: "Could not load the CWE taxonomy",
      detail: error.message,
      percent: null,
      status: "error",
    });
    updateControls();
    return;
  }

  await initModel();
}

init();
