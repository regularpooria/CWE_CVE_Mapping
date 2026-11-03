import { AutoModel, PreTrainedTokenizer, env } from "@huggingface/transformers";
import { MAX_LENGTH, MODEL_DTYPE, MODEL_LOCAL_ID } from "./config.js";

env.allowLocalModels = true;
env.allowRemoteModels = false;
env.useBrowserCache = true;

// GitHub Pages cannot set COOP/COEP, so SharedArrayBuffer is unavailable.
if (env.backends?.onnx?.wasm) {
  env.backends.onnx.wasm.numThreads = 1;
}

let tokenizer = null;
let model = null;
let loadedRoot = null;
let loadingPromise = null;

async function fetchJson(url) {
  const response = await fetch(url, { cache: "no-cache" });
  if (!response.ok) {
    throw new Error(`Could not load ${url} (HTTP ${response.status}).`);
  }
  return response.json();
}

async function loadTokenizer(root) {
  const base = new URL(`${MODEL_LOCAL_ID}/`, root);
  const [tokenizerJSON, tokenizerConfig] = await Promise.all([
    fetchJson(new URL("tokenizer.json", base)),
    fetchJson(new URL("tokenizer_config.json", base)),
  ]);
  return new PreTrainedTokenizer(tokenizerJSON, tokenizerConfig);
}

function loadModel(root) {
  if (tokenizer && model && loadedRoot === root) return Promise.resolve();
  if (!loadingPromise) {
    loadedRoot = root;
    env.localModelPath = root;
    loadingPromise = Promise.all([
      loadTokenizer(root),
      AutoModel.from_pretrained(MODEL_LOCAL_ID, {
        dtype: MODEL_DTYPE,
        progress_callback: (progress) => {
          self.postMessage({ type: "progress", payload: progress });
        },
      }),
    ])
      .then(([loadedTokenizer, loadedModel]) => {
        tokenizer = loadedTokenizer;
        model = loadedModel;
      })
      .catch((error) => {
        loadingPromise = null;
        loadedRoot = null;
        throw error;
      });
  }
  return loadingPromise;
}

function errorPayload(error) {
  return {
    message: error?.message ?? String(error),
    stack: error?.stack ?? "",
  };
}

async function embedTexts(texts) {
  const inputs = await tokenizer(texts, {
    padding: true,
    truncation: true,
    max_length: MAX_LENGTH,
  });
  const output = await model(inputs);
  const hidden = output.last_hidden_state ?? output[0];
  const [batchSize, sequenceLength, dimension] = hidden.dims;
  const hiddenData = hidden.data;
  const maskData = inputs.attention_mask.data;

  const vectors = new Float32Array(batchSize * dimension);

  for (let batch = 0; batch < batchSize; batch += 1) {
    const outOffset = batch * dimension;
    const hiddenOffset = batch * sequenceLength * dimension;
    let count = 0;

    for (let position = 0; position < sequenceLength; position += 1) {
      if (!Number(maskData[position + batch * sequenceLength])) continue;
      count += 1;
      const tokenOffset = hiddenOffset + position * dimension;
      for (let d = 0; d < dimension; d += 1) {
        vectors[outOffset + d] += hiddenData[tokenOffset + d];
      }
    }

    let norm = 0;
    const divisor = Math.max(count, 1);
    for (let d = 0; d < dimension; d += 1) {
      vectors[outOffset + d] /= divisor;
      norm += vectors[outOffset + d] ** 2;
    }
    norm = Math.sqrt(norm) || 1;
    for (let d = 0; d < dimension; d += 1) {
      vectors[outOffset + d] /= norm;
    }
  }

  return { data: vectors, dims: [batchSize, dimension] };
}

self.onmessage = async (event) => {
  const { id, type, payload } = event.data ?? {};

  try {
    if (type === "load") {
      await loadModel(payload.modelRoot);
      self.postMessage({ type: "ready", id });
      return;
    }

    if (type === "embed") {
      if (!tokenizer || !model) throw new Error("The model has not been loaded yet.");
      const result = await embedTexts(payload.texts);
      self.postMessage(
        {
          type: "result",
          id,
          payload: result,
        },
        [result.data.buffer],
      );
      return;
    }

    throw new Error(`Unknown worker request: ${type}`);
  } catch (error) {
    self.postMessage({ type: "error", id, payload: errorPayload(error) });
  }
};
