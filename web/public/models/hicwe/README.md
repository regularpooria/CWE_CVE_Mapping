# HiCWE model files

These files are a local mirror of the anonymous review copy:

<https://anonymous-hf.com/a/rizm2zd9qgqe/>

They are served from the same origin as the static app so the browser can load the
ONNX model without relying on a third-party host's CORS policy.

- `onnx/model_quantized.onnx` — int8 ONNX graph used by Transformers.js
- `config.json`, `tokenizer.json`, `tokenizer_config.json` — model configuration and tokenizer
- `1_Pooling/`, `2_Normalize/` — SentenceTransformers metadata (not used by the browser)
- `LICENSE` — Apache-2.0 license from the original model repo

The model is a fine-tuned `all-MiniLM-L12-v2` sentence encoder. It produces 384-dimensional
embeddings with mean pooling and L2 normalization.
