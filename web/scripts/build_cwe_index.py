#!/usr/bin/env python3
"""Build the precomputed CWE embedding index for the HiCWE web app.

The output is a compact JSON file containing base64-encoded little-endian
float32 vectors. It is used by the site on first load; the browser still
caches the decoded vectors in IndexedDB, and can recompute them if the file is
missing or stale.

Example (from the repository root, using the project venv):

    ./venv/bin/python web/scripts/build_cwe_index.py
"""

from __future__ import annotations

import argparse
import base64
import json
import sys
from pathlib import Path

import numpy as np
import onnxruntime as ort
from transformers import AutoTokenizer

INDEX_VERSION = 3
MODEL_ID = "HiCWE-MiniLM-L12"
MODEL_REVISION = "rizm2zd9qgqe"
MODEL_DTYPE = "q8"
MAX_LENGTH = 512
MODEL_SOURCE = "https://anonymous-hf.com/a/rizm2zd9qgqe/"

ROOT = Path(__file__).resolve().parents[2]
DEFAULT_MODEL_DIR = ROOT / "web" / "public" / "models" / "hicwe"
DEFAULT_CWE_JSON = ROOT / "web" / "public" / "data" / "CWE_SOFTWARE.json"
DEFAULT_OUTPUT = ROOT / "web" / "public" / "data" / "cwe_index.json"


def js_hash(text: str) -> str:
    """FNV-1a over UTF-16 code units, matching the browser's hashString()."""
    encoded = text.encode("utf-16-le")
    value = 2166136261
    for offset in range(0, len(encoded), 2):
        unit = encoded[offset] | (encoded[offset + 1] << 8)
        value ^= unit
        value = (value * 16777619) & 0xFFFFFFFF
    return f"{value:x}"


def ordered_items(mapping: dict):
    """Match JavaScript's Object.entries order for integer-like CWE ids."""
    return sorted(
        mapping.items(),
        key=lambda item: int(item[0]) if str(item[0]).isdigit() else str(item[0]),
    )


def category_text(category: dict) -> str:
    titles = ",".join(child["title"] for _, child in ordered_items(category["children"]))
    return f"{category['title']}{titles}{category.get('summary', '')}"


def child_text(child: dict) -> str:
    text = child.get("description") or ""
    extended = child.get("extended_description")
    if extended is not None:
        text += f"\n{extended}"
    return text


def build_texts(cwe: dict) -> tuple[list[str], list[str], list[str], list[str]]:
    category_ids: list[str] = []
    category_texts: list[str] = []
    child_ids: list[str] = []
    seen: set[str] = set()
    child_texts: list[str] = []

    for category_id, category in ordered_items(cwe):
        category_ids.append(str(category_id))
        category_texts.append(category_text(category))
        for child_id, child in ordered_items(category["children"]):
            cid = str(child_id)
            if cid in seen:
                continue
            seen.add(cid)
            child_ids.append(cid)
            child_texts.append(child_text(child))

    return category_ids, category_texts, child_ids, child_texts


def embed_texts(tokenizer, session, texts: list[str], batch_size: int = 32) -> np.ndarray:
    input_names = {item.name for item in session.get_inputs()}
    vectors: list[np.ndarray] = []

    for start in range(0, len(texts), batch_size):
        batch = texts[start : start + batch_size]
        encoded = tokenizer(
            batch,
            return_tensors="np",
            padding=True,
            truncation=True,
            max_length=MAX_LENGTH,
        )
        feeds = {
            name: encoded[name].astype(np.int64)
            for name in ("input_ids", "attention_mask", "token_type_ids")
            if name in input_names
        }
        hidden = session.run(None, feeds)[0]
        mask = feeds["attention_mask"][..., None].astype(np.float32)
        pooled = (hidden * mask).sum(axis=1) / np.clip(mask.sum(axis=1), 1e-9, None)
        pooled = pooled / np.linalg.norm(pooled, axis=1, keepdims=True)
        vectors.append(pooled)
        print(f"  {min(start + batch_size, len(texts)):,} / {len(texts):,}", flush=True)

    return np.vstack(vectors)


def encode_vectors(vectors: np.ndarray) -> str:
    return base64.b64encode(vectors.astype("<f4").tobytes()).decode("ascii")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--model-dir", type=Path, default=DEFAULT_MODEL_DIR)
    parser.add_argument("--cwe-json", type=Path, default=DEFAULT_CWE_JSON)
    parser.add_argument("--output", type=Path, default=DEFAULT_OUTPUT)
    parser.add_argument("--batch-size", type=int, default=32)
    args = parser.parse_args()

    model_path = args.model_dir / "onnx" / "model_quantized.onnx"
    if not model_path.exists():
        raise SystemExit(f"Missing {model_path}")
    if not args.cwe_json.exists():
        raise SystemExit(f"Missing {args.cwe_json}")

    raw = args.cwe_json.read_text(encoding="utf-8")
    cwe = json.loads(raw)
    category_ids, category_texts, child_ids, child_texts = build_texts(cwe)
    print(
        f"Embedding {len(category_ids)} categories and {len(child_ids)} unique children "
        f"with {model_path}"
    )

    tokenizer = AutoTokenizer.from_pretrained(args.model_dir)
    session = ort.InferenceSession(str(model_path), providers=["CPUExecutionProvider"])

    print("Categories")
    category_vectors = embed_texts(tokenizer, session, category_texts, args.batch_size)
    print("Children")
    child_vectors = embed_texts(tokenizer, session, child_texts, args.batch_size)

    if category_vectors.shape[1] != child_vectors.shape[1]:
        raise SystemExit("Category and child embedding dimensions differ.")

    payload = {
        "version": INDEX_VERSION,
        "modelId": MODEL_ID,
        "revision": MODEL_REVISION,
        "dtype": MODEL_DTYPE,
        "maxLength": MAX_LENGTH,
        "cweHash": js_hash(raw),
        "dim": int(category_vectors.shape[1]),
        "source": MODEL_SOURCE,
        "categoryIds": category_ids,
        "categoryVectors": encode_vectors(category_vectors),
        "childIds": child_ids,
        "childVectors": encode_vectors(child_vectors),
    }

    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(payload, separators=(",", ":")), encoding="utf-8")
    print(
        f"Wrote {args.output} ({args.output.stat().st_size / 1e6:.2f} MB, "
        f"dim={payload['dim']}, hash={payload['cweHash']})"
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
