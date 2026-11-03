# HiCWE web app

Static, client-side CVE → CWE search. No backend and no API keys.

## Local development

```bash
cd web
npm install
npm run dev
```

Production build:

```bash
npm run build
npm run preview
```

## What runs in the browser

- `HiCWE-MiniLM-L12` (int8 ONNX) via `@huggingface/transformers` and ONNX Runtime Web.
- The model files under `public/models/hicwe/` are a local mirror of the anonymous review
  copy at <https://anonymous-hf.com/a/rizm2zd9qgqe/>. Serving them from the same origin avoids
  third-party CORS restrictions.
- CWE titles and descriptions are read from `public/data/CWE_SOFTWARE.json`.
- The precomputed CWE embedding index is `public/data/cwe_index.json`. It is generated with the
  same ONNX model and the text-preparation rules from `experiments/model_comparison.ipynb`.
  The browser caches the decoded vectors in IndexedDB and can recompute them if the file is
  missing or stale.

Regenerate the precomputed index after changing the model or `CWE_SOFTWARE.json`:

```bash
cd ..
./venv/bin/python web/scripts/build_cwe_index.py
```

## Deployment

`.github/workflows/deploy-web.yml` builds `web/` and deploys `web/dist` to GitHub Pages.
Enable **Settings → Pages → Build and deployment → Source: GitHub Actions** once in the
repository settings.
