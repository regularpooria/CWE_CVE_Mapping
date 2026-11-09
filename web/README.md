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

- `HiCWE-MiniLM-L12` (int8 ONNX) via ONNX Runtime Web.
- The model files are bundled under `public/models/hicwe/` and served from the same origin as
  the app. The app does not contact a remote model host.
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

The app is fully static; no GitHub Actions/workflow runs are required. GitHub Pages branch
deployment can only serve from the repository **root** or the **`/docs`** folder, so the build
is copied to `docs/` for publishing.

```bash
cd web
npm run build:pages
```

This builds the app and replaces `../docs` with the production files (including
`docs/.nojekyll`, which stops GitHub from running Jekyll on the output).

Then commit `docs/` and set **Settings → Pages → Build and deployment → Source** to
**Deploy from a branch**, branch **`main`**, folder **`/docs`**.

Alternative that keeps build output out of `main`: push the contents of `web/dist` to a
`gh-pages` branch and select that branch with the **`/`** folder instead.

> `.github/workflows/deploy-web.yml` is optional. It only runs if Actions are enabled; when
> Pages is set to "Deploy from a branch", the workflow is ignored.
