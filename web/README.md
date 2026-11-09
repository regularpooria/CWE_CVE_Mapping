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

The app is fully static. `npm run build` writes the complete site to `web/dist`; serve or
upload the **contents of `web/dist`**. No build step or GitHub Actions are required on the
host.

```bash
cd web
npm run build
# then publish the contents of web/dist
```

For example, with a publish-directory host such as Surge:

```bash
cd web
npm run build
npx surge ./dist <your-name>.surge.sh
```
