---
language:
- en
tags:
- sentence-transformers
- sentence-similarity
- feature-extraction
- cybersecurity
- vulnerability
- cve
- cwe
- software-security
- retrieval
library_name: sentence-transformers
pipeline_tag: sentence-similarity
license: apache-2.0
base_model: sentence-transformers/all-MiniLM-L6-v2
---

# HiCWE: Hierarchy-Aware Contrastive CWE Encoder (MiniLM-L6-v2)

HiCWE is a sentence encoder that maps a CVE (Common Vulnerabilities and Exposures) description to its most likely CWE (Common Weakness Enumeration) entries in the CWE-699 *Software Development* view. It is an `all-MiniLM-L6-v2` encoder fine-tuned with a hierarchy-aware contrastive objective so that a CVE description lands close to its CWE category and child CWE definitions in a shared embedding space.

This is the lighter of the two released variants. See [`regularpooria/HiCWE-MiniLM-L12-v2`](https://huggingface.co/regularpooria/HiCWE-MiniLM-L12-v2) for the larger model. The two produce 384-dimensional embeddings, so they are drop-in interchangeable.

## Model description

- **Architecture:** `all-MiniLM-L6-v2` (larger variant: `all-MiniLM-L12-v2`)
- **Embedding dimension:** 384
- **Max sequence length:** 512
- **Pooling:** mean pooling + L2 normalization (cosine similarity)
- **Fine-tuning:** LoRA (rank 64, alpha 128, dropout 0) on the attention `query`, `key`, `value` and `dense` projections, merged back into the base weights so inference is a single forward pass of a plain SentenceTransformer.

The model is trained with MultipleNegativesRankingLoss using the **hierarchy-full** recipe (Recipe A):

1. `cve_to_cwe` — CVE to its own CWE, with a sibling and a look-alike CWE from another category as hard negatives.
2. `cve_to_category` — CVE to its parent category, with the nearest other category as the hard negative.
3. `cwe_geometry` — CWE to a sibling CWE, pulling siblings together and pushing look-alikes from other categories apart.

Hard negatives are mined with the untuned encoder, and the CWE side of every pair is rendered as the node title, its summary, and the titles of its immediate children. Training with the taxonomy structure teaches the model to place a CVE near its parent category *and* its child CWE, which is what enables the two-stage search below.

## Training data

- **Corpus:** CWE-699 *Software Development* view scraped from `cwe.mitre.org`, including parents and children.
- **CVE descriptions:** 1999–2021 CVEs derived from the `zefang-liu/cve-and-cwe-mapping-dataset` dataset, enriched with CWE descriptions and normalized to remove noise.
- **Split:** by CVE identifier so no CVE with multiple labels straddles splits, stratified on the primary CWE.
- **Training:** 3 epochs, learning rate 1e-4, batch size 64, linear warmup (5%).

## Intended use

Given a CVE description, embed it and rank CWE node texts by cosine similarity. The recommended inference is a two-stage search that mirrors the training objective:

1. **Stage 1 (category):** score every CWE *category* node and keep the top few.
2. **Stage 2 (child):** search only the descendants (and optionally the category node itself) of those categories and return the top-k children.

The model can also be used as a plain embedding model for asymmetric CVE-to-CWE retrieval.

## Evaluation

Recall@k on **CVEs disclosed 2023–2025, unseen during training**. Category recall uses the two-stage search; child recall is reported both restricted to predicted categories (*hier.*) and over the full taxonomy (*flat*).

| Target | Model | @1 | @3 | @5 |
|---|---|---|---|---|
| Category | Baseline (untuned L6) | 0.236 | 0.409 | 0.510 |
| Category | **HiCWE-MiniLM-L6-v2** | 0.750 | 0.856 | 0.889 |
| Category | SOTA classifier (`mulliken/cwe-predictor`) | 0.802 | 0.862 | 0.869 |
| Child (hier.) | Baseline (untuned L6) | 0.124 | 0.175 | 0.216 |
| Child (hier.) | **HiCWE-MiniLM-L6-v2** | 0.695 | 0.735 | 0.756 |
| Child (flat) | Baseline (untuned L6) | 0.337 | 0.432 | 0.479 |
| Child (flat) | **HiCWE-MiniLM-L6-v2** | 0.753 | 0.828 | 0.853 |
| Child (flat) | SOTA classifier (`mulliken/cwe-predictor`) | 0.655 | 0.753 | 0.779 |

Fine-tuning improves every target over the untuned encoder. The hierarchy-full recipe gives the strongest child predictions, which is the quantity that matters for downstream exploitability analysis. On the flat child target this model beats the SOTA classifier, and on the category target it is competitive with it at a fraction of the size.

The larger `HiCWE-MiniLM-L12-v2` is stronger at k=1 but the flat child target is essentially identical between the two sizes (0.75 at k=1 and 0.85 at k=5), so this L6 model is the efficient default.

## Usage

```python
from sentence_transformers import SentenceTransformer, util

model = SentenceTransformer("regularpooria/HiCWE-MiniLM-L6-v2")

cve = "The product does not neutralize special elements used in a SQL command."

# CWE node text = title + summary + immediate children titles
cwe_texts = [
    "Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection'). "
    "The product constructs all or part of an SQL command using externally-influenced input ...",
    "Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting'). ...",
    # ... one entry per CWE node
]

cve_emb = model.encode(cve, normalize_embeddings=True)
cwe_emb = model.encode(cwe_texts, normalize_embeddings=True)

scores = util.cos_sim(cve_emb, cwe_emb)[0]
top = scores.argsort(descending=True)[:5]
for i in top:
    print(round(float(scores[i]), 4), cwe_texts[i][:60])
```

For the best accuracy, use the two-stage category-then-children search described under *Intended use*, and embed the CWE node text with its parent/child context exactly as during training.

## Limitations

- The taxonomy is fixed to the CWE-699 *Software Development* view. New or out-of-view CWEs are not represented, although embeddings still generalize to unseen descriptions without retraining.
- Evaluation covers CVEs published 2023–2025; performance on non-software weaknesses or non-English descriptions is not established.
- The model ranks candidates; it does not produce calibrated probabilities. Cosine similarity is a relative score, not a confidence value.
- CVE descriptions can be vague or mention several weaknesses at once, in which case the top-ranked CWE may not be the primary one.

## Citation

If you use this model, please cite the HiCWE paper. (Citation details to be added.)
