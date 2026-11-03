/**
 * Vector search over the CWE hierarchy.
 *
 * Mirrors the notebook's hierarchical search: rank categories, keep the top
 * `beam`, then rank only the children that belong to those categories.
 */

export function dotAt(a, aOffset, b, bOffset, dim) {
  let dot = 0;
  for (let i = 0; i < dim; i += 1) {
    dot += a[aOffset + i] * b[bOffset + i];
  }
  return dot;
}

export function rankCwes(query, index, vectors, { topK = 3, beam = 20 } = {}) {
  const dim = vectors.dim;
  const categoryCount = index.categories.length;
  const childCount = index.children.length;

  const categoryScores = new Float32Array(categoryCount);
  for (let i = 0; i < categoryCount; i += 1) {
    categoryScores[i] = dotAt(query, 0, vectors.categoryVectors, i * dim, dim);
  }

  const categoryOrder = Array.from({ length: categoryCount }, (_, i) => i).sort(
    (a, b) => categoryScores[b] - categoryScores[a],
  );
  const topCategories = categoryOrder.slice(0, Math.min(beam, categoryCount));

  const allowed = new Uint8Array(childCount);
  for (const categoryIdx of topCategories) {
    for (const childIdx of index.categoryChildIndices[categoryIdx]) {
      allowed[childIdx] = 1;
    }
  }

  const childScores = new Float32Array(childCount);
  for (let i = 0; i < childCount; i += 1) {
    childScores[i] = allowed[i]
      ? dotAt(query, 0, vectors.childVectors, i * dim, dim)
      : Number.NEGATIVE_INFINITY;
  }

  const k = Math.max(1, Math.min(topK, childCount));
  const childOrder = Array.from({ length: childCount }, (_, i) => i)
    .filter((i) => allowed[i])
    .sort((a, b) => childScores[b] - childScores[a])
    .slice(0, k);

  const childResults = childOrder.map((childIdx) => {
    const parents = index.childParentIndices[childIdx];
    let bestParent = parents[0] ?? -1;
    for (const parentIdx of parents) {
      if (bestParent === -1 || categoryScores[parentIdx] > categoryScores[bestParent]) {
        bestParent = parentIdx;
      }
    }
    return {
      id: index.children[childIdx].id,
      score: childScores[childIdx],
      categoryId: bestParent >= 0 ? index.categories[bestParent].id : null,
      categoryTitle: bestParent >= 0 ? index.categories[bestParent].title : "",
      categoryScore: bestParent >= 0 ? categoryScores[bestParent] : null,
    };
  });

  return {
    categories: topCategories.slice(0, 5).map((categoryIdx) => ({
      id: index.categories[categoryIdx].id,
      title: index.categories[categoryIdx].title,
      score: categoryScores[categoryIdx],
    })),
    children: childResults,
  };
}
