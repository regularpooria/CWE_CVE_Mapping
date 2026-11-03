/**
 * CWE-699 taxonomy helpers.
 *
 * The text preparation intentionally mirrors experiments/model_comparison.ipynb:
 *   - category: title + immediate child titles joined by "," + summary
 *   - child:    description + "\n" + extended_description (when it exists)
 *
 * A child can appear under more than one category. We keep one embedding per
 * child id (the first occurrence in the JSON), exactly like the notebook's
 * `child_lookup.setdefault(...)`.
 */

export function childText(child) {
  let text = child.description ?? "";
  if (child.extended_description !== null && child.extended_description !== undefined) {
    text += `\n${child.extended_description}`;
  }
  return text;
}

export function categoryText(category) {
  const childTitles = Object.values(category.children ?? {})
    .map((child) => child.title)
    .join(",");
  return `${category.title}${childTitles}${category.summary ?? ""}`;
}

export function buildCweIndex(CWE) {
  const categories = [];
  const childrenById = new Map();
  const childOrder = [];

  for (const [categoryId, category] of Object.entries(CWE)) {
    const childIds = [];

    for (const [childId, child] of Object.entries(category.children ?? {})) {
      const id = String(childId);
      if (!childrenById.has(id)) {
        childrenById.set(id, {
          id,
          title: child.title ?? "",
          url: child.url ?? "",
          description: child.description ?? "",
          extended_description: child.extended_description ?? null,
          text: childText(child),
        });
        childOrder.push(id);
      }
      childIds.push(id);
    }

    categories.push({
      id: String(categoryId),
      title: category.title ?? "",
      summary: category.summary ?? "",
      url: category.url ?? "",
      childIds,
      text: categoryText(category),
    });
  }

  const children = childOrder.map((id) => childrenById.get(id));
  const categoryIndex = new Map(categories.map((category, index) => [category.id, index]));
  const childIndex = new Map(children.map((child, index) => [child.id, index]));

  const categoryChildIndices = categories.map((category) =>
    category.childIds.map((id) => childIndex.get(id)),
  );

  const childParentIndices = children.map(() => []);
  categories.forEach((category, categoryIdx) => {
    for (const childId of category.childIds) {
      const idx = childIndex.get(childId);
      if (!childParentIndices[idx].includes(categoryIdx)) {
        childParentIndices[idx].push(categoryIdx);
      }
    }
  });

  return {
    categories,
    children,
    childrenById,
    categoryIndex,
    childIndex,
    categoryChildIndices,
    childParentIndices,
    categoryIds: categories.map((category) => category.id),
    childIds: children.map((child) => child.id),
    categoryTexts: categories.map((category) => category.text),
    childTexts: children.map((child) => child.text),
  };
}

export function cweLabel(id) {
  return `CWE-${id}`;
}
