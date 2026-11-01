interface AstNode {
  type?: string;
  value?: unknown;
  operator?: string;
  left?: AstNode;
  right?: AstNode;
  expr?: AstNode;
  ast?: unknown;
  column?: string | { expr?: { value?: string } };
  table?: string | null;
}

export interface TautologyCheckResult {
  isTautology: boolean;
  reason?: string;
  hasColumnReference: boolean;
}

export function evaluateWhereClause(whereNode: unknown): TautologyCheckResult {
  if (!whereNode) {
    return {
      isTautology: true,
      reason: "Missing WHERE clause entirely (unconstrained mutation).",
      hasColumnReference: false,
    };
  }

  const node = whereNode as AstNode;

  // Check if boolean true literal: WHERE true
  if (node.type === "bool" && node.value === true) {
    return {
      isTautology: true,
      reason: "WHERE clause evaluates unconditionally to boolean TRUE literal.",
      hasColumnReference: false,
    };
  }

  // Check top-level self-referential column comparison: WHERE col = col
  if (isSelfReferentialComparison(node)) {
    return {
      isTautology: true,
      reason:
        "WHERE clause contains self-referential column comparison (e.g. col = col) matching all rows.",
      hasColumnReference: true,
    };
  }

  const hasCol = containsColumnRef(node);

  // If there are zero column references in the WHERE clause, it cannot be a targeted predicate!
  if (!hasCol) {
    const isAlwaysTrue = checkConstantExpression(node);
    if (isAlwaysTrue) {
      return {
        isTautology: true,
        reason:
          "WHERE clause contains only constant literals evaluating unconditionally to TRUE (e.g. 1=1 or 0=0).",
        hasColumnReference: false,
      };
    }
  }

  // Check for dangerous OR tautology across nested clauses (e.g. WHERE col = 'val' OR 1=1, WHERE name IS NOT NULL OR 0=0)
  if (containsOrTautology(node)) {
    return {
      isTautology: true,
      reason: "WHERE clause contains an OR branch with a constant tautology that matches all rows.",
      hasColumnReference: hasCol,
    };
  }

  // Deep inspection for unconditional subquery tautologies
  const subqueryCheck = inspectSubqueriesForTautologies(node);
  if (subqueryCheck.hasTautologySubquery) {
    return {
      isTautology: true,
      reason: subqueryCheck.reason,
      hasColumnReference: hasCol,
    };
  }

  return {
    isTautology: false,
    hasColumnReference: hasCol,
  };
}

export function isSelfReferentialComparison(node: unknown): boolean {
  if (!node || typeof node !== "object") return false;
  const ast = node as AstNode;
  if (ast.type !== "binary_expr") return false;
  const op = ast.operator?.toUpperCase();
  if (op !== "=" && op !== "IS") return false;

  const left = ast.left as AstNode | undefined;
  const right = ast.right as AstNode | undefined;

  if (left?.type === "column_ref" && right?.type === "column_ref") {
    const leftCol =
      typeof left.column === "string"
        ? left.column
        : (left.column as { expr?: { value?: string } })?.expr?.value;
    const rightCol =
      typeof right.column === "string"
        ? right.column
        : (right.column as { expr?: { value?: string } })?.expr?.value;

    if (leftCol && rightCol && String(leftCol).toLowerCase() === String(rightCol).toLowerCase()) {
      const leftTable = left.table ? String(left.table).toLowerCase() : null;
      const rightTable = right.table ? String(right.table).toLowerCase() : null;
      if (!leftTable || !rightTable || leftTable === rightTable) {
        return true;
      }
    }
  }
  return false;
}

export function isTautologyBranch(branch: unknown): boolean {
  if (!branch || typeof branch !== "object") return false;
  const node = branch as AstNode;

  if (checkConstantExpression(node)) return true;
  if (isSelfReferentialComparison(node)) return true;

  if (node.type === "binary_expr" && node.operator?.toUpperCase() === "OR") {
    return isTautologyBranch(node.left) || isTautologyBranch(node.right);
  }

  return false;
}

export function containsOrTautology(node: unknown): boolean {
  if (!node || typeof node !== "object") return false;
  const ast = node as AstNode;
  if (ast.type === "binary_expr") {
    const op = ast.operator?.toUpperCase();
    if (op === "OR") {
      if (isTautologyBranch(ast.left) || isTautologyBranch(ast.right)) {
        return true;
      }
      return containsOrTautology(ast.left) || containsOrTautology(ast.right);
    }
    if (op === "AND") {
      return containsOrTautology(ast.left) || containsOrTautology(ast.right);
    }
  }
  return false;
}

export function inspectSubqueriesForTautologies(node: unknown): {
  hasTautologySubquery: boolean;
  reason?: string;
} {
  if (!node || typeof node !== "object") return { hasTautologySubquery: false };
  const ast = node as AstNode;

  if (ast.ast && typeof ast.ast === "object") {
    const subquery = ast.ast as { where?: unknown };
    if (subquery.where) {
      const res = evaluateWhereClause(subquery.where);
      if (res.isTautology) {
        return {
          hasTautologySubquery: true,
          reason: `Subquery contains unconditional tautology in WHERE clause: ${res.reason}`,
        };
      }
    }
  }

  if (ast.left) {
    const l = inspectSubqueriesForTautologies(ast.left);
    if (l.hasTautologySubquery) return l;
  }
  if (ast.right) {
    const r = inspectSubqueriesForTautologies(ast.right);
    if (r.hasTautologySubquery) return r;
  }
  if (ast.expr) {
    const e = inspectSubqueriesForTautologies(ast.expr);
    if (e.hasTautologySubquery) return e;
  }
  if (Array.isArray(ast.value)) {
    for (const item of ast.value) {
      const sub = inspectSubqueriesForTautologies(item);
      if (sub.hasTautologySubquery) return sub;
    }
  }

  return { hasTautologySubquery: false };
}

export function containsColumnRef(node: unknown): boolean {
  if (!node || typeof node !== "object") return false;

  const ast = node as AstNode;
  if (ast.type === "column_ref") return true;

  // Recurse into left/right or expr
  if (containsColumnRef(ast.left)) return true;
  if (containsColumnRef(ast.right)) return true;
  if (containsColumnRef(ast.expr)) return true;

  if (Array.isArray(ast.value)) {
    for (const item of ast.value) {
      if (containsColumnRef(item)) return true;
    }
  }

  return false;
}

export function checkConstantExpression(node: unknown): boolean {
  if (!node || typeof node !== "object") return false;

  const ast = node as AstNode;

  // Boolean literal
  if (ast.type === "bool") {
    return Boolean(ast.value);
  }

  // Binary expression e.g. 1 = 1, 'a' = 'a'
  if (ast.type === "binary_expr") {
    const op = ast.operator?.toUpperCase();

    if (op === "=") {
      const leftVal = extractLiteralValue(ast.left);
      const rightVal = extractLiteralValue(ast.right);
      if (leftVal !== undefined && rightVal !== undefined) {
        return leftVal === rightVal;
      }
    }

    if (op === "!=" || op === "<>") {
      const leftVal = extractLiteralValue(ast.left);
      const rightVal = extractLiteralValue(ast.right);
      if (leftVal !== undefined && rightVal !== undefined) {
        return leftVal !== rightVal;
      }
    }

    if (op === "OR") {
      return checkConstantExpression(ast.left) || checkConstantExpression(ast.right);
    }

    if (op === "AND") {
      return checkConstantExpression(ast.left) && checkConstantExpression(ast.right);
    }
  }

  return false;
}

function extractLiteralValue(node: unknown): string | number | boolean | undefined {
  if (!node || typeof node !== "object") return undefined;

  const ast = node as AstNode;

  if (ast.type === "number") {
    return Number(ast.value);
  }

  if (ast.type === "single_quote_string" || ast.type === "string") {
    return String(ast.value);
  }

  if (ast.type === "bool") {
    return Boolean(ast.value);
  }

  return undefined;
}
