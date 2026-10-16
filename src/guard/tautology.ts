interface AstNode {
  type?: string;
  value?: unknown;
  operator?: string;
  left?: AstNode;
  right?: AstNode;
  expr?: AstNode;
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

  const hasCol = containsColumnRef(node);

  // If there are zero column references in the WHERE clause, it cannot be a targeted predicate!
  if (!hasCol) {
    const isAlwaysTrue = checkConstantExpression(node);
    if (isAlwaysTrue) {
      return {
        isTautology: true,
        reason:
          "WHERE clause contains only constant literals evaluating unconditionally to TRUE (e.g. 1=1).",
        hasColumnReference: false,
      };
    }
  }

  // Check for dangerous OR tautology: WHERE col = 'val' OR 1=1
  if (node.type === "binary_expr" && node.operator?.toUpperCase() === "OR") {
    const leftIsTautology = checkConstantExpression(node.left);
    const rightIsTautology = checkConstantExpression(node.right);

    if (leftIsTautology || rightIsTautology) {
      return {
        isTautology: true,
        reason:
          "WHERE clause contains an OR branch with a constant tautology that matches all rows.",
        hasColumnReference: hasCol,
      };
    }
  }

  return {
    isTautology: false,
    hasColumnReference: hasCol,
  };
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
