export function analyzeTyposquats(packages, popularNames, threshold) {
  const findings = [];

  for (const pkg of packages) {
    const packageName = normalizeName(pkg.name);
    if (!packageName || packageName.startsWith("@")) {
      continue;
    }

    let bestTarget = null;
    let bestScore = 0;

    for (const popular of popularNames) {
      if (packageName === popular) {
        bestTarget = null;
        bestScore = 0;
        break;
      }

      const score = similarity(packageName, popular);
      if (score > bestScore) {
        bestScore = score;
        bestTarget = popular;
      }
    }

    if (bestTarget && bestScore >= threshold) {
      findings.push({
        package: pkg,
        target: bestTarget,
        score: bestScore,
      });
    }
  }

  return findings;
}

function similarity(left, right) {
  const distance = levenshtein(left, right);
  return 1 - distance / Math.max(left.length, right.length);
}

function levenshtein(left, right) {
  const rows = left.length + 1;
  const cols = right.length + 1;
  const matrix = Array.from({ length: rows }, () => Array(cols).fill(0));

  for (let row = 0; row < rows; row += 1) {
    matrix[row][0] = row;
  }

  for (let col = 0; col < cols; col += 1) {
    matrix[0][col] = col;
  }

  for (let row = 1; row < rows; row += 1) {
    for (let col = 1; col < cols; col += 1) {
      const cost = left[row - 1] === right[col - 1] ? 0 : 1;
      matrix[row][col] = Math.min(
        matrix[row - 1][col] + 1,
        matrix[row][col - 1] + 1,
        matrix[row - 1][col - 1] + cost,
      );
    }
  }

  return matrix[rows - 1][cols - 1];
}

function normalizeName(value) {
  return value.toLowerCase().replace(/[^a-z0-9@/.-]/gu, "");
}
