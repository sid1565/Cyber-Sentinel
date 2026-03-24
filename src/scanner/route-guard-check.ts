// FILE: src/scanner/route-guard-check.ts

import * as fs from 'fs';
import * as path from 'path';

export interface UnguardedRoute {
  file: string;
  class: string;
  method: string;
  httpMethod: string;
  routePath: string;
  issue: string;
}

const RE_CONTROLLER = /@Controller\(\s*['"`]?([^'"`)\s]*)['"`]?\s*\)/;
const RE_ROUTE = /@(Get|Post|Put|Delete|Patch|Options|Head)\(\s*['"`]?([^'"`)\s]*)['"`]?\s*\)/;
const RE_USE_GUARDS = /@UseGuards\s*\(/;
const RE_CLASS = /export\s+(?:abstract\s+)?class\s+(\w+)/;
const RE_METHOD_NAME = /(?:(?:public|private|protected|async)\s+)*(\w+)\s*\(/;
const IGNORE_DIRS = new Set(['node_modules', '.git', 'dist', 'build', 'coverage']);

export function checkRouteGuards(projectPath: string): UnguardedRoute[] {
  const files = collectControllerFiles(projectPath);
  return files.flatMap(analyzeFile);
}

function analyzeFile(filePath: string): UnguardedRoute[] {
  let content: string;
  try {
    content = fs.readFileSync(filePath, 'utf-8');
  } catch {
    return [];
  }

  const lines = content.split('\n');
  const results: UnguardedRoute[] = [];
  let controllerBase = '';
  let className = '';
  let classHasGuard = false;

  for (let i = 0; i < lines.length; i++) {
    const line = lines[i];

    const ctrlMatch = RE_CONTROLLER.exec(line);
    if (ctrlMatch) {
      controllerBase = ctrlMatch[1] ?? '';
      const window = lines.slice(Math.max(0, i - 3), i + 6).join('\n');
      classHasGuard = RE_USE_GUARDS.test(window);
      continue;
    }

    const classMatch = RE_CLASS.exec(line);
    if (classMatch) { className = classMatch[1]; continue; }

    const routeMatch = RE_ROUTE.exec(line);
    if (!routeMatch || !className) continue;

    const httpMethod = routeMatch[1];
    const routeSuffix = routeMatch[2] ?? '';
    const fullPath = `/${[controllerBase, routeSuffix].filter(Boolean).join('/')}`;

    // Look in the 10 lines following the decorator for @UseGuards
    const handlerWindow = lines.slice(i, Math.min(i + 10, lines.length)).join('\n');
    const handlerHasGuard = RE_USE_GUARDS.test(handlerWindow);

    // Find method name: skip decorator lines (start with @) and find first real identifier
    const nonDecoratorLines = lines
      .slice(i + 1, i + 10)
      .filter((l) => !l.trim().startsWith('@'));
    const methodMatch = RE_METHOD_NAME.exec(nonDecoratorLines.join('\n'));
    const methodName = methodMatch?.[1] ?? 'unknown';

    if (!classHasGuard && !handlerHasGuard) {
      results.push({
        file: filePath,
        class: className,
        method: methodName,
        httpMethod,
        routePath: fullPath,
        issue: 'Route lacks @UseGuards() — may be publicly accessible',
      });
    }
  }

  return results;
}

function collectControllerFiles(dir: string): string[] {
  const results: string[] = [];
  walkDir(dir, results);
  return results;
}

function walkDir(dir: string, out: string[]): void {
  let entries: fs.Dirent[];
  try { entries = fs.readdirSync(dir, { withFileTypes: true }); }
  catch { return; }

  for (const entry of entries) {
    if (IGNORE_DIRS.has(entry.name)) continue;
    const full = path.join(dir, entry.name);
    if (entry.isDirectory()) {
      walkDir(full, out);
    } else if (entry.isFile() && /\.controller\.(ts|js)$/.test(entry.name)) {
      out.push(full);
    }
  }
}
