import fs from 'node:fs';
import path from 'node:path';
import yaml from 'js-yaml';
import { writePrivateConfigFileSync } from './private-config-file.js';
import { getConfig, getConfigPath, resetConfig } from './config.js';
import {
  type CuBackend,
  DEFAULT_CU_BACKEND,
  assertCuBackendSupported as assertCuBackendSupportedPure,
  parseCuBackend,
} from './cu-backend.js';

/** Set of accepted backend identifiers used for input validation. */
const VALID_BACKENDS: ReadonlySet<CuBackend> = new Set(['native', 'mcp']);

/**
 * Read the resolved Computer Use backend from `config.yaml`.
 *
 * Goes through the central {@link getConfig} parser so the resolved value
 * always matches what the rest of the runtime sees.
 */
export function getCuBackend(): CuBackend {
  return parseCuBackend((getConfig() as { cuBackend?: unknown }).cuBackend);
}

/**
 * Persist the Computer Use backend selection to `config.yaml` and reset the
 * cached `Config` so the next {@link getCuBackend} call observes the change.
 *
 * NOTE: This writer performs a non-atomic read-modify-write and is **not**
 * lockfile-protected. Concurrent mutations should go through the runtime
 * config writer/facade so hosts can deep-merge, lock, and emit
 * `config.updated`. This helper exists for one-shot CLI / test paths that do
 * not need that machinery.
 */
export function setCuBackend(value: CuBackend): void {
  if (!VALID_BACKENDS.has(value)) {
    throw new Error(`invalid cuBackend value: ${String(value)}`);
  }

  const configPath = getConfigPath();
  let raw: Record<string, unknown> = {};
  try {
    const text = fs.readFileSync(configPath, 'utf-8');
    const parsed = yaml.load(text);
    if (parsed != null && typeof parsed === 'object' && !Array.isArray(parsed)) {
      raw = parsed as Record<string, unknown>;
    }
  } catch {
    // Missing / unreadable file → treat as empty so we still write the field.
  }

  raw.cuBackend = value;
  fs.mkdirSync(path.dirname(configPath), { recursive: true });
  writePrivateConfigFileSync(configPath, yaml.dump(raw));
  resetConfig();
}

/**
 * Daemon-side wrapper around the pure
 * {@link assertCuBackendSupportedPure} guard. Defaults to {@link getCuBackend}
 * when the caller does not pass an explicit backend, sparing them an
 * extra config lookup at the call site.
 *
 * Renderer code should keep using the pure variant from
 * `@mavis/config/cu-backend` and feed it the value from the renderer-side
 * cache instead of touching `config.yaml`.
 */
export function assertCuBackendSupported(backend: CuBackend = getCuBackend()): void {
  assertCuBackendSupportedPure(backend);
}

// Re-export the pure surface for callers that want a single import target.
export { type CuBackend, DEFAULT_CU_BACKEND, parseCuBackend };
