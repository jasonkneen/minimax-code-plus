import { randomBytes } from 'node:crypto';
import { promises as fs } from 'node:fs';
import { dirname, join } from 'node:path';
import yaml from 'js-yaml';
import lockfile from 'proper-lockfile';

/** Update only the profile's presentation setting, under the same lock as model writes. */
export async function writeTuiStatusLineSetting(
  dataDir: string,
  items: readonly string[] | undefined,
): Promise<void> {
  const configPath = join(dataDir, 'config.yaml');
  let temporaryPath: string | undefined;
  let temporaryCreated = false;
  let release: (() => Promise<void>) | undefined;
  try {
    await fs.mkdir(dataDir, { recursive: true });
    await fs.writeFile(configPath, '', { flag: 'a', mode: 0o600 });
    await fs.chmod(configPath, 0o600);
    // Replace the real file, preserving any symlink used to manage profile settings.
    // Keep the temporary file on the target filesystem so rename remains atomic.
    const targetPath = await fs.realpath(configPath);
    temporaryPath = join(dirname(targetPath), `.config-tmp-${randomBytes(6).toString('hex')}`);
    release = await lockfile.lock(targetPath, {
      stale: 10_000,
      retries: { retries: 20, factor: 1, minTimeout: 5, maxTimeout: 25 },
    });
    const parsed: unknown = yaml.load(await fs.readFile(targetPath, 'utf8'));
    const document = parsed ?? {};
    if (!isRecord(document)) throw new Error('Invalid config document');
    const tui = document.tui ?? {};
    if (!isRecord(tui)) throw new Error('Invalid TUI settings');
    // Copy the subtree: YAML aliases must not mutate another settings block.
    const nextTui = { ...tui };
    if (items === undefined) delete nextTui.statusLine;
    else nextTui.statusLine = [...items];
    const next = { ...document, tui: nextTui };
    const mode = 0o600;
    const temporary = await fs.open(temporaryPath, 'wx', mode);
    temporaryCreated = true;
    try {
      await temporary.writeFile(yaml.dump(next, { lineWidth: -1, noRefs: true }), 'utf8');
      await temporary.chmod(mode);
    } finally {
      await temporary.close();
    }
    await fs.rename(temporaryPath, targetPath);
  } catch {
    // Parser errors can contain unrelated credentials from the config source.
    throw new Error(
      'Unable to save status line settings. Check config.yaml syntax and permissions.',
    );
  } finally {
    if (temporaryCreated && temporaryPath) await fs.unlink(temporaryPath).catch(() => undefined);
    await release?.().catch(() => undefined);
  }
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return (
    typeof value === 'object' &&
    value !== null &&
    !Array.isArray(value) &&
    Object.getPrototypeOf(value) === Object.prototype
  );
}
