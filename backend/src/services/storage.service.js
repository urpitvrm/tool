import fs from 'node:fs';
import fsp from 'node:fs/promises';
import path from 'node:path';
import { randomUUID } from 'node:crypto';
import { config } from '../config/index.js';

// Local/persistent-volume storage for generated reports. Mount REPORT_STORAGE_DIR on durable
// storage (Docker volume, NFS, EFS, ...). The interface (save/open/remove) is intentionally small
// so an object-storage backend can be added without touching callers.
export const STORAGE_BACKEND = 'local';

function resolveKey(key) {
  const root = config.reports.storageDir;
  const resolved = path.resolve(root, key);
  if (!resolved.startsWith(root + path.sep)) throw Object.assign(new Error('Invalid storage key'), { status: 400 });
  return resolved;
}

export async function ensureStorage() {
  await fsp.mkdir(config.reports.storageDir, { recursive: true });
}

/** Persist a report file and return its storage key and size. */
export async function saveReportFile(buffer, extension) {
  const now = new Date();
  const key = path.posix.join(String(now.getUTCFullYear()), String(now.getUTCMonth() + 1).padStart(2, '0'), `${randomUUID()}.${extension}`);
  const target = resolveKey(key);
  await fsp.mkdir(path.dirname(target), { recursive: true });
  // Write to a temp name first so a crash never leaves a partial file under the final key.
  const temporary = `${target}.partial`;
  await fsp.writeFile(temporary, buffer, { mode: 0o640 });
  await fsp.rename(temporary, target);
  return { key, size: buffer.length };
}

export async function reportFileExists(key) {
  try {
    await fsp.access(resolveKey(key));
    return true;
  } catch {
    return false;
  }
}

export function openReportFile(key) {
  return fs.createReadStream(resolveKey(key));
}

export async function readReportFile(key) {
  return fsp.readFile(resolveKey(key));
}

export async function removeReportFile(key) {
  if (!key) return;
  await fsp.rm(resolveKey(key), { force: true });
}
