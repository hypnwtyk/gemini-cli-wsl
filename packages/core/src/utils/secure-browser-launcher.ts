/**
 * @license
 * Copyright 2025 Google LLC
 * SPDX-License-Identifier: Apache-2.0
 */

import { execFile, spawn, type SpawnOptions } from 'node:child_process';
import { promisify } from 'node:util';
import { promises as fs } from 'node:fs';
import path from 'node:path';
import os from 'node:os';
import { platform } from 'node:os';
import { URL } from 'node:url';
import { isWSL as coreIsWSL } from './browser.js';

const execFileAsync = promisify(execFile);

function isAuthDebug(): boolean {
  return process.env.GEMINI_AUTH_DEBUG === '1' || process.env.GEMINI_DEBUG === '1';
}

async function writeAuthDebug(message: string): Promise<void> {
  if (!isAuthDebug()) return;
  try {
    const logDir = path.join(os.homedir(), '.gemini');
    await fs.mkdir(logDir, { recursive: true });
    const logPath = path.join(logDir, 'auth-debug.log');
    const line = `[${new Date().toISOString()}] [secure-browser-launcher] ${message}\n`;
    await fs.appendFile(logPath, line, 'utf8');
    // Also echo to stderr for immediate visibility
    // eslint-disable-next-line no-console
    console.error(line.trimEnd());
  } catch {
    // ignore
  }
}

/**
 * Validates that a URL is safe to open in a browser.
 * Only allows HTTP and HTTPS URLs to prevent command injection.
 *
 * @param url The URL to validate
 * @throws Error if the URL is invalid or uses an unsafe protocol
 */
function validateUrl(url: string): void {
  let parsedUrl: URL;

  try {
    parsedUrl = new URL(url);
  } catch (_error) {
    throw new Error(`Invalid URL: ${url}`);
  }

  // Only allow HTTP and HTTPS protocols
  if (parsedUrl.protocol !== 'http:' && parsedUrl.protocol !== 'https:') {
    throw new Error(
      `Unsafe protocol: ${parsedUrl.protocol}. Only HTTP and HTTPS are allowed.`,
    );
  }

  // Additional validation: ensure no newlines or control characters
  // eslint-disable-next-line no-control-regex
  if (/[\r\n\x00-\x1f]/.test(url)) {
    throw new Error('URL contains invalid characters');
  }
}

/**
 * Opens a URL in the default browser using platform-specific commands.
 * This implementation avoids shell injection vulnerabilities by:
 * 1. Validating the URL to ensure it's HTTP/HTTPS only
 * 2. Using execFile instead of exec to avoid shell interpretation
 * 3. Passing the URL as an argument rather than constructing a command string
 *
 * @param url The URL to open
 * @throws Error if the URL is invalid or if opening the browser fails
 */
export async function openBrowserSecurely(url: string): Promise<void> {
  // Validate the URL first
  validateUrl(url);

  const platformName = platform();
  let command: string;
  let args: string[];

  switch (platformName) {
    case 'darwin':
      // macOS
      command = 'open';
      args = [url];
      break;

    case 'win32':
      // Windows - use PowerShell with Start-Process
      // This avoids the cmd.exe shell which is vulnerable to injection
      command = 'powershell.exe';
      args = [
        '-NoProfile',
        '-NonInteractive',
        '-WindowStyle',
        'Hidden',
        '-Command',
        `Start-Process '${url.replace(/'/g, "''")}'`,
      ];
      break;

    case 'linux':
    case 'freebsd':
    case 'openbsd':
      // Linux and BSD variants
      await writeAuthDebug(
        `Platform=${platformName} BROWSER=${process.env.BROWSER || ''} DISPLAY=${
          process.env.DISPLAY || ''
        } WAYLAND_DISPLAY=${process.env.WAYLAND_DISPLAY || ''} isWSL=${isWSL()}`,
      );
      // First, honor an explicit BROWSER if it's a valid Linux binary path
      {
        const forced = resolveBrowserFromEnv();
        if (forced) {
          await writeAuthDebug(`Using BROWSER override: ${forced}`);
          command = forced;
          args = [url];
          break;
        }
      }
      // If running under WSL, prefer native Linux browsers over Windows default.
      if (isWSL()) {
        const candidate = detectLinuxBrowserCandidate();
        if (candidate) {
          await writeAuthDebug(`Detected browser candidate: ${candidate}`);
          command = candidate;
          args = [url];
          break;
        }
        // If we detected WSLg (display present) but no known browser was found,
        // try to auto-detect a .desktop default and resolve it to a real binary.
        const desktopDefault = resolveDefaultLinuxBrowser();
        if (desktopDefault) {
          await writeAuthDebug(`Using desktop default browser: ${desktopDefault}`);
          command = desktopDefault;
          args = [url];
          break;
        }
        await writeAuthDebug('No browser found via which/desktop default under WSL. Falling back to xdg-open');
      }
      // Try xdg-open first, fall back to other options
      command = 'xdg-open';
      args = [url];
      break;

    default:
      throw new Error(`Unsupported platform: ${platformName}`);
  }

  const spawnOptions: SpawnOptions = {
    env: {
      ...process.env,
      SHELL: undefined,
    },
    detached: true,
    stdio: 'ignore',
  };

  try {
    await writeAuthDebug(`Launching browser: ${command} ${args.join(' ')}`);
    // Use spawn so we don't wait for the browser process to exit.
    await new Promise<void>((resolve, reject) => {
      const child = spawn(command, args, spawnOptions);
      child.once('spawn', () => {
        try {
          child.unref();
        } catch {}
        void writeAuthDebug('Browser process spawned successfully');
        resolve();
      });
      child.once('error', reject);
    });
  } catch (error) {
    await writeAuthDebug(
      `Primary launch failed for ${command}: ${error instanceof Error ? error.message : String(error)}`,
    );
    // For Linux, try fallback commands if xdg-open fails
    if (
      (platformName === 'linux' ||
        platformName === 'freebsd' ||
        platformName === 'openbsd') &&
      command === 'xdg-open'
    ) {
      const fallbackCommands = [
        'gnome-open',
        'kde-open',
        'firefox',
        'chromium',
        'google-chrome',
        'brave-browser',
        'microsoft-edge',
        'opera',
        'vivaldi',
      ];

      for (const fallbackCommand of fallbackCommands) {
        try {
          await writeAuthDebug(`Attempting fallback browser: ${fallbackCommand}`);
          await new Promise<void>((resolve, reject) => {
            const child = spawn(fallbackCommand, [url], spawnOptions);
            child.once('spawn', () => {
              try {
                child.unref();
              } catch {}
              void writeAuthDebug(`Fallback spawned: ${fallbackCommand}`);
              resolve();
            });
            child.once('error', reject);
          });
          return; // Success!
        } catch {
          await writeAuthDebug(`Fallback failed: ${fallbackCommand}`);
          continue;
        }
      }
    }

    // Re-throw the error if all attempts failed
    throw new Error(
      `Failed to open browser: ${error instanceof Error ? error.message : 'Unknown error'}`,
    );
  }
}

/** Detect if running inside Windows Subsystem for Linux (WSL). */
function isWSL(): boolean {
  // Delegate to the shared detector to keep logic consistent
  return coreIsWSL();
}

/**
 * If BROWSER is set, resolve it to an absolute Linux path and validate that it
 * points to a browser binary within the current distro (not a Windows path or wslview).
 */
function resolveBrowserFromEnv(): string | null {
  const b = process.env.BROWSER?.trim();
  if (!b) return null;
  // Strip desktop placeholders like "%U"
  const token = b.split(/\s+/)[0];
  if (!token || token.toLowerCase() === 'wslview') return null;
  const { spawnSync } =
    require('node:child_process') as typeof import('node:child_process');
  const fs = require('node:fs') as typeof import('node:fs');
  // If absolute path, verify it exists and is not a Windows mount
  if (token.startsWith('/')) {
    try {
      fs.accessSync(token, fs.constants.X_OK);
      if (!isWindowsMountedPath(token)) return token;
    } catch {
      return null;
    }
    return null;
  }
  // Resolve via which
  const res = spawnSync('which', [token], { encoding: 'utf8' });
  if (res.status === 0) {
    const resolved = String(res.stdout || '').trim();
    if (
      resolved &&
      !isWindowsMountedPath(resolved) &&
      resolved.toLowerCase() !== 'wslview'
    ) {
      return resolved;
    }
  }
  return null;
}

/**
 * Attempt to find a native Linux browser binary to use under WSL.
 * Returns the command name if found, otherwise null.
 */
function detectLinuxBrowserCandidate(): string | null {
  try {
    const { spawnSync } =
      require('node:child_process') as typeof import('node:child_process');
    // Prefer Chrome/Chromium-family by default; fall back to others if absent
    const candidates = [
      'google-chrome-stable',
      'google-chrome',
      'chromium-browser',
      'chromium',
      'microsoft-edge',
      'brave-browser',
      'firefox',
      'opera',
      'vivaldi',
    ];
    for (const name of candidates) {
      const res = spawnSync('which', [name], { encoding: 'utf8' });
      if (res.status === 0) {
        const p = String(res.stdout || '').trim();
        if (p && !isWindowsMountedPath(p)) return p;
      }
    }
  } catch {
    // ignore
  }
  return null;
}

/** Windows paths mounted into WSL appear under /mnt/<drive>/... */
function isWindowsMountedPath(p: string): boolean {
  return p.startsWith('/mnt/');
}

/**
 * Resolve the user's default Linux browser via xdg-settings/xdg-mime and convert
 * it to an executable path (rejecting Windows mounts and wslview).
 */
function resolveDefaultLinuxBrowser(): string | null {
  try {
    const { spawnSync } =
      require('node:child_process') as typeof import('node:child_process');
    // Try xdg-settings first
    const out = spawnSync('xdg-settings', ['get', 'default-web-browser'], {
      encoding: 'utf8',
    });
    let desktop = '';
    if (out.status === 0) desktop = String(out.stdout || '').trim();
    if (!desktop) {
      // Fallback: read default app for text/html
      const mime = spawnSync('xdg-mime', ['query', 'default', 'text/html'], {
        encoding: 'utf8',
      });
      if (mime.status === 0) desktop = String(mime.stdout || '').trim();
    }
    if (!desktop) return null;

    // Map common .desktop names to binaries
    const map: Record<string, string[]> = {
      'google-chrome.desktop': ['google-chrome-stable', 'google-chrome'],
      'chromium.desktop': ['chromium-browser', 'chromium'],
      'brave-browser.desktop': ['brave-browser'],
      'microsoft-edge.desktop': ['microsoft-edge'],
      'firefox.desktop': ['firefox'],
      'opera.desktop': ['opera'],
      'vivaldi-stable.desktop': ['vivaldi'],
    };
    const candidates = map[desktop] || [];
    for (const bin of candidates) {
      const r = spawnSync('which', [bin], { encoding: 'utf8' });
      if (r.status === 0) {
        const p = String(r.stdout || '').trim();
        if (p && !isWindowsMountedPath(p)) return p;
      }
    }
  } catch {
    // ignore
  }
  return null;
}

/**
 * Checks if the current environment should attempt to launch a browser.
 * This is the same logic as in browser.ts for consistency.
 *
 * @returns True if the tool should attempt to launch a browser
 */
export function shouldLaunchBrowser(): boolean {
  // A list of browser names that indicate we should not attempt to open a
  // web browser for the user.
  const browserBlocklist = ['www-browser'];
  const browserEnv = process.env.BROWSER;
  if (browserEnv && browserBlocklist.includes(browserEnv)) {
    return false;
  }

  // Common environment variables used in CI/CD or other non-interactive shells.
  if (process.env.CI || process.env.DEBIAN_FRONTEND === 'noninteractive') {
    return false;
  }

  // The presence of SSH_CONNECTION indicates a remote session.
  // We should not attempt to launch a browser unless a display is explicitly available
  // (checked below for Linux).
  const isSSH = !!process.env.SSH_CONNECTION;

  // On Linux, the presence of a display server is a strong indicator of a GUI.
  if (platform() === 'linux') {
    // These are environment variables that can indicate a running compositor on Linux.
    const displayVariables = ['DISPLAY', 'WAYLAND_DISPLAY', 'MIR_SOCKET'];
    const hasDisplay = displayVariables.some((v) => !!process.env[v]);
    if (!hasDisplay) {
      return false;
    }
  }

  // If in an SSH session on a non-Linux OS (e.g., macOS), don't launch browser.
  // The Linux case is handled above (it's allowed if DISPLAY is set).
  if (isSSH && platform() !== 'linux') {
    return false;
  }

  // For non-Linux OSes, we generally assume a GUI is available
  // unless other signals (like SSH) suggest otherwise.
  return true;
}
