/**
 * @license
 * Copyright 2025 Google LLC
 * SPDX-License-Identifier: Apache-2.0
 */

/**
 * Determines if we should attempt to launch a browser for authentication
 * based on the user's environment.
 *
 * This is an adaptation of the logic from the Google Cloud SDK.
 * @returns True if the tool should attempt to launch a browser.
 */
export function shouldAttemptBrowserLaunch(): boolean {
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

  // On Linux (including WSL), ensure a display server is available and, for WSL,
  // that a Linux GUI browser is present to avoid falling back to Windows browsers.
  if (process.platform === 'linux') {
    const hasDisplay = linuxHasDisplay();
    if (!hasDisplay) {
      return false;
    }
    // If running inside WSL, prefer not to auto-launch unless a Linux browser is installed.
    if (isWSL() && !linuxHasInstalledBrowser()) {
      return false;
    }
  }

  // If in an SSH session on a non-Linux OS (e.g., macOS), don't launch browser.
  // The Linux case is handled above (it's allowed if DISPLAY is set).
  if (isSSH && process.platform !== 'linux') {
    return false;
  }

  // For non-Linux OSes, we generally assume a GUI is available
  // unless other signals (like SSH) suggest otherwise.
  // The `open` command's error handling will catch final edge cases.
  return true;
}

/**
 * Detect if running inside Windows Subsystem for Linux (WSL).
 * Uses common environment signals and kernel release string.
 */
function isWSL(): boolean {
  if (process.platform !== 'linux') return false;
  if (process.env.WSL_DISTRO_NAME || process.env.WSL_INTEROP) return true;
  try {
    const os = require('node:os') as typeof import('node:os');
    const release = String(os.release()).toLowerCase();
    if (release.includes('microsoft')) return true;
  } catch {
    // ignore
  }
  try {
    const fs = require('node:fs') as typeof import('node:fs');
    const version = fs.readFileSync('/proc/version', 'utf8').toLowerCase();
    if (version.includes('microsoft')) return true;
  } catch {
    // ignore
  }
  return false;
}

/**
 * Check if a Linux display server is available (X11/Wayland/Mir).
 */
function linuxHasDisplay(): boolean {
  const displayVariables = ['DISPLAY', 'WAYLAND_DISPLAY', 'MIR_SOCKET'];
  return displayVariables.some((v) => !!process.env[v]);
}

/**
 * Detect if a known Linux browser binary is on PATH.
 * This is used in WSL to avoid launching the Windows browser via wslview/xdg-open.
 */
function linuxHasInstalledBrowser(): boolean {
  try {
    const { spawnSync } =
      require('node:child_process') as typeof import('node:child_process');
    // Only consider native browser binaries; do not count xdg-open, which can
    // forward to Windows browsers via wslview under WSL.
    const candidates = [
      'firefox',
      'chromium',
      'google-chrome',
      'brave-browser',
      'microsoft-edge',
      'opera',
      'vivaldi',
    ];
    for (const name of candidates) {
      const res = spawnSync('which', [name], { stdio: 'ignore' });
      if (res.status === 0) return true;
    }
  } catch {
    // ignore
  }
  return false;
}
