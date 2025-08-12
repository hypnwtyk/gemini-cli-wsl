/**
 * @license
 * Copyright 2025 Google LLC
 * SPDX-License-Identifier: Apache-2.0
 */

import {
  OAuth2Client,
  Credentials,
  Compute,
  CodeChallengeMethod,
} from 'google-auth-library';
import * as http from 'http';
import url from 'url';
import crypto from 'crypto';
import * as net from 'net';
// Use secure launcher to avoid WSL forwarding to Windows by xdg-open/wslview
import { openBrowserSecurely } from '../utils/secure-browser-launcher.js';
import path from 'node:path';
import { promises as fs } from 'node:fs';
import * as os from 'os';
import { Config } from '../config/config.js';
import { getErrorMessage } from '../utils/errors.js';
import {
  cacheGoogleAccount,
  getCachedGoogleAccount,
  clearCachedGoogleAccount,
} from '../utils/user_account.js';
import { AuthType } from '../core/contentGenerator.js';
import readline from 'node:readline';

//  OAuth Client ID used to initiate OAuth2Client class.
const OAUTH_CLIENT_ID =
  '681255809395-oo8ft2oprdrnp9e3aqf6av3hmdib135j.apps.googleusercontent.com';

// OAuth Secret value used to initiate OAuth2Client class.
// Note: It's ok to save this in git because this is an installed application
// as described here: https://developers.google.com/identity/protocols/oauth2#installed
// "The process results in a client ID and, in some cases, a client secret,
// which you embed in the source code of your application. (In this context,
// the client secret is obviously not treated as a secret.)"
const OAUTH_CLIENT_SECRET = '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';

// OAuth Scopes for Cloud Code authorization.
const OAUTH_SCOPE = [
  'https://www.googleapis.com/auth/cloud-platform',
  'https://www.googleapis.com/auth/userinfo.email',
  'https://www.googleapis.com/auth/userinfo.profile',
];

const HTTP_REDIRECT = 301;
const SIGN_IN_SUCCESS_URL =
  'https://developers.google.com/gemini-code-assist/auth_success_gemini';
const SIGN_IN_FAILURE_URL =
  'https://developers.google.com/gemini-code-assist/auth_failure_gemini';

const GEMINI_DIR = '.gemini';
const CREDENTIAL_FILENAME = 'oauth_creds.json';
const OAUTH_SERVER_TIMEOUT_MS = Number(process.env.OAUTH_TIMEOUT_MS || 300000);

/**
 * An Authentication URL for updating the credentials of a Oauth2Client
 * as well as a promise that will resolve when the credentials have
 * been refreshed (or which throws error when refreshing credentials failed).
 */
export interface OauthWebLogin {
  authUrl: string;
  loginCompletePromise: Promise<void>;
}

export async function getOauthClient(
  authType: AuthType,
  config: Config,
): Promise<OAuth2Client> {
  const client = new OAuth2Client({
    clientId: OAUTH_CLIENT_ID,
    clientSecret: OAUTH_CLIENT_SECRET,
    transporterOptions: {
      proxy: config.getProxy(),
    },
  });

  if (
    process.env.GOOGLE_GENAI_USE_GCA &&
    process.env.GOOGLE_CLOUD_ACCESS_TOKEN
  ) {
    client.setCredentials({
      access_token: process.env.GOOGLE_CLOUD_ACCESS_TOKEN,
    });
    await fetchAndCacheUserInfo(client);
    return client;
  }

  client.on('tokens', async (tokens: Credentials) => {
    await cacheCredentials(tokens);
  });

  // If there are cached creds on disk, they always take precedence
  if (await loadCachedCredentials(client)) {
    // Found valid cached credentials.
    // Check if we need to retrieve Google Account ID or Email
    if (!getCachedGoogleAccount()) {
      try {
        await fetchAndCacheUserInfo(client);
      } catch {
        // Non-fatal, continue with existing auth.
      }
    }
    console.log('Loaded cached credentials.');
    return client;
  }

  // In Google Cloud Shell, we can use Application Default Credentials (ADC)
  // provided via its metadata server to authenticate non-interactively using
  // the identity of the user logged into Cloud Shell.
  if (authType === AuthType.CLOUD_SHELL) {
    try {
      console.log("Attempting to authenticate via Cloud Shell VM's ADC.");
      const computeClient = new Compute({
        // We can leave this empty, since the metadata server will provide
        // the service account email.
      });
      await computeClient.getAccessToken();
      console.log('Authentication successful.');

      // Do not cache creds in this case; note that Compute client will handle its own refresh
      return computeClient;
    } catch (e) {
      throw new Error(
        `Could not authenticate using Cloud Shell credentials. Please select a different authentication method or ensure you are in a properly configured environment. Error: ${getErrorMessage(
          e,
        )}`,
      );
    }
  }

  if (config.isBrowserLaunchSuppressed()) {
    let success = false;
    const maxRetries = 2;
    for (let i = 0; !success && i < maxRetries; i++) {
      success = await authWithUserCode(client);
      if (!success) {
        console.error(
          '\nFailed to authenticate with user code.',
          i === maxRetries - 1 ? '' : 'Retrying...\n',
        );
      }
    }
    if (!success) {
      process.exit(1);
    }
  } else {
    const webLogin = await authWithWeb(client);

    console.log(
      `\n\nCode Assist login required.\n` +
        `Attempting to open authentication page in your browser.\n` +
        `Otherwise navigate to:\n\n${webLogin.authUrl}\n\n`,
    );
    try {
      // Attempt to open the authentication URL in a secure, WSL-aware way.
      await openBrowserSecurely(webLogin.authUrl);
    } catch (err) {
      console.error(
        'An unexpected error occurred while trying to open the browser:',
        err,
        '\nPlease try running again with NO_BROWSER=true set.',
      );
      process.exit(1);
    }
    console.log('Waiting for authentication...');

    await webLogin.loginCompletePromise;
  }

  return client;
}

function sanitizeLoopbackHost(input: string | undefined): string {
  const h = (input || '').trim().toLowerCase();
  // Prefer IPv4 loopback for widest compatibility in WSL/WSLg
  if (h === 'localhost' || h === '') return '127.0.0.1';
  if (h === '127.0.0.1' || h === '::1') return h;
  return '127.0.0.1';
}

function formatHostForUrl(host: string): string {
  // Wrap IPv6 literals in [] for URLs
  if (host.includes(':') && host !== 'localhost') return `[${host}]`;
  return host;
}

async function authWithUserCode(client: OAuth2Client): Promise<boolean> {
  const redirectUri = 'https://codeassist.google.com/authcode';
  const codeVerifier = await client.generateCodeVerifierAsync();
  const state = crypto.randomBytes(32).toString('hex');
  const authUrl: string = client.generateAuthUrl({
    redirect_uri: redirectUri,
    access_type: 'offline',
    scope: OAUTH_SCOPE,
    code_challenge_method: CodeChallengeMethod.S256,
    code_challenge: codeVerifier.codeChallenge,
    state,
  });
  console.log('Please visit the following URL to authorize the application:');
  console.log('');
  console.log(authUrl);
  console.log('');

  const code = await new Promise<string>((resolve) => {
    const rl = readline.createInterface({
      input: process.stdin,
      output: process.stdout,
    });
    rl.question('Enter the authorization code: ', (code) => {
      rl.close();
      resolve(code.trim());
    });
  });

  if (!code) {
    console.error('Authorization code is required.');
    return false;
  }

  try {
    const { tokens } = await client.getToken({
      code,
      codeVerifier: codeVerifier.codeVerifier,
      redirect_uri: redirectUri,
    });
    client.setCredentials(tokens);
  } catch (_error) {
    return false;
  }
  return true;
}

function isAuthDebug(): boolean {
  return (
    process.env.GEMINI_AUTH_DEBUG === '1' || process.env.GEMINI_DEBUG === '1'
  );
}

async function writeAuthDebug(message: string): Promise<void> {
  if (!isAuthDebug()) return;
  try {
    const logDir = path.join(os.homedir(), '.gemini');
    await fs.mkdir(logDir, { recursive: true });
    const logPath = path.join(logDir, 'auth-debug.log');
    const line = `[${new Date().toISOString()}] [oauth2] ${message}\n`;
    await fs.appendFile(logPath, line, 'utf8');
    // eslint-disable-next-line no-console
    console.error(line.trimEnd());
  } catch {}
}

async function authWithWeb(client: OAuth2Client): Promise<OauthWebLogin> {
  // Resolve the loopback host consistently for both server binding and redirect URL.
  // Only allow localhost, 127.0.0.1, or ::1 to avoid leaking the callback externally.
  const host = sanitizeLoopbackHost(process.env.OAUTH_CALLBACK_HOST);
  const state = crypto.randomBytes(32).toString('hex');
  let redirectUri = '';

  // Create the server first and bind to an ephemeral port on the selected host.
  // This guarantees the port is open before generating the redirect URL used by the browser.
  const server = http.createServer(async (req, res) => {
    try {
      const reqUrl = req.url || '';
      await writeAuthDebug(`Incoming request: ${req.method} ${reqUrl}`);
      if (!req.url) {
        res.writeHead(400);
        res.end('Bad Request');
        return;
      }
      const parsed = new url.URL(req.url, `http://${formatHostForUrl(host)}`);
      if (parsed.pathname === '/favicon.ico') {
        await writeAuthDebug('Ignoring /favicon.ico request');
        res.writeHead(204);
        res.end();
        return;
      }
      if (parsed.pathname !== '/oauth2callback') {
        await writeAuthDebug(`Unexpected path: ${parsed.pathname}`);
        res.writeHead(404);
        res.end('Not Found');
        return;
      }
      const qs = parsed.searchParams;
      if (qs.get('error')) {
        res.writeHead(HTTP_REDIRECT, { Location: SIGN_IN_FAILURE_URL });
        res.end();
        await writeAuthDebug(`Error param from provider: ${qs.get('error')}`);
        cleanupAndReject(
          new Error(`Error during authentication: ${qs.get('error')}`),
        );
        return;
      }
      if (qs.get('state') !== state) {
        res.end('State mismatch. Possible CSRF attack');
        await writeAuthDebug(
          `State mismatch. expected=${state} got=${qs.get('state')}`,
        );
        cleanupAndReject(new Error('State mismatch. Possible CSRF attack'));
        return;
      }
      const code = qs.get('code');
      if (!code) {
        await writeAuthDebug(
          'No authorization code found in callback request.',
        );
        res.writeHead(400);
        res.end('Missing code');
        return;
      }
      await writeAuthDebug(
        'Received authorization code. Exchanging for tokens...',
      );
      const { tokens } = await client.getToken({
        code,
        redirect_uri: redirectUri,
      });
      client.setCredentials(tokens);
      try {
        await fetchAndCacheUserInfo(client);
      } catch (error) {
        console.error(
          'Failed to retrieve Google Account ID during authentication:',
          error,
        );
      }
      await writeAuthDebug(
        'Token exchange succeeded. Redirecting to success page.',
      );
      res.writeHead(HTTP_REDIRECT, { Location: SIGN_IN_SUCCESS_URL });
      res.end();
      cleanupAndResolve();
    } catch (e) {
      await writeAuthDebug(`Callback handler exception: ${String(e)}`);
      cleanupAndReject(e as Error);
    }
  });

  let loginResolve: (() => void) | null = null;
  let loginReject: ((e: Error) => void) | null = null;
  let timeoutHandle: NodeJS.Timeout | null = null;
  const cleanupAndResolve = () => {
    if (timeoutHandle) clearTimeout(timeoutHandle);
    try {
      server.close();
    } catch {}
    if (loginResolve) loginResolve();
  };
  const cleanupAndReject = (e: Error) => {
    if (timeoutHandle) clearTimeout(timeoutHandle);
    try {
      server.close();
    } catch {}
    if (loginReject) loginReject(e);
  };

  const loginCompletePromise = new Promise<void>((resolve, reject) => {
    loginResolve = resolve;
    loginReject = reject;
  });

  // Bind and compute redirect URL
  const boundPort: number = await new Promise((resolve, reject) => {
    try {
      // In WSLg some Chrome builds may run in a different network namespace or obey host proxies.
      // Binding to 0.0.0.0 makes the listener reachable via the distro's local IP as well as 127.0.0.1.
      // We still only advertise the redirect on 127.0.0.1 to avoid external exposure.
      const listenHost =
        process.env.OAUTH_LISTEN_HOST ||
        (host === '127.0.0.1' ? '0.0.0.0' : host);
      server.listen(0, listenHost, () => {
        const address = server.address() as net.AddressInfo;
        resolve(address.port);
      });
    } catch (e) {
      reject(e);
    }
  });
  // Timeout to avoid hanging forever waiting for callback
  timeoutHandle = setTimeout(async () => {
    await writeAuthDebug(
      `OAuth server timeout after ${OAUTH_SERVER_TIMEOUT_MS}ms waiting for callback`,
    );
    cleanupAndReject(new Error('OAuth callback timeout'));
  }, OAUTH_SERVER_TIMEOUT_MS);
  redirectUri = `http://${formatHostForUrl(host)}:${boundPort}/oauth2callback`;
  await writeAuthDebug(
    `Auth server listening on ${host}:${boundPort}; redirectUri=${redirectUri}`,
  );

  const authUrl = client.generateAuthUrl({
    redirect_uri: redirectUri,
    access_type: 'offline',
    scope: OAUTH_SCOPE,
    state,
  });
  await writeAuthDebug(`Generated authUrl: ${authUrl}`);

  return { authUrl, loginCompletePromise };
}

export function getAvailablePort(): Promise<number> {
  return new Promise((resolve, reject) => {
    let port = 0;
    try {
      const portStr = process.env.OAUTH_CALLBACK_PORT;
      if (portStr) {
        port = parseInt(portStr, 10);
        if (isNaN(port) || port <= 0 || port > 65535) {
          return reject(
            new Error(`Invalid value for OAUTH_CALLBACK_PORT: "${portStr}"`),
          );
        }
        return resolve(port);
      }
      const server = net.createServer();
      server.listen(0, () => {
        const address = server.address()! as net.AddressInfo;
        port = address.port;
      });
      server.on('listening', () => {
        server.close();
        server.unref();
      });
      server.on('error', (e) => reject(e));
      server.on('close', () => resolve(port));
    } catch (e) {
      reject(e);
    }
  });
}

async function loadCachedCredentials(client: OAuth2Client): Promise<boolean> {
  try {
    const keyFile =
      process.env.GOOGLE_APPLICATION_CREDENTIALS || getCachedCredentialPath();

    const creds = await fs.readFile(keyFile, 'utf-8');
    client.setCredentials(JSON.parse(creds));

    // This will verify locally that the credentials look good.
    const { token } = await client.getAccessToken();
    if (!token) {
      return false;
    }

    // This will check with the server to see if it hasn't been revoked.
    await client.getTokenInfo(token);

    return true;
  } catch (_) {
    return false;
  }
}

async function cacheCredentials(credentials: Credentials) {
  const filePath = getCachedCredentialPath();
  await fs.mkdir(path.dirname(filePath), { recursive: true });

  const credString = JSON.stringify(credentials, null, 2);
  await fs.writeFile(filePath, credString, { mode: 0o600 });
}

function getCachedCredentialPath(): string {
  return path.join(os.homedir(), GEMINI_DIR, CREDENTIAL_FILENAME);
}

export async function clearCachedCredentialFile() {
  try {
    await fs.rm(getCachedCredentialPath(), { force: true });
    // Clear the Google Account ID cache when credentials are cleared
    await clearCachedGoogleAccount();
  } catch (_) {
    /* empty */
  }
}

async function fetchAndCacheUserInfo(client: OAuth2Client): Promise<void> {
  try {
    const { token } = await client.getAccessToken();
    if (!token) {
      return;
    }

    const response = await fetch(
      'https://www.googleapis.com/oauth2/v2/userinfo',
      {
        headers: {
          Authorization: `Bearer ${token}`,
        },
      },
    );

    if (!response.ok) {
      console.error(
        'Failed to fetch user info:',
        response.status,
        response.statusText,
      );
      return;
    }

    const userInfo = await response.json();
    if (userInfo.email) {
      await cacheGoogleAccount(userInfo.email);
    }
  } catch (error) {
    console.error('Error retrieving user info:', error);
  }
}
