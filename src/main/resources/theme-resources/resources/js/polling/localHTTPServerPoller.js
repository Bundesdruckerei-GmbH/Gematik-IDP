/*
 * Copyright 2026 Bundesdruckerei GmbH and/or its affiliates
 * and other contributors.
 *
 *  Licensed under the Apache License, Version 2.0 (the "License");
 *  you may not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *  http://www.apache.org/licenses/LICENSE-2.0
 *
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 */

/**
 * Local HTTP Server poller – periodically checks whether the local HTTP server started
 * by the new Gematik‑Authenticator is reachable. When the server responds, the poller claims
 * ownership of the authentication flow.
 */

// The poller is now created via the generic `createPoller` factory defined in
// `gematik-idp.js`. The previous manual interval/timeout variables are no longer
// needed.
let _poller = null;

function getAuthenticatorVersion() {
    return typeof globalThis.V4_17 === "string" ? globalThis.V4_17 : "v4.17";
}

/**
 * Starts the poller. The poller periodically attempts to fetch the local HTTP server
 * started by the Authenticator 4.17.0. The target URL is constructed by the backend
 * and stored in sessionStorage (see PROBE_AUTH_SERVER_URL).
 * @param {String} handshakeId - handshake identifier loaded from the configuration and forwarded to
 * @param {number} [timeout=10000] – Maximum time to keep trying before giving up.
 * @param {number} [pollInterval=500] – Interval between fetch attempts (ms).
 */
function startLocalHttpServerPoller({handshakeId, timeout = 10_000, pollInterval = 500} = {}) {
    if (_poller !== null) {
        console.warn('Local HTTP Server poller already started – ignoring subsequent start call.');
        return;
    }

    const probeAuthenticatorUrl = sessionStorage.getItem(PROBE_AUTH_SERVER_URL);
    if (!probeAuthenticatorUrl) {
        console.warn('Probe authenticator URL is not set or empty.');
        return;
    }

    const pollFn = async ({handshakeId: hsId}) => {
        const {reachable, handshakeMatch} = await probeServer({handshakeId: hsId, probeUrl: probeAuthenticatorUrl});
        if (!reachable) {
            return false; // keep polling
        }

        const handshakeOk = hsId === undefined || handshakeMatch === true;
        if (handshakeOk) {
            const claimed = claimAuthenticatorIfPossible();
            if (claimed) {
                // Returning true signals the factory to stop the poller.
                return true;
            }
            console.info('claimAuthenticator not available – continuing poller.');
        } else {
            console.info('Authenticator reachable but handshake_id mismatch; continuing poller.');
        }
        return false;
    };

    _poller = createPoller(pollFn);
    // The factory handles its own timeout handling; we only forward timeoutUrl if needed.
    _poller.start({timeout, pollInterval, handshakeId, timeoutUrl: undefined});
}

/**
 * Helper that checks the readiness probe defined at GET /status.
 * The URL is obtained from sessionStorage (PROBE_AUTH_SERVER_URL).
 */
async function probeServer({handshakeId, probeUrl} = {}) {
    let timeoutId;

    try {
        // Per‑request timeout using AbortController (mirrors hasReachableHttpService implementation).
        const controller = new AbortController();
        // Default timeout of 5 seconds; adjust if needed.
        const FETCH_TIMEOUT_MS = 5000;
        timeoutId = globalThis.setTimeout(() => controller.abort(), FETCH_TIMEOUT_MS);
        const resp = await fetch(probeUrl, {
            method: "GET",
            mode: "cors",
            cache: "no-store",
            signal: controller.signal,
        });

        const reachable = resp.ok;
        if (!reachable) {
            return {reachable};
        }

        const json = await resp.json();
        if (json.status !== "ready") {
            return {reachable: false};
        }

        const version = typeof json.version === "string" ? json.version : null;
        if (version === null) {
            sessionStorage.removeItem(AUTHENTICATOR_VERSION);
        } else {
            sessionStorage.setItem(AUTHENTICATOR_VERSION, version);
        }

        const result = {reachable};

        if (handshakeId !== undefined) {
            const echoed = json.handshake_id ?? json.handshakeId;
            result.handshakeMatch = echoed != null && String(echoed) === String(handshakeId);
        }
        return result;
    } catch {
        return {reachable: false};
    } finally {
        // Clear timeout after fetch completes.
        if (timeoutId !== undefined) {
            globalThis.clearTimeout(timeoutId);
        }
    }
}

/**
 * Attempts to claim the Gematik Authenticator using the globally provided
 * `claimAuthenticator` hook.
 *
 * The function checks whether `globalThis.claimAuthenticator` is a function.
 * If present, it is invoked with the authenticator version constant defined
 * above and a descriptive message. The return value of the hook (if any) is
 * coerced to a boolean and returned to the caller so the poller can decide
 * whether to stop or continue.
 *
 * @returns {boolean} `true` when the claim hook was called and returned a truthy
 *                    value, otherwise `false`.
 */
function claimAuthenticatorIfPossible() {
    // Use the module‑level constant that already resolves the global version.
    let claimFn = null;
    if (typeof globalThis.claimAuthenticator === "function") {
        claimFn = globalThis.claimAuthenticator;
    }
    if (claimFn) {
        // Propagate the boolean result of the claim function (if it returns a value).
        const result = claimFn(
            getAuthenticatorVersion(),
            "Authenticator 4.17.0 detected via localhost server"
        );
        return Boolean(result);
    }
    return false;
}

/**
 * Stops the poller and clears any scheduled timers.
 */
function stopLocalHttpServerPoller() {
    if (_poller !== null) {
        _poller.stop();
        _poller = null;
    }
}

if (typeof module !== "undefined" && module.exports !== undefined) {
    module.exports = {startLocalHttpServerPoller, stopLocalHttpServerPoller};
}

if (typeof globalThis !== "undefined") {
    globalThis.startLocalHttpServerPoller = startLocalHttpServerPoller;
    globalThis.stopLocalHttpServerPoller = stopLocalHttpServerPoller;
}
