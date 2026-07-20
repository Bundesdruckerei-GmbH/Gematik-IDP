/**
 * Local HTTP Server poller – periodically checks whether the local HTTP server started
 * by the new Gematik‑Authenticator is reachable. When the server responds, the poller claims
 * ownership of the authentication flow.
 */

let _intervalId = null;
let _timeoutId = null;
/**
 * Internal flag indicating whether a fetch request is currently in progress.
 * This prevents overlapping fetches when the network is slow and the poll interval
 * fires before the previous request resolves.
 */
let _isFetching = false;

/**
 * Starts the poller. The poller periodically attempts to fetch the local HTTP server
 * started by the Authenticator 4.17.0. The target URL is now constructed by the backend
 * and stored in sessionStorage (see PROBE_AUTH_SERVER_URL). Therefore the explicit
 * {@code serverPort} argument is no longer required.
 *
 * @param {Object} config
 * @param {String} config.handshakeId - handshake identifier loaded from the configuration and forwarded to
 * @param {number} [config.timeout=60000] – Maximum time to keep trying before giving up.
 * @param {number} [config.pollInterval=1000] – Interval between fetch attempts (ms).
 */
function startLocalHttpServerPoller({handshakeId, timeout = 10_000, pollInterval = 1000}) {
    // Guard against starting the poller multiple times.
    if (_intervalId !== null) {
        console.warn('Local HTTP Server poller already started – ignoring subsequent start call.');
        return;
    }
    // Periodically check the local server and claim the authenticator when appropriate.
    _intervalId = setInterval(async () => {
        // Prevent overlapping fetches.
        if (_isFetching) {
            return;
        }
        _isFetching = true;
        try {
            const {reachable, handshakeMatch} = await probeServer({handshakeId});

            if (!reachable) {
                return;
            }

            const handshakeOk =
                handshakeId === undefined || handshakeMatch === true;

            if (handshakeOk) {
                const claimed = claimAuthenticatorIfPossible();
                if (claimed) {
                    stopLocalHttpServerPoller();
                } else {
                    console.info('claimAuthenticator not available – continuing poller.');
                }
            } else {
                console.info('Authenticator reachable but handshake_id mismatch; continuing poller.');
            }
        } catch (e) {
            console.error('localHTTPServerPoller interval error:', e);
        } finally {
            // Reset fetching flag so the next interval can run.
            _isFetching = false;
        }
    }, pollInterval);

    // After the maximum wait time we stop trying and let the legacy poller continue.
    _timeoutId = setTimeout(() => {
        console.warn(`Local HTTP server poller timeout of ${timeout}ms exceeded – stopping poller.`);
        stopLocalHttpServerPoller();
    }, timeout);
}

/**
 * Helper that checks the readiness probe defined at GET /status.
 * Verify that the server reports the expected handshake identifier.
 * Returns true when the handshake matches; otherwise false.
 **/
/**
 * Helper that checks the readiness probe defined at GET /status.
 * The URL is obtained from sessionStorage (PROBE_AUTH_SERVER_URL).
 * The previously accepted {@code port} argument is removed because the URL already
 * contains the correct host and port information.
 */
async function probeServer({handshakeId} = {}) {

    let probeAuthenticatorUrl = sessionStorage.getItem(PROBE_AUTH_SERVER_URL);

    try {
        // Per‑request timeout using AbortController (mirrors hasReachableHttpService implementation).
        const controller = new AbortController();
        // Default timeout of 5 seconds; adjust if needed.
        const FETCH_TIMEOUT_MS = 5000;
        const timeoutId = globalThis.setTimeout(() => controller.abort(), FETCH_TIMEOUT_MS);
        const resp = await fetch(probeAuthenticatorUrl, {
            method: "GET",
            mode: "cors",
            cache: "no-store",
            signal: controller.signal,
        });
        // Clear timeout after fetch completes.
        globalThis.clearTimeout(timeoutId);

        const reachable = resp.ok;
        if (!reachable) {
            return {reachable};
        }

        const json = await resp.json();

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
    }
}

/**
 * Attempts to claim the Gematik Authenticator using the globally provided
 * `claimAuthenticator` hook.
 *
 * The function checks whether `globalThis.claimAuthenticator` is a function.
 * If present, it is invoked with the hard‑coded authenticator version string
 * "v4.17" and a descriptive message.  The return value of the hook (if any) is
 * coerced to a boolean and returned to the caller so the poller can decide
 * whether to stop or continue.
 *
 * @returns {boolean} `true` when the claim hook was called and returned a truthy
 *                    value, otherwise `false`.
 */
function claimAuthenticatorIfPossible() {
    // Use the literal version expected by consumers/tests.
    const authenticatorVersion = "v4.17";
    let claimFn = null;
    if (typeof globalThis.claimAuthenticator === "function") {
        claimFn = globalThis.claimAuthenticator;
    }
    if (claimFn) {
        // Propagate the boolean result of the claim function (if it returns a value).
        const result = claimFn(
            authenticatorVersion,
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
    if (_intervalId !== null) {
        clearInterval(_intervalId);
        _intervalId = null;
    }
    if (_timeoutId !== null) {
        clearTimeout(_timeoutId);
        _timeoutId = null;
    }
    // Ensure the fetching flag is cleared in case a request was in flight.
    _isFetching = false;
}

if (typeof module !== "undefined" && module.exports !== undefined) {
    module.exports = {startLocalHttpServerPoller, stopLocalHttpServerPoller};
}

if (typeof globalThis !== "undefined") {
    globalThis.startLocalHttpServerPoller = startLocalHttpServerPoller;
    globalThis.stopLocalHttpServerPoller = stopLocalHttpServerPoller;
}
