/*
 * Copyright 2025 Bundesdruckerei GmbH and/or its affiliates
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
 * Coordination state for the two possible authenticators.
 * Only one authenticator can become active for a login attempt.
 */
let activeAuthenticator = null;

const V4_16_1 = "v4.16.1";
const V4_17 = "v4.17";
// The authenticator flow state persistence (sessionStorage) has been removed
// because the required data is now supplied directly by the gematik‑idp plugin.
// Keeping the related constants would introduce unused-code warnings.

// Expose version constant globally for other scripts (e.g., poller) to reference.
if (typeof globalThis !== "undefined") {
    globalThis.V4_17 = V4_17;
}

const HANDSHAKE_ID_KEY = "gematikIdp.handshakeId";
const AUTH_REQ_URL = "gematikIdp.authorizeUrl";
const PROBE_AUTH_SERVER_URL = "gematikIdp.probeAuthenticatorServerUrl";
const AUTHENTICATOR_VERSION = "gematikIdp.authenticatorVersion"
const AUTHENTICATOR_VERSION_PARAM = "authenticator_version"

/**
 * Shared ownership arbitration. Called by the "v4.16.1" and the "v4.17"
 * poller when they detect that they should take control.
 *
 * @param {"v4.16.1"|"v4.17"} type - Which authenticator claims ownership.
 * @param {string} reason - Human‑readable reason for the claim (used for logging).
 * @returns {boolean} true if the claim was accepted, false if another authenticator is already active.
 */
function claimAuthenticator(type, reason) {
    if (activeAuthenticator !== null) {
        console.info(`Authenticator already selected: ${activeAuthenticator}. Ignoring claim from ${type}.`);
        return false;
    }

    activeAuthenticator = type;
    console.info(`Authenticator selected: ${type}. Reason: ${reason}`);

    if (type === V4_16_1) {
        stopLocalHttpServerPoller?.();
    }
    if (type === V4_17) {
        legacyPoller?.stop?.();
        callAuthorizeEndpoint();
    }
    return true;
}

/**
 * Navigates the browser to the authentication request URL.
 *
 * The backend {@code authRequest} endpoint returns a 302 redirect. By assigning
 * the URL to `location.href` (via `location.assign`) the browser follows the
 * redirect automatically. This call is synchronous and does not throw, so the
 * function is deliberately not declared as `async` and returns no Promise.
 */
function callAuthorizeEndpoint() {
    const authRequestUrl = sessionStorage.getItem(AUTH_REQ_URL);
    if (!authRequestUrl) {
        console.error('Missing auth request URL in session storage');
        return;
    }

    // Append authenticator version if available.
    const version = sessionStorage.getItem(AUTHENTICATOR_VERSION);
    const requestUrl = new URL(authRequestUrl);
    if (version) {
        requestUrl.searchParams.set(AUTHENTICATOR_VERSION_PARAM, version);
    }

    // `location.assign` is synchronous; any error would be a programming error
    // and would surface as an exception automatically.
    location.assign(requestUrl.toString());
}

/**
 * Legacy poller – polls the status endpoint used by the original authenticator.
 */
let legacyPoller = {
    _intervalId: null,
    _timeoutId: null,
    // Guard flag – true while a fetch request is in flight.
    _isFetching: false,
    start({statusUrl, timeoutUrl, timeout = 60000, pollInterval = 1000}) {
        // Explicit version identifier for the legacy poller (v4.16.1 or earlier).
        console.log('v4.16.1 poller checking statusUrl');

        if (!statusUrl) {
            return;
        }
        this._intervalId = setInterval(async () => {
            // Prevent overlapping fetches – if a request is already in progress, skip this tick.
            if (this._isFetching) {
                return;
            }
            this._isFetching = true;
            try {
                const response = await fetch(statusUrl);
                const json = await response.json();
                // Prefix‑based detection of RECEIVED* statuses.
                // Use optional chaining to safely check the step prefix.
                if (json.currentStep?.startsWith("RECEIVED")) {
                    // Use explicit version identifier for legacy authenticator claims.
                    if (claimAuthenticator(V4_16_1, `v4.16.1 or earlier getStatus returned ${json.currentStep}`)) {
                        // Ownership granted – redirect to the next step.
                        location.assign(json.nextStepUrl);
                    }
                } else if (json.currentStep === "ERROR") {
                    // Treat error as a terminal condition.
                    if (claimAuthenticator(V4_16_1, "v4.16.1 or earlier poller encountered ERROR")) {
                        location.assign(json.nextStepUrl);
                    }
                }
            } catch (e) {
                console.error(`Legacy poller error: ${e}`);
            } finally {
                // Ensure the flag is cleared irrespective of success or error.
                this._isFetching = false;
            }
        }, pollInterval);

        this._timeoutId = setTimeout(() => {
            this.stop();
            if (timeoutUrl) {
                location.assign(timeoutUrl);
            }
        }, timeout);
    },
    stop() {

        if (this._intervalId !== null) {
            clearInterval(this._intervalId);
            this._intervalId = null;
        }
        if (this._timeoutId !== null) {
            clearTimeout(this._timeoutId);
            this._timeoutId = null;
        }
        // Reset fetching flag in case a request was in flight when stop is called.
        this._isFetching = false;
    }
};

function buildPreflightUrlFromLoginUrl(loginUrl) {
    const url = new URL(loginUrl, globalThis.location.origin);

    url.pathname = url.pathname.replace(/\/login$/, "/endpoint/preflight");
    url.search = "";

    return url.toString();
}

if (globalThis.global !== undefined) {
    const {findFreePort} = require("./utils/freePortHelper.js");
    globalThis.findFreePort = findFreePort;
    globalThis.handleGematikLoginClick = handleGematikLoginClick;
}

/**
 * Retrieves the port‑range configuration from the pre‑flight endpoint.
 *
 * A per‑request timeout is applied using an {@link AbortController}. This
 * mirrors the pattern used in {@code freePortHelper.js#hasReachableHttpService}
 * and prevents the fetch from hanging indefinitely.
 *
 * @param {string} preflightUrl - The URL of the pre‑flight endpoint.
 * @param {number} [timeoutMs=5000] - Optional timeout in milliseconds. If the
 *        request does not complete within this period it will be aborted and
 *        an error will be thrown.
 * @returns {Promise<Object>} The parsed JSON response.
 */
async function getAuthenticatorPortRangeConfig(preflightUrl, timeoutMs = 5000) {
    const controller = new AbortController();
    const timeoutId = globalThis.setTimeout(() => controller.abort(), timeoutMs);
    try {
        const response = await fetch(preflightUrl, {
            method: "GET",
            cache: "no-store",
            credentials: "same-origin",
            signal: controller.signal,
        });

        if (!response.ok) {
            throw new Error("Preflight failed");
        }

        return await response.json();
    } finally {
        globalThis.clearTimeout(timeoutId);
    }
}

/**
 * Handles click events on Gematik login links.
 *
 * It prevents the default navigation, performs a pre‑flight request to
 * retrieve configuration (including a range of ports), selects a free port
 * using the extracted `findFreePort` helper, and finally redirects the
 * browser to the original login URL with the chosen `authenticatorPort`
 * appended as a query parameter.
 */
async function handleGematikLoginClick(event) {
    event.preventDefault();
    try {
        const originalLoginUrl = event.currentTarget.href;
        const preflightUrl = buildPreflightUrlFromLoginUrl(originalLoginUrl);
        const portRangeConfig = await getAuthenticatorPortRangeConfig(preflightUrl);
        const serverPort = await globalThis.findFreePort(
            portRangeConfig.authenticatorPortRangeStart,
            portRangeConfig.authenticatorPortRangeEnd
        );
        const loginUrl = new URL(originalLoginUrl, globalThis.location.origin);
        loginUrl.searchParams.set("authenticatorPort", serverPort.toString());
        if (typeof crypto === "undefined" || typeof crypto.randomUUID !== "function") {
            throw new TypeError("Web Crypto API not available.");
        }
        const handshakeId = crypto.randomUUID();
        sessionStorage.setItem(HANDSHAKE_ID_KEY, handshakeId);
        loginUrl.searchParams.set("handshake_id", handshakeId);
        globalThis.location.href = loginUrl.toString();
    } catch (e) {
        console.error('Gematik login pre-flight failed:', e);
        // Fallback: direct navigation without port handling
        globalThis.location.href = event.currentTarget.href;
    }
}

/**
 * Attaches click event listeners to all Gematik login links on the page.
 *
 * It selects anchor elements whose `href` attribute contains both
 * `"/broker/gematik-"` and `"/login"`. For each matched element, it registers
 * `handleGematikLoginClick` as the click handler, enabling the custom Gematik
 * authentication pre‑flight flow.
 */
function addGematikLoginLinksListeners() {
    const gematikLoginLinks = document.querySelectorAll(
        'a[href*="/broker/gematik-"][href*="/login"]'
    );

    gematikLoginLinks.forEach((link) => {
        link.addEventListener("click", handleGematikLoginClick);
    })
}

/**
 * Starts the pollers used during authentication. The legacy poller and the new
 * "v4.17" (local HTTP server) poller are started. The local HTTP server poller
 * now receives its own timeout configuration (`authenticatorHttpServerTimeout`).
 *
 * @param {Object} params - Parameters required to start the pollers.
 * @param {string} params.statusUrl - URL for the legacy poller.
 * @param {string} params.timeoutUrl - URL to redirect on timeout.
 * @param {number} [params.timeout] - Timeout in milliseconds for the legacy poller.
 * @param {number} [params.authenticatorHttpServerTimeout] - Timeout in milliseconds for the local HTTP server poller.
 * @param {string} [params.handshakeId] - Optional handshake identifier loaded from the configuration and forwarded to
 *     the local HTTP server poller.
 */
function startPollers({statusUrl, timeoutUrl, timeout, authenticatorHttpServerTimeout, handshakeId}) {
    // Start the legacy poller with its own timeout configuration.
    legacyPoller.start({statusUrl, timeoutUrl, timeout});

    if (typeof startLocalHttpServerPoller === "function") {
        try {
            // Pass handshakeId and the dedicated timeout to the poller.
            startLocalHttpServerPoller({handshakeId, timeout: authenticatorHttpServerTimeout});
        } catch (e) {
            console.error('Failed to start localHTTPServerPoller on page load:', e);
        }
    }
}

// Guard against environments (e.g., Jest) where the DOM APIs are unavailable.
if (typeof globalThis.addEventListener === "function") {
    globalThis.addEventListener("DOMContentLoaded", async () => {
        // Attach listeners only if document exists.
        if (typeof document !== "undefined") {
            addGematikLoginLinksListeners();

            const modal = document.querySelector(".gematik-idp-modal");

            try {
                const configElement = document.getElementById("gematikIdpConfiguration");
                if (!configElement) {
                    // Abort further execution of this async block; nothing to poll.
                    return;
                }
                const {
                    statusUrl,
                    timeoutUrl,
                    timeout,
                    authenticatorHttpServerTimeout,
                    authRequestUrl,
                    probeAuthenticatorServerUrl
                } = JSON.parse(
                    configElement.textContent
                );

                sessionStorage.setItem(AUTH_REQ_URL, authRequestUrl);
                sessionStorage.setItem(PROBE_AUTH_SERVER_URL, probeAuthenticatorServerUrl);

                let handshakeId = sessionStorage.getItem(HANDSHAKE_ID_KEY);

                if (modal) {
                    const closeBtn = document.querySelector(".gematik-idp-modal .close");
                    if (closeBtn) {
                        closeBtn.addEventListener("click", function () {
                            modal.style.display = "none";
                            // Start both pollers after the user confirms the modal.
                            startPollers({statusUrl, timeoutUrl, timeout, authenticatorHttpServerTimeout, handshakeId});
                        });
                    }
                } else {
                    // Start both pollers immediately if authenticator auto‑launch is enabled.
                    startPollers({statusUrl, timeoutUrl, timeout, authenticatorHttpServerTimeout, handshakeId});
                }
            } catch (e) {
                console.log(`Exception while polling Authentication Status: ${e}`);
            }
        }
    });
}

