/**
 * Integration tests for the new‑version poller coordination logic.
 *
 * These tests verify that the poller correctly interacts with the
 * `claimAuthenticator` hook and respects the configured timeout.
 *
 * The implementation under test is `newVersionPoller` located at
 * `../main/resources/theme-resources/resources/js/polling/newVersionPoller.js`
 * which follows the same API as the legacy poller (`start({freePort, maxWaitMs, pollInterval})` and `stop()`).
 */

"use strict";

// Jest‑fetch‑mock provides a mock for the global `fetch` used by the helper.
const fetchMock = require("jest-fetch-mock");
fetchMock.enableMocks();

// Extend the default test timeout to accommodate real‑timer based async operations.
jest.setTimeout(20000);

// Import the poller we want to test. Path adjusted for the new location.
// Adjusted relative path to the source file from the new test location.
// Define the constant used by the poller to look up the probe URL.
globalThis.PROBE_AUTH_SERVER_URL = "gematikIdp.probeAuthenticatorServerUrl";
const {startLocalHttpServerPoller, stopLocalHttpServerPoller} = require(
    "../../../main/resources/theme-resources/resources/js/polling/localHTTPServerPoller.js");

/** Helper to advance timers and flush pending promises/ micro‑tasks.
 * Jest's `runAllTimers` executes the timer callbacks, but if those callbacks are `async`
 * (as is the case for the poller interval) their internal `await`s schedule further
 * micro‑tasks. To ensure those are processed before the test assertions we also
 * await a `setImmediate` tick which flushes the promise queue.
 */
async function advanceTimers(ms) {
    // Move the fake timer forward.
    jest.advanceTimersByTime(ms);
    // Execute any queued timer callbacks.
    jest.runAllTimers();
    // Flush pending micro‑tasks (promises created by async callbacks).
    await new Promise(setImmediate);
}

describe("newVersionPoller integration", () => {
    beforeEach(() => {
        // Use real timers for integration‑style async behavior.
        jest.useRealTimers();
        fetchMock.resetMocks();
        // Mock sessionStorage used by the poller (required for storing version).
        // The poller reads the probe URL from sessionStorage under the key defined by
        // `PROBE_AUTH_SERVER_URL`. In production this constant is provided by
        // `gematik-idp.js`. We expose it globally for the test environment.
        globalThis.PROBE_AUTH_SERVER_URL = "gematikIdp.probeAuthenticatorServerUrl";
        globalThis.sessionStorage = {
            setItem: jest.fn(),
            getItem: jest.fn(key => {
                // Return the URL when the poller asks for the probe URL.
                if (key === globalThis.PROBE_AUTH_SERVER_URL) {
                    return "http://localhost:1234/status";
                }
                return null;
            }),
            removeItem: jest.fn()
        };
        // Define the AUTHENTICATOR_VERSION constant expected by the poller.
        globalThis.AUTHENTICATOR_VERSION = "gematikIdp.authenticatorVersion";
        // Ensure the poller sees the claim hook via globalThis, which is the reference used in production code.
        globalThis.claimAuthenticator = jest.fn(() => true);
        // Ensure fetch mock is reset for each test.
        fetchMock.resetMocks();
    });

    afterEach(() => {
        stopLocalHttpServerPoller();
        jest.useRealTimers();
        delete globalThis.claimAuthenticator;
    });

    test("detects reachable server and claims new authenticator", async () => {
        // Simulate a successful readiness probe.
        fetchMock.mockResponseOnce(JSON.stringify({ version: "v4.17" }), { status: 200 });
        // The poller no longer requires `serverPort`; it reads the URL from sessionStorage.
        startLocalHttpServerPoller({ timeout: 5000, pollInterval: 1000 });
        // Wait sufficiently long for the poller interval to fire and process the mocked fetch.
        await new Promise(r => setTimeout(r, 1500));
        expect(fetchMock).toHaveBeenCalledWith('http://localhost:1234/status', expect.objectContaining({
            method: "GET",
        }));
        expect(globalThis.claimAuthenticator).toHaveBeenCalledWith(
            "v4.17",
            "Authenticator 4.17.0 detected via localhost server"
        );
        // Ensure no extra fetch calls were made.
        expect(fetchMock).toHaveBeenCalledTimes(1);
    });

    test("times out when server is not reachable and does not claim", async () => {
        fetchMock.mockReject(new Error('network'));
        // Use a slightly larger timeout so that three poll attempts can occur before the poller stops.
        // Use a different URL for the failing scenario; the mock `getItem` will still
        // return the same URL, which is fine because fetch is mocked to reject.
        startLocalHttpServerPoller({ timeout: 3500, pollInterval: 1000 });
        // Wait long enough for the poller to perform three retry attempts and hit its timeout.
        await new Promise(r => setTimeout(r, 5000));
        expect(fetchMock).toHaveBeenCalledTimes(3);
        expect(globalThis.claimAuthenticator).not.toHaveBeenCalled();
    });
});
