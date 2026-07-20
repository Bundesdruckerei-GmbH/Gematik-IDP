/**
 * The tests run in a Node environment (Jest) and therefore mock the browser globals
 * required by the implementation.
 */
/* eslint-env jest */

// Mock browser globals used by gematik-idp.js
globalThis.location = {
    href: "",
    origin: "http://example.com",
    assign: jest.fn(),
};

globalThis.crypto = {
    randomUUID: () => "123e4567-e89b-12d3-a456-426614174000",
};

// Mock sessionStorage used by the implementation to store authenticatorPort and handshake_id.
globalThis.sessionStorage = {
    setItem: jest.fn(),
    getItem: jest.fn(() => null),
    removeItem: jest.fn(),
};

// Mock the freePortHelper used by the code to avoid network activity.
jest.mock(
    "../../../main/resources/theme-resources/resources/js/utils/freePortHelper.js",
    () => ({
        findFreePort: jest.fn(() => Promise.resolve(4242)),
    })
);

// Import the module under test after the mocks are in place using CommonJS.
require("../../../main/resources/theme-resources/resources/js/gematik-idp.js");

describe('handshake_id deep link generation', () => {
    it('adds handshake_id to the URL and exposes it globally', async () => {
        // Mock the pre‑flight fetch request.
        globalThis.fetch = jest.fn(() =>
                                       Promise.resolve({
                                                           ok: true,
                                                           json: () => Promise.resolve(
                                                               {authenticatorPortRangeStart: 4000, authenticatorPortRangeEnd: 5000}),
                                                       })
        );

        const fakeEvent = {
            preventDefault: jest.fn(),
            currentTarget: {href: 'http://example.com/broker/gematik-login'},
        };

        // Execute the click handler directly.
        await handleGematikLoginClick(fakeEvent);

        const url = new URL(globalThis.location.href);
        expect(url.searchParams.get('authenticatorPort')).toBe('4242');
        expect(url.searchParams.get('handshake_id')).toBe('123e4567-e89b-12d3-a456-426614174000');
    });

    // Additional edge‑case tests to increase coverage of the comments and error handling paths.
    it('falls back to original URL when pre‑flight request fails (non‑ok response)', async () => {
        // Mock fetch to return a response with ok: false.
        globalThis.fetch = jest.fn(() =>
            Promise.resolve({
                ok: false,
                json: () => Promise.resolve({}),
            })
        );

        const originalUrl = 'http://example.com/broker/gematik-login';
        const fakeEvent = {
            preventDefault: jest.fn(),
            currentTarget: { href: originalUrl },
        };

        // Execute the click handler.
        await handleGematikLoginClick(fakeEvent);

        // The location.href should be set directly to the original URL because the pre‑flight failed.
        expect(globalThis.location.href).toBe(originalUrl);
    });

    it('falls back to original URL when fetch throws an exception', async () => {
        // Mock fetch to reject with an error.
        globalThis.fetch = jest.fn(() => Promise.reject(new Error('network error')));

        const originalUrl = 'http://example.com/broker/gematik-login';
        const fakeEvent = {
            preventDefault: jest.fn(),
            currentTarget: { href: originalUrl },
        };

        await handleGematikLoginClick(fakeEvent);
        expect(globalThis.location.href).toBe(originalUrl);
    });

    it('falls back to original URL when Web Crypto API is unavailable', async () => {
        // Remove crypto to simulate missing Web Crypto API.
        const originalCrypto = globalThis.crypto;
        // @ts-ignore – deliberately delete for the test.
        delete globalThis.crypto;

        // Mock a successful fetch response.
        globalThis.fetch = jest.fn(() =>
            Promise.resolve({
                ok: true,
                json: () => Promise.resolve({ authenticatorPortRangeStart: 4000, authenticatorPortRangeEnd: 5000 }),
            })
        );

        const originalUrl = 'http://example.com/broker/gematik-login';
        const fakeEvent = {
            preventDefault: jest.fn(),
            currentTarget: { href: originalUrl },
        };

        await handleGematikLoginClick(fakeEvent);
        expect(globalThis.location.href).toBe(originalUrl);

        // Restore crypto for subsequent tests.
        globalThis.crypto = originalCrypto;
    });
});
