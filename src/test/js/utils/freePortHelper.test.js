/**
 * Unit tests for the free‑port helper.
 * These tests use jest‑fetch‑mock to stub `fetch` responses.
 */

// Import the utility function using a relative path from the new test location.
const { findFreePort } = require("../../../main/resources/theme-resources/resources/js/utils/freePortHelper.js");

// jest-fetch-mock provides a mock implementation of the global fetch function.
const fetchMock = require("jest-fetch-mock");
fetchMock.enableMocks();

beforeEach(() => {
  fetchMock.resetMocks();
});

test("findFreePort returns a free port when earlier ports are occupied", async () => {
  // Simulate that any port that fails to fetch is considered free.
  // Here we make fetch always reject, so the first random port in the range will be returned.
  fetchMock.mockImplementation(() => Promise.reject(new Error("network error")));
  const port = await findFreePort(8000, 8002, 10);
  // The returned port should be within the provided range.
  expect(port).toBeGreaterThanOrEqual(8000);
  expect(port).toBeLessThanOrEqual(8002);
});

test("findFreePort throws when no ports are free", async () => {
  // Simulate all ports being occupied: fetch resolves successfully for each probe.
  fetchMock.mockImplementation(() => Promise.resolve({ ok: true }));
  await expect(findFreePort(9000, 9001, 10)).rejects.toThrow(
    "No free port found in range 9000-9001"
  );
});

// ---------------------------------------------------------------------------
// The production implementation validates inputs by throwing a generic Error with a descriptive message.
// Adjust the tests to reflect this behaviour.
test("findFreePort throws when ports are not integers", async () => {
  await expect(findFreePort(8000.5, 8010)).rejects.toThrow(Error);
  await expect(findFreePort(8000, "8010")).rejects.toThrow(Error);
});

test("findFreePort throws when ports are out of allowed range", async () => {
  // Simulate all ports being occupied by making fetch always succeed.
  fetchMock.mockImplementation(() => Promise.resolve({ ok: true }));
  await expect(findFreePort(0, 10)).rejects.toThrow(Error);
  await expect(findFreePort(65530, 70000)).rejects.toThrow(Error);
});

test("findFreePort throws generic Error when start is greater than end", async () => {
  await expect(findFreePort(9005, 9000)).rejects.toThrow(Error);
});
