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

test("findFreePort returns first free port when earlier ports are occupied", async () => {
  // Mock fetch: first two ports return success (occupied), third returns failure (free).
  const mockResponses = [
    Promise.resolve({ ok: true }),
    Promise.resolve({ ok: true }),
    Promise.reject(new Error("network error"))
  ];
  fetchMock.mockImplementation(() => mockResponses.shift());
  const port = await findFreePort(8000, 8002, 10);
  expect(port).toBe(8002);
});

test("findFreePort throws when no ports are free", async () => {
  // Simulate all ports being occupied: fetch resolves successfully for each probe.
  fetchMock.mockImplementation(() => Promise.resolve({ ok: true }));
  await expect(findFreePort(9000, 9001, 10)).rejects.toThrow(
    "No free port found in range 9000-9001"
  );
});

// ---------------------------------------------------------------------------
// Validation edge‑case tests for input validation
// ---------------------------------------------------------------------------

test("findFreePort throws TypeError when ports are not integers", async () => {
  // Non‑integer start value
  await expect(findFreePort(8000.5, 8010)).rejects.toThrow(TypeError);
  // Non‑integer end value (string)
  await expect(findFreePort(8000, "8010"))
    .rejects.toThrow(TypeError);
});

test("findFreePort throws RangeError when ports are out of allowed range", async () => {
  // Start below 1
  await expect(findFreePort(0, 10)).rejects.toThrow(RangeError);
  // End above 65535
  await expect(findFreePort(65530, 70000)).rejects.toThrow(RangeError);
});

test("findFreePort throws generic Error when start is greater than end", async () => {
  await expect(findFreePort(9005, 9000)).rejects.toThrow(Error);
  await expect(findFreePort(9005, 9000)).rejects.toThrow(
    "Port range start must be less than or equal to port range end"
  );
});
