// Free Port Helper Module
// Provides a utility to find a free TCP port candidate within a given range.
// This logic was previously embedded in gematik-idp.js. Extracted for reusability
// and testability as per US001.

/**
 * Formats the provided port range values for inclusion in error messages.
 * @param {number} portStart
 * @param {number} portEnd
 * @returns {string}
 */
function formatPortRange(portStart, portEnd) {
    return `Received start=${portStart}, end=${portEnd}`;
}

/**
 * Validates that the given start and end ports constitute a proper range.
 * Throws descriptive errors when validation fails.
 * @param {number} portStart
 * @param {number} portEnd
 */
function validatePortRange(portStart, portEnd) {
    if (!Number.isInteger(portStart) || !Number.isInteger(portEnd)) {
        throw new TypeError(`Port range must contain integer values. ${formatPortRange(portStart, portEnd)}`);
    }
    if (portStart < 1 || portEnd > 65535) {
        throw new RangeError(`Port range must be between 1 and 65535. ${formatPortRange(portStart, portEnd)}`);
    }
    if (portStart > portEnd) {
        throw new Error(
            `Port range start must be less than or equal to port range end. ${formatPortRange(portStart, portEnd)}`);
    }
}

/**
 * Checks whether an HTTP‑like service appears to respond on localhost:port.
 * @param {number} port
 * @param {number} timeoutMs
 * @returns {Promise<boolean>} true if a fetch succeeds, false otherwise.
 */
async function hasReachableHttpService(port, timeoutMs) {
    const controller = new AbortController();
    const timeoutId = globalThis.setTimeout(() => controller.abort(), timeoutMs);
    try {
        await fetch(`http://localhost:${port}/`, {
            method: "HEAD",
            mode: "no-cors",
            cache: "no-store",
            signal: controller.signal
        });
        return true;
    } catch {
        return false;
    } finally {
        globalThis.clearTimeout(timeoutId);
    }
}

/**
 * Finds the first candidate port in the given range where no HTTP service appears reachable.
 * @param {number} start - Inclusive start of the port range.
 * @param {number} end - Inclusive end of the port range.
 * @param {number} [timeoutMs=300] - Timeout per port probe in milliseconds.
 * @returns {Promise<number|null>} The first free candidate port, or null if none found.
 */
async function findFreePort(start, end, timeoutMs = 300) {
    validatePortRange(start, end);
    for (let port = start; port <= end; port++) {
        const occupied = await hasReachableHttpService(port, timeoutMs);
        if (!occupied) {
            return port;
        }
    }
    // No free port found within the range – throw an error as per acceptance criteria.
    throw new Error(`No free port found in range ${start}-${end}`);
}

if (typeof module !== "undefined" && typeof module.exports !== "undefined") {
    module.exports = {findFreePort};
}
