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

// Free Port Helper Module
// Provides a utility to find a free TCP port candidate within a given range.
// This logic was previously embedded in gematik-idp.js. Extracted for reusability
// and testability as per US001.

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
 * @returns {Promise<number>} The first free candidate port.
 * @throws {Error} If no free port is found in the supplied range.
 */
async function findFreePort(start, end, timeoutMs = 300) {
    // Ensure the range is valid.
    if (end < start) {
        throw new Error(`Invalid port range: start (${start}) > end (${end})`);
    }

    // Build an array of all candidate ports in the range.
    const ports = [];
    for (let p = Math.ceil(start); p <= Math.floor(end); p++) {
        ports.push(p);
    }

    //Randomize array
    for (let i = ports.length - 1; i > 0; i--) {
        const j = Math.floor(Math.random() * (i + 1));
        [ports[i], ports[j]] = [ports[j], ports[i]]; // swap
    }

    // Scan the shuffled list until a free port is found.
    for (const port of ports) {
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
