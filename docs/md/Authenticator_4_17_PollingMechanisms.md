# Polling Mechanisms

> Documentation of the polling mechanisms used by **Authenticator 5.0**.

## Overview

The authenticator runs two polling mechanisms in parallel:

1. **New‑Version polling** – checks for the local HTTP server started by the new authenticator.
2. **Legacy polling** – repeatedly calls `getStatus()` on the legacy authenticator.

The first mechanism that succeeds determines which version is considered running, and the other is stopped. This ensures
a seamless fallback when the new version cannot start in time.

## New‑Version Polling

- Starts the new‑version polling.
- Repeatedly checks if the local HTTP server is reachable (until detected or a timeout `MAX_WAIT`ms is reached).
- If the server is detected:
    - The new version is **running**.
    - Legacy polling is stopped.
    - Additional parameters are sent to the HTTP server to start the flow.
- If the timeout occurs:
    - New‑version polling stops.
    - The system falls back to the **legacy** mechanism.

## Legacy Polling

- Starts the legacy polling (active from the beginning).
- Calls `getStatus()` on the legacy authenticator in a loop.
- When a status is received:
    - The legacy authenticator is **running**.
    - Any still‑alive new‑version polling is cancelled.
- If no status is received, the loop continues waiting.

## Interaction

Both mechanisms are launched in a **fork** (parallel) block. Whichever mechanism wins first stops the other,
guaranteeing that either the new or legacy authenticator takes over.

---

### PlantUML diagram

The diagram is defined in the accompanying PlantUML file. You can view it directly:

[Authenticator 5.0 polling mechanisms diagram](../puml/Authenticator_4_17_PollingMechanisms.puml)

---

## Summary

The dual‑polling approach provides a reliable fallback from the new implementation to the legacy one, ensuring the
authenticator can always operate.

---
