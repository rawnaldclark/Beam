package com.zaptransfer.android.connection

/**
 * Typed exception thrown by send-path call sites when
 * [ConnectionAuthority.ensureSendable] returns a non-[SendGate.Ok] verdict.
 *
 * The carried [gate] is exactly the value the authority returned, so the
 * catch site can distinguish [SendGate.SelfOffline] (UI: "Not connected —
 * Reconnect" banner) from [SendGate.PeerUnreachable] (UI: a Failed transfer
 * card with retry button) without a brittle string-tag round trip.
 *
 * Design note: extends [RuntimeException] (rather than e.g. [java.io.IOException])
 * to keep call sites' existing `catch (e: Exception)` blocks unchanged. The
 * production send paths in [com.zaptransfer.android.service.TransferEngine] /
 * [com.zaptransfer.android.ui.devicehub.DeviceHubViewModel] already wrap the
 * v2 send with a broad catch that routes to a Failed history row + toast;
 * subclassing RuntimeException lets a more specific catch ladder slot in
 * ahead of that broad catch when the UI binding (Task 19) lands without
 * touching every existing try/catch.
 *
 * Mirrors the pattern used in `extension/background-relay.js` (Chrome Task 9):
 * the Chrome side throws a plain `Error` with `err.code = gate.reason`; we
 * preserve more structure by carrying the typed [SendGate] directly. Both
 * platforms agree that "zero frames are transmitted on a non-Ok gate" —
 * this exception is the throw used to short-circuit the v2 transport call.
 */
class PreFlightFailedException(val gate: SendGate) :
    RuntimeException("pre-flight failed: $gate")
