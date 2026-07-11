package com.zaptransfer.android.webrtc

import org.junit.Assert.assertEquals
import org.junit.Test

/**
 * Unit coverage for [buildRendezvousIds].
 *
 * Invariant under test: every register-rendezvous frame must carry the
 * COMPLETE membership set this device should belong to — its OWN deviceId
 * (so its own-id-keyed peer-pings route, per [com.zaptransfer.android.connection.PeerPingTracker])
 * PLUS every paired peer's deviceId (so it is a member of each peer's room
 * and can be a routing target there). The server's `presence.register`
 * REPLACES the set on every call, so a partial set silently breaks routing.
 *
 * Mirrors the JS `extension/shared/rendezvous.js` helper test-for-test.
 */
class RendezvousIdsTest {

    private val own = "OWNdeviceId0000000000A"
    private val peerA = "PEERaaaaaaaaaaaaaaaaaA"
    private val peerB = "PEERbbbbbbbbbbbbbbbbbB"

    @Test
    fun ownDeviceId_isAlwaysIncluded() {
        val ids = buildRendezvousIds(own, listOf(peerA))
        assertEquals(true, ids.contains(own))
    }

    @Test
    fun pairedPeerIds_areIncluded() {
        val ids = buildRendezvousIds(own, listOf(peerA, peerB))
        assertEquals(true, ids.contains(peerA))
        assertEquals(true, ids.contains(peerB))
    }

    @Test
    fun emptyPeers_yieldsOwnOnly() {
        val ids = buildRendezvousIds(own, emptyList())
        assertEquals(listOf(own), ids)
    }

    @Test
    fun ownAlreadyInPeers_isNotDuplicated() {
        // This is the production bug: callers pass `devices.map { it.deviceId }`
        // which on a self-paired/loopback edge could already contain own.
        val ids = buildRendezvousIds(own, listOf(peerA, own))
        assertEquals(1, ids.count { it == own })
        assertEquals(true, ids.contains(peerA))
    }

    @Test
    fun duplicatePeers_areDeduped() {
        val ids = buildRendezvousIds(own, listOf(peerA, peerA, peerB))
        assertEquals(1, ids.count { it == peerA })
        assertEquals(1, ids.count { it == peerB })
    }
}
