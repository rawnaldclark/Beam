/**
 * @file rendezvous.js
 * @description Shared helper for building the COMPLETE rendezvous membership
 *   set this device must register with the relay.
 *
 *   Every `register-rendezvous` frame must carry the device's OWN deviceId
 *   (so its own-id-keyed peer-pings — see connection/peer-ping.js — route)
 *   PLUS every paired peer's deviceId (so it is a member of each peer's room
 *   and can be a routing target there). The relay's `presence.register`
 *   REPLACES the membership set on every call, so a partial set (own-only,
 *   or peers-only) silently breaks routing — the "can't connect/send" bug.
 *
 *   Mirrors the Android `buildRendezvousIds` in SignalingClient.kt.
 */

/**
 * @param {string} ownDeviceId        This device's own deviceId.
 * @param {string[]} [peerDeviceIds]  Paired peer deviceIds.
 * @returns {string[]} Deduped list = own + peers (own first), falsy entries removed.
 */
export function computeRendezvousIds(ownDeviceId, peerDeviceIds = []) {
  return [...new Set([ownDeviceId, ...peerDeviceIds].filter(Boolean))];
}
