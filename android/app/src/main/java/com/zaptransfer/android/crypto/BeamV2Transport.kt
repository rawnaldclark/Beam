package com.zaptransfer.android.crypto

import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.delay
import kotlinx.coroutines.launch
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import org.json.JSONArray
import org.json.JSONObject
import java.nio.ByteBuffer
import java.nio.ByteOrder
import java.security.SecureRandom
import java.util.Base64
import java.util.concurrent.ConcurrentHashMap

/**
 * Beam v2 sender + receiver state machine — Kotlin mirror of
 * `extension/crypto/beam-v2-transport.js`.
 *
 * The codec ([BeamV2]) is pure; this class holds the per-transfer in-flight
 * state and wires it to the relay client. All external dependencies (sendJson,
 * sendBinary, peer-key store, delivery handlers) are injected via [Hooks].
 *
 * Spec: docs/superpowers/specs/2026-04-30-beam-v2-design.md
 */
class BeamV2Transport(
    private val sendJson: (JSONObject) -> Unit,
    private val sendBinary: (ByteArray) -> Boolean,
    private val hooks: Hooks,
    private val codec: BeamV2 = BeamV2(),
    private val scope: CoroutineScope = CoroutineScope(SupervisorJob() + Dispatchers.Default),
    private val random: SecureRandom = SecureRandom(),
) {

    interface Hooks {
        suspend fun getPeer(deviceId: String): PairedPeer?
        suspend fun listPeers(): List<PairedPeer>
        suspend fun storeKABRing(deviceId: String, ring: KABRing)
        suspend fun onClipboardReceived(content: String, fromDeviceId: String)
        suspend fun onFileReceived(args: FileDelivery)
        fun onSendError(transferIdHex: String, code: String) {}
        fun onReceiveError(transferIdHex: String, code: String) {}
        fun onProgress(transferIdHex: String, percent: Int) {}
        fun ourDeviceId(): String? = null
    }

    /**
     * Per-pair record exposed via the [Hooks.getPeer] / [Hooks.listPeers]
     * callbacks. The transport never persists this directly — the storage
     * layer owns serialization to Room (or chrome.storage on JS side).
     */
    data class PairedPeer(
        val deviceId:  String,
        val ourSk:     ByteArray,
        val peerPk:    ByteArray,
        val ourEdPk:   ByteArray,
        val peerEdPk:  ByteArray,
        val kABRing:   KABRing,
    )

    data class KABRing(
        val currentGeneration: Int,
        val keys: Map<Int, KABEntry>,
    )

    data class KABEntry(
        val kAB: ByteArray,
        val expiresAt: Long? = null,
        val rotateNonce: ByteArray? = null,
        val createdAt: Long = System.currentTimeMillis(),
    )

    data class FileDelivery(
        val bytes: ByteArray,
        val fileName: String,
        val fileSize: Long,
        val mimeType: String,
        val fromDeviceId: String,
    )

    // -------------------------------------------------------------------------
    // State
    // -------------------------------------------------------------------------

    private data class Outbox(
        val transferIdHex: String,
        val targetDeviceId: String,
        val generation: Int,
        val transferId: ByteArray,
        val framesByIndex: Map<Int, OutboxFrame>,
        val firstSentAt: Long,
        var resendsUsed: Int,
        var giveupJob: Job?,
    )

    private data class OutboxFrame(
        val plaintext: ByteArray,
        val isFinal: Boolean,
        val hasMeta: Boolean,
    )

    private data class Inbox(
        val transferIdHex: String,
        val peer: PairedPeer,
        var kind: String,                   // "clipboard" | "file" | "file-pending-meta"
        val generation: Int,
        var totalChunks: Int,
        var fileName: String?,
        var fileSize: Long,
        var mimeType: String?,
        val frames: MutableMap<Int, ByteArray>,
        var metaSeen: Boolean,
        var finalSeen: Boolean,
        var bytesReceived: Long,
        val firstFrameAt: Long,
        var lastFrameAt: Long,
        var gapJob: Job?,
        var giveupJob: Job?,
        var resendRequested: Boolean,
    )

    private data class PendingRotation(
        val fromGen: Int,
        val toGen: Int,
        val nonce: ByteArray,
        val role: String, // "initiator" or "responder"
    )

    private val outbox            = ConcurrentHashMap<String, Outbox>()
    private val inbox             = ConcurrentHashMap<String, Inbox>()
    private val pendingRotations  = ConcurrentHashMap<String, PendingRotation>()
    private val rotationMutex     = Mutex()

    // -------------------------------------------------------------------------
    // Sender — clipboard
    // -------------------------------------------------------------------------

    suspend fun sendClipboard(targetDeviceId: String, text: String): String {
        android.util.Log.i("BeamV2T", "sendClipboard: target=$targetDeviceId len=${text.length}")
        val peer = hooks.getPeer(targetDeviceId)
            ?: run {
                android.util.Log.w("BeamV2T", "sendClipboard: NO_PEER for $targetDeviceId")
                throw BeamV2Exception("NO_PEER", "peer $targetDeviceId not paired")
            }
        val gen = peer.kABRing.currentGeneration
        val kAB = peer.kABRing.keys[gen]?.kAB
            ?: run {
                android.util.Log.w("BeamV2T", "sendClipboard: NO_KEY peer=$targetDeviceId gen=$gen ringGens=${peer.kABRing.keys.keys}")
                throw BeamV2Exception("NO_KEY", "no K_AB for peer $targetDeviceId gen $gen")
            }

        val transferId = codec.newTransferId()
        val transferIdHex = bytesToHex(transferId)

        val meta = JSONObject().put("kind", "clipboard").put("v", 2).toString().toByteArray(Charsets.UTF_8)
        val textBytes = text.toByteArray(Charsets.UTF_8)
        val plaintext = ByteArray(2 + meta.size + textBytes.size).also {
            putU16be(it, 0, meta.size)
            meta.copyInto(it, 2)
            textBytes.copyInto(it, 2 + meta.size)
        }

        val ob = registerOutbox(
            transferIdHex   = transferIdHex,
            transferId      = transferId,
            targetDeviceId  = targetDeviceId,
            generation      = gen,
            framesByIndex   = mapOf(0 to OutboxFrame(plaintext, isFinal = true, hasMeta = true)),
        )
        sendRelayBind(transferId, targetDeviceId)
        sendOutboxFrame(ob, 0, kAB)
        android.util.Log.i("BeamV2T", "sendClipboard: completed id=$transferIdHex (1 frame)")
        scheduleSenderGiveup(transferIdHex)
        return transferIdHex
    }

    /**
     * Beam v2 binary frames need a one-shot relay-bind so the server's
     * data-relay can pre-populate both ends of its session map via
     * rendezvous lookup. The receiver never binds — it doesn't know the
     * transferId until after decrypting the frame.
     */
    private fun sendRelayBind(transferId: ByteArray, targetDeviceId: String) {
        val msg = JSONObject()
            .put("type", "relay-bind")
            .put("transferId", b64urlFromBytes(transferId))
            .put("targetDeviceId", targetDeviceId)
            .put("rendezvousId", targetDeviceId)
        sendJson(msg)
    }

    // -------------------------------------------------------------------------
    // Sender — file
    // -------------------------------------------------------------------------

    suspend fun sendFile(targetDeviceId: String, fileName: String, fileSize: Long, mimeType: String, bytes: ByteArray): String {
        android.util.Log.i("BeamV2T", "sendFile: target=$targetDeviceId name=$fileName size=$fileSize")
        val peer = hooks.getPeer(targetDeviceId)
            ?: run {
                android.util.Log.w("BeamV2T", "sendFile: NO_PEER for $targetDeviceId")
                throw BeamV2Exception("NO_PEER", "peer $targetDeviceId not paired")
            }
        require(bytes.size.toLong() == fileSize) { "fileSize must match bytes.size" }
        require(fileSize in 1..BeamV2Constants.MAX_FILE_SIZE) { "fileSize out of range" }
        val gen = peer.kABRing.currentGeneration
        val kAB = peer.kABRing.keys[gen]?.kAB
            ?: run {
                android.util.Log.w("BeamV2T", "sendFile: NO_KEY peer=$targetDeviceId gen=$gen ringGens=${peer.kABRing.keys.keys}")
                throw BeamV2Exception("NO_KEY", "no K_AB for peer $targetDeviceId gen $gen")
            }

        val totalChunks = ((fileSize + BeamV2Constants.FILE_CHUNK_SIZE - 1) / BeamV2Constants.FILE_CHUNK_SIZE).toInt()
        require(totalChunks <= BeamV2Constants.MAX_CHUNKS) { "totalChunks > ${BeamV2Constants.MAX_CHUNKS}" }

        val transferId = codec.newTransferId()
        val transferIdHex = bytesToHex(transferId)

        val metaJson = JSONObject()
            .put("kind", "file").put("v", 2)
            .put("fileName", fileName).put("fileSize", fileSize)
            .put("mime", mimeType).put("totalChunks", totalChunks)
            .toString().toByteArray(Charsets.UTF_8)
        val metaPlain = ByteArray(2 + metaJson.size).also {
            putU16be(it, 0, metaJson.size)
            metaJson.copyInto(it, 2)
        }

        val frames = LinkedHashMap<Int, OutboxFrame>(totalChunks + 1)
        frames[0] = OutboxFrame(metaPlain, isFinal = false, hasMeta = true)
        for (i in 0 until totalChunks) {
            val start = i.toLong() * BeamV2Constants.FILE_CHUNK_SIZE
            val end = minOf(start + BeamV2Constants.FILE_CHUNK_SIZE, fileSize)
            val chunk = bytes.copyOfRange(start.toInt(), end.toInt())
            frames[i + 1] = OutboxFrame(chunk, isFinal = (i == totalChunks - 1), hasMeta = false)
        }

        val ob = registerOutbox(
            transferIdHex   = transferIdHex,
            transferId      = transferId,
            targetDeviceId  = targetDeviceId,
            generation      = gen,
            framesByIndex   = frames,
        )

        sendRelayBind(transferId, targetDeviceId)

        for (idx in 0..totalChunks) {
            sendOutboxFrame(ob, idx, kAB)
            if (idx < totalChunks) delay(20)
            hooks.onProgress(transferIdHex, ((idx + 1) * 100) / (totalChunks + 1))
        }
        android.util.Log.i("BeamV2T", "sendFile: completed id=$transferIdHex frames=${totalChunks + 1}")
        scheduleSenderGiveup(transferIdHex)
        return transferIdHex
    }

    private fun sendOutboxFrame(ob: Outbox, index: Int, kAB: ByteArray) {
        val f = ob.framesByIndex[index]
            ?: throw BeamV2Exception("UNKNOWN_FRAME", "outbox missing index $index")
        val frame = codec.encodeFrame(
            kAB        = kAB,
            generation = ob.generation,
            transferId = ob.transferId,
            index      = index,
            isFinal    = f.isFinal,
            hasMeta    = f.hasMeta,
            plaintext  = f.plaintext,
        )
        val ok = sendBinary(frame)
        android.util.Log.d("BeamV2T", "sendOutboxFrame: id=${ob.transferIdHex} idx=$index size=${frame.size} ok=$ok")
        if (!ok) {
            throw BeamV2Exception("NO_TRANSPORT", "sendBinary returned false (WS closed?)")
        }
    }

    private fun registerOutbox(
        transferIdHex: String,
        transferId: ByteArray,
        targetDeviceId: String,
        generation: Int,
        framesByIndex: Map<Int, OutboxFrame>,
    ): Outbox {
        val ob = Outbox(
            transferIdHex   = transferIdHex,
            targetDeviceId  = targetDeviceId,
            generation      = generation,
            transferId      = transferId,
            framesByIndex   = framesByIndex,
            firstSentAt     = System.currentTimeMillis(),
            resendsUsed     = 0,
            giveupJob       = null,
        )
        outbox[transferIdHex] = ob
        return ob
    }

    private fun scheduleSenderGiveup(transferIdHex: String) {
        val ob = outbox[transferIdHex] ?: return
        ob.giveupJob?.cancel()
        ob.giveupJob = scope.launch {
            delay(BeamV2Constants.SENDER_GIVEUP_MS)
            outbox.remove(transferIdHex)
        }
    }

    // -------------------------------------------------------------------------
    // Receiver
    // -------------------------------------------------------------------------

    suspend fun handleIncomingFrame(bytes: ByteArray) {
        val head = codec.peekHeader(bytes) ?: return // not a v2 frame; drop
        android.util.Log.d("BeamV2T", "handleIncomingFrame: id=${bytesToHex(head.transferId)} idx=${head.index} gen=${head.generation} size=${bytes.size}")

        // Try every paired peer's K_AB at the frame's generation. AEAD verify
        // failure is microseconds, so O(N) over peers (N typically 1–3) is fine.
        val peers = hooks.listPeers()
        var matched: PairedPeer? = null
        var decoded: BeamV2.DecodedFrame? = null
        for (peer in peers) {
            val kAB = peer.kABRing.keys[head.generation]?.kAB ?: continue
            val out = codec.decodeFrame(bytes) { gen -> if (gen == head.generation) kAB else null }
            if (out != null) {
                matched = peer
                decoded = out
                break
            }
        }
        if (matched == null || decoded == null) {
            android.util.Log.w("BeamV2T", "handleIncomingFrame: NO_KEY_OR_DECRYPT_FAIL — peers=${peers.size} gen=${head.generation}")
            hooks.onReceiveError(bytesToHex(head.transferId), "NO_KEY_OR_DECRYPT_FAIL")
            return
        }
        processDecoded(matched, decoded)
    }

    private suspend fun processDecoded(peer: PairedPeer, dec: BeamV2.DecodedFrame) {
        val transferIdHex = bytesToHex(dec.header.transferId)
        var ib = inbox[transferIdHex]

        if (dec.header.index == 0) {
            if (!dec.header.hasMeta) {
                hooks.onReceiveError(transferIdHex, "FRAME0_NO_META")
                return
            }
            val (meta, payload) = parseMetaFrame(dec.plaintext)
            if (meta == null) {
                hooks.onReceiveError(transferIdHex, "BAD_META")
                return
            }
            when (meta.optString("kind")) {
                "clipboard" -> {
                    if (!dec.header.isFinal) {
                        hooks.onReceiveError(transferIdHex, "CLIPBOARD_NOT_FINAL")
                        return
                    }
                    inbox.remove(transferIdHex)
                    hooks.onClipboardReceived(String(payload, Charsets.UTF_8), peer.deviceId)
                }
                "file" -> {
                    val totalChunks = meta.optInt("totalChunks", -1)
                    val fileSize    = meta.optLong("fileSize", -1)
                    val fileName    = meta.optString("fileName", "")
                    val mime        = meta.optString("mime", "")
                    if (totalChunks <= 0 || totalChunks > BeamV2Constants.MAX_CHUNKS) {
                        hooks.onReceiveError(transferIdHex, "BAD_TOTAL_CHUNKS"); return
                    }
                    if (fileSize <= 0 || fileSize > BeamV2Constants.MAX_FILE_SIZE) {
                        hooks.onReceiveError(transferIdHex, "BAD_FILE_SIZE"); return
                    }
                    if (fileName.isEmpty() || fileName.length > 255) {
                        hooks.onReceiveError(transferIdHex, "BAD_FILENAME"); return
                    }
                    if (ib == null) {
                        ib = registerInbox(
                            transferIdHex, peer, "file",
                            dec.header.generation, totalChunks, fileName, fileSize, mime,
                        )
                    } else {
                        ib.kind = "file"
                        ib.totalChunks = totalChunks
                        ib.fileName = fileName
                        ib.fileSize = fileSize
                        ib.mimeType = mime
                    }
                    ib.metaSeen = true
                    touchInbox(ib)
                }
                else -> hooks.onReceiveError(transferIdHex, "UNKNOWN_KIND_${meta.optString("kind")}")
            }
            return
        }

        // index > 0 — chunk frame
        if (ib == null) {
            ib = registerInbox(
                transferIdHex, peer, "file-pending-meta",
                dec.header.generation, totalChunks = 0,
                fileName = null, fileSize = 0, mimeType = null,
            )
        }
        if (dec.header.index < 1 || (ib.totalChunks > 0 && dec.header.index > ib.totalChunks)) {
            hooks.onReceiveError(transferIdHex, "INDEX_OUT_OF_RANGE")
            return
        }
        if (!ib.frames.containsKey(dec.header.index)) {
            ib.frames[dec.header.index] = dec.plaintext
            ib.bytesReceived += dec.plaintext.size
        }
        if (dec.header.isFinal) ib.finalSeen = true
        touchInbox(ib)

        maybeCompleteOrResend(ib)
    }

    private fun registerInbox(
        transferIdHex: String, peer: PairedPeer, kind: String,
        generation: Int, totalChunks: Int,
        fileName: String? = null, fileSize: Long = 0, mimeType: String? = null,
    ): Inbox {
        val ib = Inbox(
            transferIdHex = transferIdHex, peer = peer, kind = kind,
            generation = generation, totalChunks = totalChunks,
            fileName = fileName, fileSize = fileSize, mimeType = mimeType,
            frames = mutableMapOf(), metaSeen = (kind == "clipboard" || kind == "file" && totalChunks > 0),
            finalSeen = false, bytesReceived = 0,
            firstFrameAt = System.currentTimeMillis(),
            lastFrameAt  = System.currentTimeMillis(),
            gapJob = null, giveupJob = null,
            resendRequested = false,
        )
        inbox[transferIdHex] = ib
        scheduleInboxTimers(ib)
        return ib
    }

    private fun touchInbox(ib: Inbox) {
        ib.lastFrameAt = System.currentTimeMillis()
        ib.gapJob?.cancel()
        ib.gapJob = scope.launch {
            delay(BeamV2Constants.RECEIVE_GAP_MS)
            maybeRequestResend(ib)
        }
    }

    private fun scheduleInboxTimers(ib: Inbox) {
        ib.gapJob = scope.launch {
            delay(BeamV2Constants.RECEIVE_GAP_MS)
            maybeRequestResend(ib)
        }
        ib.giveupJob = scope.launch {
            delay(BeamV2Constants.RECEIVER_GIVEUP_MS)
            inbox.remove(ib.transferIdHex)
            hooks.onReceiveError(ib.transferIdHex, "PARTIAL")
        }
    }

    private suspend fun maybeCompleteOrResend(ib: Inbox) {
        if (!ib.metaSeen) return
        if (ib.frames.size == ib.totalChunks && ib.finalSeen) {
            completeFile(ib)
        } else if (ib.finalSeen) {
            maybeRequestResend(ib)
        }
    }

    private fun maybeRequestResend(ib: Inbox) {
        if (!ib.metaSeen) return
        val missing = (1..ib.totalChunks).filter { !ib.frames.containsKey(it) }
        if (missing.isEmpty()) return
        if (ib.resendRequested) return
        ib.resendRequested = true
        val msg = JSONObject()
            .put("type", "beam-v2-resend")
            .put("transferId", b64urlFromBytes(hexToBytes(ib.transferIdHex)))
            .put("missing", JSONArray(missing))
            .put("targetDeviceId", ib.peer.deviceId)
            .put("rendezvousId", ib.peer.deviceId)
        sendJson(msg)
    }

    private suspend fun completeFile(ib: Inbox) {
        ib.giveupJob?.cancel()
        ib.gapJob?.cancel()
        inbox.remove(ib.transferIdHex)
        val totalLen = ib.frames.values.sumOf { it.size }
        if (totalLen.toLong() != ib.fileSize) {
            hooks.onReceiveError(ib.transferIdHex, "SIZE_MISMATCH")
            return
        }
        val out = ByteArray(totalLen)
        var off = 0
        for (i in 1..ib.totalChunks) {
            val part = ib.frames[i] ?: run {
                hooks.onReceiveError(ib.transferIdHex, "MISSING_CHUNK_$i"); return
            }
            part.copyInto(out, off)
            off += part.size
        }
        hooks.onFileReceived(FileDelivery(
            bytes = out, fileName = ib.fileName ?: "untitled",
            fileSize = ib.fileSize, mimeType = ib.mimeType ?: "application/octet-stream",
            fromDeviceId = ib.peer.deviceId,
        ))
    }

    // -------------------------------------------------------------------------
    // JSON message dispatch
    // -------------------------------------------------------------------------

    /**
     * Returns true if the message was a v2 transport message (handled);
     * false otherwise so the caller can route to other handlers.
     */
    suspend fun handleJsonMessage(msg: JSONObject): Boolean {
        return when (msg.optString("type")) {
            "beam-v2-resend"        -> { handleResendRequest(msg); true }
            "beam-v2-fail"          -> { handleSenderFailure(msg); true }
            "beam-v2-rotate-init"   -> { handleRotateInit(msg);    true }
            "beam-v2-rotate-ack"    -> { handleRotateAck(msg);     true }
            "beam-v2-rotate-commit" -> { handleRotateCommit(msg);  true }
            else -> false
        }
    }

    private suspend fun handleResendRequest(msg: JSONObject) {
        val transferIdBytes = bytesFromB64url(msg.getString("transferId"))
        val transferIdHex   = bytesToHex(transferIdBytes)
        val ob = outbox[transferIdHex] ?: return
        if (ob.resendsUsed >= BeamV2Constants.MAX_RESENDS) {
            sendJson(JSONObject()
                .put("type", "beam-v2-fail")
                .put("transferId", msg.getString("transferId"))
                .put("targetDeviceId", ob.targetDeviceId)
                .put("rendezvousId", ob.targetDeviceId)
                .put("code", "PARTIAL"))
            return
        }
        ob.resendsUsed += 1

        val peer = hooks.getPeer(ob.targetDeviceId) ?: return
        val kAB = peer.kABRing.keys[ob.generation]?.kAB ?: return
        val arr = msg.getJSONArray("missing")
        for (i in 0 until arr.length()) {
            sendOutboxFrame(ob, arr.getInt(i), kAB)
        }
    }

    private fun handleSenderFailure(msg: JSONObject) {
        val transferIdHex = bytesToHex(bytesFromB64url(msg.getString("transferId")))
        val ib = inbox.remove(transferIdHex)
        ib?.gapJob?.cancel()
        ib?.giveupJob?.cancel()
        hooks.onReceiveError(transferIdHex, msg.optString("code", "PEER_FAILED"))
    }

    // -------------------------------------------------------------------------
    // Rotation
    // -------------------------------------------------------------------------

    suspend fun rotateKAB(targetDeviceId: String) = rotationMutex.withLock {
        val peer = hooks.getPeer(targetDeviceId)
            ?: throw BeamV2Exception("NO_PEER", "peer $targetDeviceId not paired")
        val fromGen = peer.kABRing.currentGeneration
        val toGen   = fromGen + 1
        val nonce   = ByteArray(16).also { random.nextBytes(it) }
        pendingRotations[targetDeviceId] = PendingRotation(fromGen, toGen, nonce, "initiator")
        sendJson(JSONObject()
            .put("type", "beam-v2-rotate-init")
            .put("fromGen", fromGen)
            .put("toGen", toGen)
            .put("nonce", b64urlFromBytes(nonce))
            .put("targetDeviceId", targetDeviceId)
            .put("rendezvousId", targetDeviceId))
    }

    private suspend fun handleRotateInit(msg: JSONObject) {
        val fromDeviceId = msg.optString("fromDeviceId").takeIf { it.isNotEmpty() } ?: return
        val peer = hooks.getPeer(fromDeviceId) ?: return

        val ours = pendingRotations[fromDeviceId]
        if (ours != null && ours.role == "initiator") {
            // Tiebreaker: lex-smaller deviceId wins concurrent rotation.
            val ourId = hooks.ourDeviceId()
            if (ourId != null && fromDeviceId > ourId) return // peer's id larger → ignore
        }

        val nonce = bytesFromB64url(msg.getString("nonce"))
        val toGen = msg.getInt("toGen")
        val newKab = codec.deriveKAB(
            ourSk = peer.ourSk, peerPk = peer.peerPk,
            ourEdPk = peer.ourEdPk, peerEdPk = peer.peerEdPk,
            generation = toGen, rotateNonce = nonce,
        )
        val newRing = stageRotation(peer.kABRing, toGen, newKab, nonce)
        hooks.storeKABRing(fromDeviceId, newRing)

        sendJson(JSONObject()
            .put("type", "beam-v2-rotate-ack")
            .put("fromGen", msg.getInt("fromGen"))
            .put("toGen", toGen)
            .put("nonce", msg.getString("nonce"))
            .put("targetDeviceId", fromDeviceId)
            .put("rendezvousId", fromDeviceId))
    }

    private suspend fun handleRotateAck(msg: JSONObject) {
        val fromDeviceId = msg.optString("fromDeviceId").takeIf { it.isNotEmpty() } ?: return
        val pending = pendingRotations[fromDeviceId] ?: return
        val toGen = msg.getInt("toGen")
        if (pending.toGen != toGen) return
        val peer = hooks.getPeer(fromDeviceId) ?: return

        val newKab = codec.deriveKAB(
            ourSk = peer.ourSk, peerPk = peer.peerPk,
            ourEdPk = peer.ourEdPk, peerEdPk = peer.peerEdPk,
            generation = toGen, rotateNonce = pending.nonce,
        )
        val staged = stageRotation(peer.kABRing, toGen, newKab, pending.nonce)
        val newKeys = staged.keys.toMutableMap()
        // expire old generation
        newKeys[pending.fromGen]?.let { old ->
            newKeys[pending.fromGen] = old.copy(expiresAt = System.currentTimeMillis() + BeamV2Constants.ROTATION_GRACE_MS)
        }
        val committed = KABRing(currentGeneration = toGen, keys = newKeys)
        hooks.storeKABRing(fromDeviceId, committed)
        pendingRotations.remove(fromDeviceId)

        sendJson(JSONObject()
            .put("type", "beam-v2-rotate-commit")
            .put("toGen", toGen)
            .put("targetDeviceId", fromDeviceId)
            .put("rendezvousId", fromDeviceId))
    }

    private suspend fun handleRotateCommit(msg: JSONObject) {
        val fromDeviceId = msg.optString("fromDeviceId").takeIf { it.isNotEmpty() } ?: return
        val peer = hooks.getPeer(fromDeviceId) ?: return
        val toGen = msg.getInt("toGen")
        val ring = peer.kABRing
        if (!ring.keys.containsKey(toGen)) return

        val oldGen = ring.currentGeneration
        val newKeys = ring.keys.toMutableMap()
        newKeys[oldGen]?.let { old ->
            newKeys[oldGen] = old.copy(expiresAt = System.currentTimeMillis() + BeamV2Constants.ROTATION_GRACE_MS)
        }
        hooks.storeKABRing(fromDeviceId, KABRing(toGen, newKeys))
    }

    private fun stageRotation(ring: KABRing, toGen: Int, kAB: ByteArray, nonce: ByteArray): KABRing {
        val newKeys = ring.keys.toMutableMap()
        newKeys[toGen] = KABEntry(kAB = kAB, rotateNonce = nonce, createdAt = System.currentTimeMillis())
        return ring.copy(keys = newKeys)
    }

    // -------------------------------------------------------------------------
    // Helpers
    // -------------------------------------------------------------------------

    private fun parseMetaFrame(plaintext: ByteArray): Pair<JSONObject?, ByteArray> {
        if (plaintext.size < 2) return null to ByteArray(0)
        val metaLen = ((plaintext[0].toInt() and 0xff) shl 8) or (plaintext[1].toInt() and 0xff)
        if (metaLen == 0 || 2 + metaLen > plaintext.size) return null to ByteArray(0)
        val meta = try {
            JSONObject(String(plaintext, 2, metaLen, Charsets.UTF_8))
        } catch (_: Exception) {
            return null to ByteArray(0)
        }
        val payload = plaintext.copyOfRange(2 + metaLen, plaintext.size)
        return meta to payload
    }

    private fun putU16be(b: ByteArray, off: Int, v: Int) {
        b[off]     = ((v ushr 8) and 0xff).toByte()
        b[off + 1] = (v and 0xff).toByte()
    }

    private fun bytesToHex(b: ByteArray): String {
        val sb = StringBuilder(b.size * 2)
        for (x in b) {
            val v = x.toInt() and 0xff
            sb.append(HEX[v ushr 4]); sb.append(HEX[v and 0xf])
        }
        return sb.toString()
    }

    private fun hexToBytes(s: String): ByteArray {
        val out = ByteArray(s.length / 2)
        for (i in out.indices) {
            out[i] = ((Character.digit(s[i * 2], 16) shl 4) or Character.digit(s[i * 2 + 1], 16)).toByte()
        }
        return out
    }

    private fun b64urlFromBytes(b: ByteArray): String =
        Base64.getUrlEncoder().withoutPadding().encodeToString(b)

    private fun bytesFromB64url(s: String): ByteArray =
        Base64.getUrlDecoder().decode(s)

    companion object {
        private val HEX = "0123456789abcdef".toCharArray()
    }
}

class BeamV2Exception(val code: String, message: String) : RuntimeException(message)
