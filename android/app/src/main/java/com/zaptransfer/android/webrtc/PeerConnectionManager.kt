package com.zaptransfer.android.webrtc

import android.content.Context
import android.util.Log
import dagger.hilt.android.qualifiers.ApplicationContext
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.cancel
import kotlinx.coroutines.launch
import org.json.JSONObject
import org.webrtc.DataChannel
import org.webrtc.DefaultVideoDecoderFactory
import org.webrtc.DefaultVideoEncoderFactory
import org.webrtc.EglBase
import org.webrtc.IceCandidate
import org.webrtc.MediaConstraints
import org.webrtc.PeerConnection
import org.webrtc.PeerConnectionFactory
import org.webrtc.RtpTransceiver
import org.webrtc.SdpObserver
import org.webrtc.SessionDescription
import java.nio.ByteBuffer
import java.util.concurrent.ConcurrentHashMap
import javax.inject.Inject
import javax.inject.Singleton

private const val TAG = "PeerConnectionManager"

/**
 * STUN/TURN server configuration.
 *
 * Uses Google's public STUN servers for development. Production deployments should
 * configure a private STUN/TURN server (e.g., via Coturn) to avoid dependency on
 * Google infrastructure and to support symmetric NATs via TURN relay.
 */
private val ICE_SERVERS = listOf(
    PeerConnection.IceServer.builder("stun:stun.l.google.com:19302").createIceServer(),
    PeerConnection.IceServer.builder("stun:stun1.l.google.com:19302").createIceServer(),
    PeerConnection.IceServer.builder("stun:stun2.l.google.com:19302").createIceServer(),
)

/**
 * RTCConfiguration shared across all peer connections.
 *
 * - [PeerConnection.BundlePolicy.MAXBUNDLE]: all media/data channels share one transport.
 * - [PeerConnection.RtcpMuxPolicy.REQUIRE]: RTCP is multiplexed on the same port as RTP.
 * - [PeerConnection.TcpCandidatePolicy.DISABLED]: disables slow TCP ICE candidates;
 *   STUN/TURN UDP candidates are sufficient for LAN and relay scenarios.
 */
private val RTC_CONFIG = PeerConnection.RTCConfiguration(ICE_SERVERS).apply {
    bundlePolicy = PeerConnection.BundlePolicy.MAXBUNDLE
    rtcpMuxPolicy = PeerConnection.RtcpMuxPolicy.REQUIRE
    tcpCandidatePolicy = PeerConnection.TcpCandidatePolicy.DISABLED
    continualGatheringPolicy = PeerConnection.ContinualGatheringPolicy.GATHER_CONTINUALLY
    keyType = PeerConnection.KeyType.ECDSA
}

/**
 * [DataChannel.Init] parameters for the file-transfer data channel.
 *
 * - [ordered] = true: chunks must arrive in order. Prevents the receiver from writing
 *   chunk N+1 before chunk N, which would corrupt the assembled file.
 * - [reliable] = implicit (the channel is reliable by default when maxRetransmits and
 *   maxPacketLifeTime are unset). Retransmission is handled by SCTP internally.
 * - [negotiated] = false: the channel is created and signalled in-band by the data
 *   channel protocol (simpler than out-of-band negotiation for this use case).
 */
private fun dataChannelInit(label: String): DataChannel.Init = DataChannel.Init().apply {
    ordered = true
    // id = -1 means SCTP assigns the stream ID automatically
    id = -1
}

/**
 * Manages a set of WebRTC [PeerConnection]s and their associated [DataChannel]s.
 *
 * ## Responsibilities
 *  - Initialise a single [PeerConnectionFactory] for the process lifetime.
 *  - Create and track [PeerConnection]s keyed by peer device ID.
 *  - Create ordered, reliable [DataChannel]s for file transfer.
 *  - Handle WebRTC signalling (offer/answer/ICE candidates) dispatched via [SignalingClient].
 *  - Support [restartIce] for network change recovery (called by [IceRestartPolicy]).
 *  - Expose [isConnected] for connection state queries from [TransferEngine].
 *
 * ## Signalling flow (initiator side)
 *  1. [createConnection] → [createOffer] → send offer via [SignalingClient].
 *  2. Receive answer → [handleAnswer].
 *  3. Receive ICE candidates → [handleIceCandidate].
 *  4. DataChannel opens → [TransferEngine] switches to P2P path.
 *
 * ## Signalling flow (responder side)
 *  1. Receive offer → [handleOffer] → creates answer → sends via [SignalingClient].
 *  2. ICE candidates exchanged via [handleIceCandidate].
 *
 * ## Thread safety
 *  All public methods dispatch to [scope] (IO dispatcher) or run on the WebRTC
 *  signalling thread. [connections] and [dataChannels] are [ConcurrentHashMap]s for
 *  safe concurrent access.
 *
 * @param signalingClient Active relay WebSocket for exchanging SDP + ICE messages.
 * @param context         Application context used to initialise [PeerConnectionFactory].
 */
@Singleton
class PeerConnectionManager @Inject constructor(
    private val signalingClient: SignalingClient,
    @ApplicationContext private val context: Context,
) {
    private val scope = CoroutineScope(SupervisorJob() + Dispatchers.IO)

    /** Shared EGL context — required by [PeerConnectionFactory] even for data-only sessions. */
    private val eglBase: EglBase = EglBase.create()

    /**
     * The single [PeerConnectionFactory] for the process lifetime.
     *
     * [PeerConnectionFactory.initialize] must be called exactly once per process.
     * Calling it a second time is a no-op if the parameters match; calling it with
     * different parameters causes undefined behaviour.
     */
    val factory: PeerConnectionFactory

    /** Live peer connections keyed by peer device ID. */
    private val connections = ConcurrentHashMap<String, PeerConnection>()

    /** Data channels keyed by peer device ID → transfer ID. */
    private val dataChannels = ConcurrentHashMap<String, DataChannel>()

    /** Listener callbacks registered by the TransferEngine for DataChannel events. */
    private val channelListeners = ConcurrentHashMap<String, DataChannelListener>()

    init {
        // One-time native library initialisation (must happen before any WebRTC call)
        PeerConnectionFactory.initialize(
            PeerConnectionFactory.InitializationOptions.builder(context)
                .setEnableInternalTracer(false)
                .createInitializationOptions()
        )

        factory = PeerConnectionFactory.builder()
            .setVideoDecoderFactory(
                DefaultVideoDecoderFactory(eglBase.eglBaseContext)
            )
            .setVideoEncoderFactory(
                DefaultVideoEncoderFactory(eglBase.eglBaseContext, true, true)
            )
            .createPeerConnectionFactory()

        Log.d(TAG, "PeerConnectionFactory initialised")
    }

    // ── Public API ────────────────────────────────────────────────────────────

    /**
     * Creates a new [PeerConnection] for [peerId] and registers it in [connections].
     *
     * If a connection for [peerId] already exists, it is closed and replaced.
     *
     * The connection starts ICE gathering immediately after creation; candidates are
     * automatically forwarded to the remote peer via [SignalingClient].
     *
     * @param peerId The relay device ID of the remote peer.
     * @return The newly created [PeerConnection].
     */
    fun createConnection(peerId: String): PeerConnection {
        // Close any existing connection for this peer before creating a new one
        connections[peerId]?.close()

        val observer = BeamPeerConnectionObserver(peerId)
        val pc = factory.createPeerConnection(RTC_CONFIG, observer)
            ?: error("PeerConnectionFactory returned null for peer $peerId")

        connections[peerId] = pc
        Log.d(TAG, "PeerConnection created for peer $peerId")
        return pc
    }

    /**
     * Creates an ordered, reliable [DataChannel] on [pc] for the given [transferId].
     *
     * The channel label is the [transferId] so each transfer's data channel is uniquely
     * identifiable by the receiver during the [handleOffer] flow.
     *
     * @param pc         The [PeerConnection] to create the channel on.
     * @param transferId UUID of the transfer — used as the DataChannel label.
     * @return The new [DataChannel].
     */
    fun createDataChannel(pc: PeerConnection, transferId: String): DataChannel {
        val channel = pc.createDataChannel(transferId, dataChannelInit(transferId))
            ?: error("createDataChannel returned null for transferId=$transferId")
        Log.d(TAG, "DataChannel created: label=$transferId")
        return channel
    }

    /**
     * Initiates the offer/answer signalling for [peerId] as the ICE initiator.
     *
     * Steps:
     *  1. Creates a [PeerConnection] via [createConnection].
     *  2. Creates a [DataChannel] via [createDataChannel].
     *  3. Generates an SDP offer and sets it as the local description.
     *  4. Sends the offer to the remote peer via [SignalingClient].
     *
     * @param peerId     Remote peer device ID.
     * @param transferId UUID of the transfer — also the DataChannel label.
     * @param listener   Callback for DataChannel open/message/close events.
     */
    fun initiateOffer(peerId: String, transferId: String, listener: DataChannelListener) {
        scope.launch {
            val pc = createConnection(peerId)
            val dc = createDataChannel(pc, transferId)
            dataChannels[peerId] = dc
            channelListeners[peerId] = listener
            dc.registerObserver(BeamDataChannelObserver(peerId, dc, listener))

            val constraints = MediaConstraints()
            pc.createOffer(
                object : SdpObserver {
                    override fun onCreateSuccess(sdp: SessionDescription) {
                        pc.setLocalDescription(
                            object : SdpObserver {
                                override fun onSetSuccess() {
                                    sendSdp(peerId, sdp)
                                    Log.d(TAG, "Offer set and sent to peer $peerId")
                                }
                                override fun onSetFailure(error: String) {
                                    Log.e(TAG, "setLocalDescription failed: $error")
                                }
                                override fun onCreateSuccess(sdp: SessionDescription) {}
                                override fun onCreateFailure(error: String) {}
                            },
                            sdp
                        )
                    }
                    override fun onCreateFailure(error: String) {
                        Log.e(TAG, "createOffer failed for peer $peerId: $error")
                    }
                    override fun onSetSuccess() {}
                    override fun onSetFailure(error: String) {}
                },
                constraints
            )
        }
    }

    /**
     * Handles an incoming SDP offer from [peerId] and creates an answer.
     *
     * Steps:
     *  1. Creates or reuses a [PeerConnection] for [peerId].
     *  2. Sets the remote description (the offer SDP).
     *  3. Creates an SDP answer and sets it as the local description.
     *  4. Sends the answer back via [SignalingClient].
     *
     * The [DataChannel] is created by the initiator's side — the responder receives
     * the channel via [PeerConnectionObserver.onDataChannel].
     *
     * @param peerId The relay device ID of the remote peer (the offerer).
     * @param sdp    The SDP offer from the remote peer.
     */
    fun handleOffer(peerId: String, sdp: SessionDescription) {
        scope.launch {
            val pc = connections[peerId] ?: createConnection(peerId)

            pc.setRemoteDescription(
                object : SdpObserver {
                    override fun onSetSuccess() {
                        Log.d(TAG, "Remote description (offer) set for peer $peerId")
                        createAnswer(peerId, pc)
                    }
                    override fun onSetFailure(error: String) {
                        Log.e(TAG, "setRemoteDescription (offer) failed for $peerId: $error")
                    }
                    override fun onCreateSuccess(sdp: SessionDescription) {}
                    override fun onCreateFailure(error: String) {}
                },
                sdp
            )
        }
    }

    /**
     * Handles an incoming SDP answer from [peerId] and sets it as the remote description.
     *
     * Called after the remote peer responds to our [initiateOffer].
     *
     * @param peerId The relay device ID of the answering peer.
     * @param sdp    The SDP answer from the remote peer.
     */
    fun handleAnswer(peerId: String, sdp: SessionDescription) {
        scope.launch {
            val pc = connections[peerId] ?: run {
                Log.w(TAG, "handleAnswer: no connection for peer $peerId")
                return@launch
            }
            pc.setRemoteDescription(
                object : SdpObserver {
                    override fun onSetSuccess() {
                        Log.d(TAG, "Remote description (answer) set for peer $peerId")
                    }
                    override fun onSetFailure(error: String) {
                        Log.e(TAG, "setRemoteDescription (answer) failed for $peerId: $error")
                    }
                    override fun onCreateSuccess(sdp: SessionDescription) {}
                    override fun onCreateFailure(error: String) {}
                },
                sdp
            )
        }
    }

    /**
     * Adds a trickling ICE candidate received from the remote peer.
     *
     * Must be called AFTER [handleOffer] or [handleAnswer] has set the remote description,
     * otherwise the candidate is silently dropped by the WebRTC stack.
     *
     * @param peerId    The relay device ID of the peer who sent the candidate.
     * @param candidate The [IceCandidate] parsed from the signalling message.
     */
    fun handleIceCandidate(peerId: String, candidate: IceCandidate) {
        val pc = connections[peerId] ?: run {
            Log.w(TAG, "handleIceCandidate: no connection for peer $peerId")
            return
        }
        pc.addIceCandidate(candidate)
        Log.v(TAG, "ICE candidate added for peer $peerId: ${candidate.sdpMid}")
    }

    /**
     * Triggers an ICE restart for [peerId]'s [PeerConnection].
     *
     * An ICE restart creates new ICE ufrag/password values and re-runs the gathering
     * and connectivity-check phases, which allows the connection to recover after a
     * network change (e.g., Wi-Fi → cellular handover).
     *
     * This generates a new offer with `iceRestart: true` in the offer constraints,
     * which the remote peer must respond to with a new answer.
     *
     * @param peerId The relay device ID of the peer whose connection should be restarted.
     */
    fun restartIce(peerId: String) {
        val pc = connections[peerId] ?: run {
            Log.w(TAG, "restartIce: no connection for peer $peerId")
            return
        }
        scope.launch {
            val constraints = MediaConstraints().apply {
                mandatory.add(MediaConstraints.KeyValuePair("IceRestart", "true"))
            }
            pc.createOffer(
                object : SdpObserver {
                    override fun onCreateSuccess(sdp: SessionDescription) {
                        pc.setLocalDescription(
                            object : SdpObserver {
                                override fun onSetSuccess() {
                                    sendSdp(peerId, sdp)
                                    Log.i(TAG, "ICE restart offer sent for peer $peerId")
                                }
                                override fun onSetFailure(error: String) {
                                    Log.e(TAG, "ICE restart setLocalDescription failed: $error")
                                }
                                override fun onCreateSuccess(sdp: SessionDescription) {}
                                override fun onCreateFailure(error: String) {}
                            },
                            sdp
                        )
                    }
                    override fun onCreateFailure(error: String) {
                        Log.e(TAG, "ICE restart createOffer failed for peer $peerId: $error")
                    }
                    override fun onSetSuccess() {}
                    override fun onSetFailure(error: String) {}
                },
                constraints
            )
        }
    }

    /**
     * Sends a chunk via the DataChannel for [peerId].
     *
     * Falls back gracefully if the DataChannel is not open — callers should check
     * [isConnected] before calling this to avoid silent drops.
     *
     * @param peerId The remote peer ID.
     * @param data   The raw bytes to send (encrypted chunk frame).
     * @return true if the data was queued on the DataChannel; false otherwise.
     */
    fun sendData(peerId: String, data: ByteArray): Boolean {
        val dc = dataChannels[peerId] ?: return false
        if (dc.state() != DataChannel.State.OPEN) return false
        val buffer = DataChannel.Buffer(ByteBuffer.wrap(data), true)
        return dc.send(buffer)
    }

    /**
     * Returns true if [peerId] has an active [PeerConnection] in the [CONNECTED] state.
     *
     * [PeerConnection.PeerConnectionState.CONNECTED] means ICE has succeeded and
     * DTLS has completed — the DataChannel should be open or opening.
     *
     * @param peerId The relay device ID of the remote peer.
     */
    fun isConnected(peerId: String): Boolean {
        return connections[peerId]?.connectionState() ==
            PeerConnection.PeerConnectionState.CONNECTED
    }

    /**
     * Closes and removes the [PeerConnection] and [DataChannel] for [peerId].
     *
     * Safe to call if no connection exists for the peer — no-op in that case.
     *
     * @param peerId The relay device ID of the peer to disconnect from.
     */
    fun close(peerId: String) {
        dataChannels.remove(peerId)?.dispose()
        channelListeners.remove(peerId)
        connections.remove(peerId)?.close()
        Log.d(TAG, "Connection closed for peer $peerId")
    }

    /**
     * Closes all connections and releases the [PeerConnectionFactory] and EGL context.
     *
     * Must be called when the owning component (singleton service) is destroyed.
     */
    fun closeAll() {
        connections.keys.toList().forEach { close(it) }
        factory.dispose()
        eglBase.release()
        scope.cancel()
        Log.d(TAG, "PeerConnectionManager closed — all resources released")
    }

    // ── Private helpers ───────────────────────────────────────────────────────

    /**
     * Creates an SDP answer for an inbound offer and sends it to the remote peer.
     *
     * @param peerId Initiator's device ID.
     * @param pc     The [PeerConnection] whose offer was just set as remote description.
     */
    private fun createAnswer(peerId: String, pc: PeerConnection) {
        val constraints = MediaConstraints()
        pc.createAnswer(
            object : SdpObserver {
                override fun onCreateSuccess(sdp: SessionDescription) {
                    pc.setLocalDescription(
                        object : SdpObserver {
                            override fun onSetSuccess() {
                                sendSdp(peerId, sdp)
                                Log.d(TAG, "Answer set and sent to peer $peerId")
                            }
                            override fun onSetFailure(error: String) {
                                Log.e(TAG, "setLocalDescription (answer) failed for $peerId: $error")
                            }
                            override fun onCreateSuccess(sdp: SessionDescription) {}
                            override fun onCreateFailure(error: String) {}
                        },
                        sdp
                    )
                }
                override fun onCreateFailure(error: String) {
                    Log.e(TAG, "createAnswer failed for peer $peerId: $error")
                }
                override fun onSetSuccess() {}
                override fun onSetFailure(error: String) {}
            },
            constraints
        )
    }

    /**
     * Sends an SDP offer or answer to [peerId] via the relay [SignalingClient].
     *
     * Wire format:
     * ```json
     * {
     *   "type": "webrtc_sdp",
     *   "targetDeviceId": "<peerId>",
     *   "sdpType": "offer" | "answer",
     *   "sdp": "<SDP string>"
     * }
     * ```
     *
     * @param peerId Destination device ID.
     * @param sdp    The [SessionDescription] to send.
     */
    private fun sendSdp(peerId: String, sdp: SessionDescription) {
        val msg = JSONObject().apply {
            put("type", "webrtc_sdp")
            put("targetDeviceId", peerId)
            put("sdpType", sdp.type.canonicalForm())
            put("sdp", sdp.description)
        }
        signalingClient.send(msg)
    }

    /**
     * Sends an ICE candidate to [peerId] via the relay.
     *
     * Wire format:
     * ```json
     * {
     *   "type": "webrtc_ice",
     *   "targetDeviceId": "<peerId>",
     *   "sdpMid": "<media stream ID>",
     *   "sdpMLineIndex": <integer>,
     *   "candidate": "<SDP candidate string>"
     * }
     * ```
     *
     * @param peerId    Destination device ID.
     * @param candidate The [IceCandidate] to send.
     */
    private fun sendIceCandidate(peerId: String, candidate: IceCandidate) {
        val msg = JSONObject().apply {
            put("type", "webrtc_ice")
            put("targetDeviceId", peerId)
            put("sdpMid", candidate.sdpMid)
            put("sdpMLineIndex", candidate.sdpMLineIndex)
            put("candidate", candidate.sdp)
        }
        signalingClient.send(msg)
    }

    // ── Observer implementations ──────────────────────────────────────────────

    /**
     * [PeerConnection.Observer] implementation for a single peer connection.
     *
     * Routes ICE candidates to [SignalingClient] and logs connection state changes.
     * When a remote DataChannel is opened (responder side), it is registered in
     * [dataChannels] so [sendData] can find it.
     */
    private inner class BeamPeerConnectionObserver(
        private val peerId: String,
    ) : PeerConnection.Observer {

        override fun onIceCandidate(candidate: IceCandidate) {
            sendIceCandidate(peerId, candidate)
        }

        override fun onIceCandidatesRemoved(candidates: Array<out IceCandidate>) {
            Log.d(TAG, "ICE candidates removed: ${candidates.size} (peer=$peerId)")
        }

        override fun onDataChannel(dataChannel: DataChannel) {
            // Responder side: the initiator opened a DataChannel — register it
            val listener = channelListeners[peerId]
            if (listener != null) {
                dataChannel.registerObserver(
                    BeamDataChannelObserver(peerId, dataChannel, listener)
                )
            }
            dataChannels[peerId] = dataChannel
            Log.d(TAG, "Remote DataChannel received: label=${dataChannel.label()} (peer=$peerId)")
        }

        override fun onConnectionChange(newState: PeerConnection.PeerConnectionState) {
            Log.i(TAG, "Connection state → $newState (peer=$peerId)")
        }

        override fun onIceConnectionChange(newState: PeerConnection.IceConnectionState) {
            Log.d(TAG, "ICE connection state → $newState (peer=$peerId)")
        }

        override fun onIceConnectionReceivingChange(receiving: Boolean) {}

        override fun onIceGatheringChange(newState: PeerConnection.IceGatheringState) {
            Log.d(TAG, "ICE gathering state → $newState (peer=$peerId)")
        }

        override fun onSignalingChange(newState: PeerConnection.SignalingState) {
            Log.d(TAG, "Signaling state → $newState (peer=$peerId)")
        }

        override fun onRenegotiationNeeded() {
            Log.d(TAG, "Renegotiation needed (peer=$peerId)")
        }

        override fun onAddStream(stream: org.webrtc.MediaStream) {}
        override fun onRemoveStream(stream: org.webrtc.MediaStream) {}
        override fun onAddTrack(
            receiver: org.webrtc.RtpReceiver,
            streams: Array<out org.webrtc.MediaStream>,
        ) {}
        override fun onTrack(transceiver: RtpTransceiver) {}
    }

    /**
     * [DataChannel.Observer] implementation that forwards events to [DataChannelListener].
     */
    private inner class BeamDataChannelObserver(
        private val peerId: String,
        private val dataChannel: DataChannel,
        private val listener: DataChannelListener,
    ) : DataChannel.Observer {

        override fun onBufferedAmountChange(previousAmount: Long) {}

        override fun onStateChange() {
            val state = dataChannel.state()
            Log.d(TAG, "DataChannel state → $state (peer=$peerId label=${dataChannel.label()})")
            when (state) {
                DataChannel.State.OPEN -> listener.onOpen(peerId, dataChannel.label())
                DataChannel.State.CLOSED,
                DataChannel.State.CLOSING -> listener.onClose(peerId)
                else -> { /* CONNECTING — no action */ }
            }
        }

        override fun onMessage(buffer: DataChannel.Buffer) {
            val data = ByteArray(buffer.data.remaining())
            buffer.data.get(data)
            listener.onMessage(peerId, data)
        }
    }
}

// ── DataChannelListener interface ─────────────────────────────────────────────

/**
 * Callback interface for [DataChannel] lifecycle and data events.
 *
 * Implemented by [TransferEngine] to receive P2P chunks without polling.
 */
interface DataChannelListener {
    /**
     * Called when the [DataChannel] transitions to [DataChannel.State.OPEN].
     *
     * After this callback, [PeerConnectionManager.sendData] is safe to call.
     * The [TransferEngine] uses this to switch from relay to the P2P path.
     *
     * @param peerId      Remote peer device ID.
     * @param channelLabel The DataChannel label (= transferId for Beam channels).
     */
    fun onOpen(peerId: String, channelLabel: String)

    /**
     * Called for every incoming binary message on the DataChannel.
     *
     * Equivalent to [SignalingListener.onMessage] for [RelayMessage.Binary] — the
     * [TransferEngine] can use the same chunk handler for both relay and P2P frames.
     *
     * @param peerId Remote peer device ID.
     * @param data   Raw binary chunk frame bytes.
     */
    fun onMessage(peerId: String, data: ByteArray)

    /**
     * Called when the [DataChannel] closes (either side closed or connection lost).
     *
     * The [TransferEngine] should fall back to the relay path.
     *
     * @param peerId Remote peer device ID.
     */
    fun onClose(peerId: String)
}
