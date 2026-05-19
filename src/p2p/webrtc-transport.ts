/**
 * WebRTC transport for S4 Max NVR (type 300) stations — issue #863.
 *
 * Orchestrates the four modules built for the WebRTC connection path that the
 * legacy `P2PClientProtocol` does not implement:
 *
 *   signaling.ts  — the 0x0800 / 5062 signaling channel (AES-128-ECB)
 *   turn.ts       — TURN Allocate -> relay candidate
 *   iceagent.ts   — ICE host candidates + connectivity checks
 *   media.ts      — AES-GCM media-frame crypto
 *
 * Connection flow (verified order, from the #863 capture + BC_P2PClient RE):
 *   1. open the signaling channel and register with the signaling server
 *   2. gather ICE candidates (host) + a TURN relay candidate
 *   3. exchange SDP + ICE credentials over signaling
 *   4. run ICE connectivity checks; on success the data channel is up
 *   5. send CMD_START_REALTIME_MEDIA; decrypt incoming frames with media.ts
 *
 * Status: orchestration skeleton. The crypto in each module is verified; the
 * end-to-end sequencing here needs a live-device dev loop (see TODOs) — this
 * class makes that loop short by having every piece wired and typed.
 */
import { EventEmitter } from "events";
import { IceAgent, IceCredentials } from "./iceagent";
import { TurnClient } from "./turn";
import { SignalingClient } from "./signaling";
import { MediaKey, decryptMediaFrame } from "./media";

/** Minimal shape of the station fields this transport needs (see RawStation). */
export interface WebRTCStationInfo {
    station_sn: string;
    device_type: number;
    webrtc_sdk_version?: string;
    signaling_servers?: Array<string>;
}

/** S4 Max NVR. Kept in sync with DeviceType.NVR_S4_MAX in http/types.ts. */
const DEVICE_TYPE_NVR_S4_MAX = 300;

/**
 * Transport selector: a type-300 station with a non-empty `webrtc_sdk_version`
 * uses this WebRTC path instead of `P2PClientProtocol`.
 */
export function shouldUseWebRTC(station: WebRTCStationInfo): boolean {
    return (
        station.device_type === DEVICE_TYPE_NVR_S4_MAX &&
        !!station.webrtc_sdk_version &&
        station.webrtc_sdk_version.length > 0
    );
}

export interface WebRTCTransportConfig {
    station: WebRTCStationInfo;
    account: string;
}

export class WebRTCTransport extends EventEmitter {
    private signaling?: SignalingClient;
    private ice?: IceAgent;
    private turn?: TurnClient;
    private mediaKey?: MediaKey;
    private connected = false;

    constructor(private readonly config: WebRTCTransportConfig) {
        super();
    }

    /** Run the connection flow. Resolves once the ICE data channel is up. */
    public async connect(): Promise<void> {
        const host = pickSignalingHost(this.config.station.signaling_servers);
        if (!host) throw new Error("station has no signaling_servers");

        // 1. signaling channel
        this.signaling = new SignalingClient({
            host,
            stationSN: this.config.station.station_sn,
            account: this.config.account,
        });
        await this.signaling.open();

        // 2. candidate gathering — host candidates + a TURN relay candidate
        this.ice = new IceAgent(false); // app side is ICE-CONTROLLED (NVR controls)
        const hostCandidates = await this.ice.gather();
        this.turn = new TurnClient({ host, port: 3478, username: "", password: "" });
        // TODO(#863): TURN long-term creds arrive in the signaling SDP — feed
        // them in before allocate() once the SDP exchange (step 3) is wired.

        // 3. SDP / ICE credential exchange over signaling
        this.signaling.on("message", (body: Buffer) => this.onSignalingMessage(body));
        // TODO(#863): build + send the local SDP offer; the remote answer
        // carries the ICE ufrag/pwd and TURN creds — needs live validation.

        // 4. ICE connectivity — resolves the promise on "connected"
        await new Promise<void>((resolve, reject) => {
            this.ice!.once("connected", () => {
                this.connected = true;
                this.emit("connected");
                resolve();
            });
            this.ice!.once("failed", reject);
            void hostCandidates; // candidates are exchanged via signaling (step 3)
        });

        // 5. media — incoming frames are AES-GCM; decrypt via media.ts
        this.ice.on("data", (frame: Buffer) => this.onMediaFrame(frame));
    }

    /** Provide the negotiated media key (from the signaling SDP / ECC exchange). */
    public setMediaKey(mediaKey: MediaKey): void {
        this.mediaKey = mediaKey;
    }

    private onSignalingMessage(body: Buffer): void {
        // TODO(#863): parse the SDP answer -> IceCredentials + remote candidates
        // + MediaKey, then this.ice.setCredentials(...) / addRemoteCandidate(...).
        this.emit("signaling", body);
    }

    private onMediaFrame(frame: Buffer): void {
        if (!this.mediaKey) {
            this.emit("media-raw", frame);
            return;
        }
        try {
            this.emit("media", decryptMediaFrame(this.mediaKey, frame));
        } catch (err) {
            this.emit("media-error", err);
        }
    }

    public isConnected(): boolean {
        return this.connected;
    }

    public applyCredentials(creds: IceCredentials): void {
        this.ice?.setCredentials(creds);
    }

    public close(): void {
        this.signaling?.close();
        this.ice?.close();
        this.turn?.close();
        this.connected = false;
    }
}

/** Prefer a bare host[:port] entry; strip any `https://` scheme. */
function pickSignalingHost(servers?: Array<string>): string | undefined {
    if (!servers || servers.length === 0) return undefined;
    for (const s of servers) {
        const h = s.replace(/^https?:\/\//, "").split("/")[0];
        if (h) return h;
    }
    return undefined;
}
