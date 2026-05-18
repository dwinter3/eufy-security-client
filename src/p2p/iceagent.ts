/**
 * ICE agent for the WebRTC transport used by S4 Max NVR (type 300) stations.
 * See issue #863.
 *
 * Host-candidate connectivity using the STUN codec in ./ice. RFC 8445-style
 * check list, scoped to the eufy LAN case. Remote candidates are fed in from
 * the PPCS-32100 rendezvous; TURN relay candidates are added by the TURN
 * client (both built separately). This module is the connectivity core.
 *
 * Status: agent + host-candidate checks implemented; not yet wired to a
 * rendezvous source, so it cannot establish a session standalone.
 */
import { EventEmitter } from "events";
import { createSocket, Socket } from "dgram";
import { networkInterfaces } from "os";
import { randomBytes } from "crypto";
import {
    buildConnectivityCheck,
    parseStun,
    isStun,
    StunMessageType,
} from "./ice";

export interface IceCandidate {
    foundation: string;
    component: number;
    transport: "udp";
    priority: number;
    ip: string;
    port: number;
    type: "host" | "srflx" | "relay";
}

export interface IceCredentials {
    localUfrag: string;
    localPwd: string;
    remoteUfrag: string;
    remotePwd: string;
}

interface CandidatePair {
    local: IceCandidate;
    remote: IceCandidate;
    state: "waiting" | "in-progress" | "succeeded" | "failed";
    txid?: Buffer;
}

const CHECK_INTERVAL_MS = 50;
const CHECK_TIMEOUT_MS = 8000;

export class IceAgent extends EventEmitter {
    private socket?: Socket;
    private readonly localCandidates: IceCandidate[] = [];
    private readonly remoteCandidates: IceCandidate[] = [];
    private readonly pairs: CandidatePair[] = [];
    private readonly controlling: boolean;
    private readonly tieBreaker = randomBytes(8);
    private creds?: IceCredentials;
    private checkTimer?: ReturnType<typeof setInterval>;
    private connected = false;

    constructor(controlling = true) {
        super();
        this.controlling = controlling;
    }

    /** Gather host candidates: bind one UDP socket, enumerate non-internal IPv4 interfaces. */
    public async gather(): Promise<IceCandidate[]> {
        const socket = createSocket("udp4");
        this.socket = socket;
        socket.on("message", (msg, rinfo) => this.onPacket(msg, rinfo.address, rinfo.port));
        await new Promise<void>((resolve, reject) => {
            socket.once("error", reject);
            socket.bind(0, () => resolve());
        });
        const port = socket.address().port;
        let foundation = 0;
        for (const addrs of Object.values(networkInterfaces())) {
            for (const a of addrs ?? []) {
                if (a.family === "IPv4" && !a.internal) {
                    foundation += 1;
                    this.localCandidates.push({
                        foundation: String(foundation),
                        component: 1,
                        transport: "udp",
                        priority: candidatePriority("host", foundation),
                        ip: a.address,
                        port,
                        type: "host",
                    });
                }
            }
        }
        for (const c of this.localCandidates) this.emit("candidate", c);
        return this.localCandidates;
    }

    public setCredentials(creds: IceCredentials): void {
        this.creds = creds;
    }

    public addRemoteCandidate(c: IceCandidate): void {
        this.remoteCandidates.push(c);
        for (const local of this.localCandidates) {
            this.pairs.push({ local, remote: c, state: "waiting" });
        }
    }

    /** Begin connectivity checks. Outcome is delivered via 'connected' / 'failed'. */
    public start(): void {
        if (!this.creds) throw new Error("ICE credentials not set");
        const deadline = Date.now() + CHECK_TIMEOUT_MS;
        this.checkTimer = setInterval(() => {
            if (this.connected) return;
            if (Date.now() > deadline) {
                this.stop();
                this.emit("failed", new Error("ICE connectivity checks timed out"));
                return;
            }
            const pair = this.pairs.find((p) => p.state === "waiting");
            if (pair) this.sendCheck(pair);
        }, CHECK_INTERVAL_MS);
    }

    private sendCheck(pair: CandidatePair): void {
        if (!this.socket || !this.creds) return;
        pair.state = "in-progress";
        pair.txid = randomBytes(12);
        const msg = buildConnectivityCheck({
            transactionId: pair.txid,
            username: `${this.creds.remoteUfrag}:${this.creds.localUfrag}`,
            priority: pair.local.priority,
            controlling: this.controlling,
            tieBreaker: this.tieBreaker,
            integrityKey: Buffer.from(this.creds.remotePwd, "utf8"),
        });
        this.socket.send(msg, pair.remote.port, pair.remote.ip);
    }

    private onPacket(data: Buffer, ip: string, port: number): void {
        if (!isStun(data)) {
            this.emit("data", data, ip, port);
            return;
        }
        const stun = parseStun(data);
        if (!stun) return;
        if (stun.messageType === StunMessageType.BindingSuccess) {
            const pair = this.pairs.find((p) => p.txid?.equals(stun.transactionId));
            if (pair && !this.connected) {
                pair.state = "succeeded";
                this.connected = true;
                this.stop();
                this.emit("connected", {
                    local: pair.local,
                    remote: pair.remote,
                    socket: this.socket,
                });
            }
        } else if (stun.messageType === StunMessageType.BindingRequest) {
            // peer-initiated connectivity check; a full agent replies Binding Success
            this.emit("incoming-check", stun, ip, port);
        }
    }

    public stop(): void {
        if (this.checkTimer) clearInterval(this.checkTimer);
        this.checkTimer = undefined;
    }

    public close(): void {
        this.stop();
        this.socket?.close();
        this.socket = undefined;
    }
}

/** RFC 8445 candidate priority. */
function candidatePriority(type: "host" | "srflx" | "relay", localPref: number): number {
    const typePreference = type === "host" ? 126 : type === "srflx" ? 100 : 0;
    return ((typePreference << 24) | ((65535 - localPref) << 8) | 255) >>> 0;
}
