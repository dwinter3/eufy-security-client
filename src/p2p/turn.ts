/**
 * TURN client for the WebRTC transport used by S4 Max NVR (type 300) stations.
 * See issue #863.
 *
 * The eufy app obtains a relay candidate by sending a STUN `Allocate` to the
 * TURN server listed in the station record's `signaling_servers` (observed:
 * `13.248.157.102:3478`, SOFTWARE=libcoreice). This client performs the
 * Allocate / Refresh exchange and exposes the relayed transport address as an
 * ICE `relay` candidate.
 *
 * Status: Allocate/Refresh implemented and verified against the #863 capture —
 * the server is coturn (`Coturn-4.6.2`), realm `anker.com`, RFC 5766 long-term
 * credentials (MD5 key). The 16-char per-session TURN username/password are
 * carried in the encrypted P2P control session (the signaling layer, TBD).
 */
import { EventEmitter } from "events";
import { createSocket, Socket } from "dgram";
import { randomBytes, createHash } from "crypto";
import {
    encodeStun,
    parseStun,
    appendMessageIntegrity,
    appendFingerprint,
    StunMessageType,
    StunAttribute,
    StunAttr,
} from "./ice";
import { IceCandidate } from "./iceagent";

const ALLOCATE_LIFETIME_S = 600;
const UDP_TRANSPORT = 0x11000000; // REQUESTED-TRANSPORT value for UDP
// SOFTWARE value the eufy/libcoreice client sends — observed in the #863 capture.
const SOFTWARE_NAME = "libcoreice";

export interface TurnConfig {
    host: string;
    port: number;
    username: string;
    password: string;
}

export class TurnClient extends EventEmitter {
    private socket?: Socket;
    private nonce?: Buffer;
    private realm?: Buffer;
    private relayCandidate?: IceCandidate;

    constructor(private readonly config: TurnConfig) {
        super();
    }

    /** Allocate a relay address on the TURN server; resolves to a relay ICE candidate. */
    public async allocate(): Promise<IceCandidate> {
        const socket = createSocket("udp4");
        this.socket = socket;
        socket.on("message", (msg) => this.onMessage(msg));
        await new Promise<void>((resolve, reject) => {
            socket.once("error", reject);
            socket.bind(0, () => resolve());
        });
        return new Promise<IceCandidate>((resolve, reject) => {
            this.once("allocated", resolve);
            this.once("error", reject);
            setTimeout(() => reject(new Error("TURN allocate timed out")), 8000);
            this.sendAllocate();
        });
    }

    private sendAllocate(): void {
        if (!this.socket) return;
        // Attribute order matches the observed eufy/libcoreice client (#863 capture):
        // LIFETIME, REQUESTED-TRANSPORT, SOFTWARE, USERNAME, [REALM, NONCE], [MI], FINGERPRINT.
        // The real client sends USERNAME on the *first* Allocate too; REALM/NONCE and
        // MESSAGE-INTEGRITY are added only after the 401 challenge supplies them.
        const attrs: StunAttr[] = [
            { type: StunAttribute.Lifetime, value: u32(ALLOCATE_LIFETIME_S) },
            { type: StunAttribute.RequestedTransport, value: u32(UDP_TRANSPORT) },
            { type: StunAttribute.Software, value: Buffer.from(SOFTWARE_NAME) },
            { type: StunAttribute.Username, value: Buffer.from(this.config.username) },
        ];
        let key: Buffer | undefined;
        if (this.nonce && this.realm) {
            attrs.push({ type: STUN_ATTR_REALM, value: this.realm });
            attrs.push({ type: STUN_ATTR_NONCE, value: this.nonce });
            key = longTermKey(this.config.username, this.realm.toString(), this.config.password);
        }
        let msg = encodeStun({
            messageType: StunMessageType.AllocateRequest,
            transactionId: randomBytes(12),
            attributes: attrs,
        });
        if (key) msg = appendMessageIntegrity(msg, key);
        msg = appendFingerprint(msg); // FINGERPRINT is always last, after MESSAGE-INTEGRITY.
        this.socket.send(msg, this.config.port, this.config.host);
    }

    private onMessage(data: Buffer): void {
        const stun = parseStun(data);
        if (!stun) return;
        if (stun.messageType === StunMessageType.AllocateError) {
            // 401 Unauthorized -> capture REALM + NONCE and retry with credentials
            const realm = findAttr(stun.attributes, STUN_ATTR_REALM);
            const nonce = findAttr(stun.attributes, STUN_ATTR_NONCE);
            if (realm && nonce && !this.nonce) {
                this.realm = realm;
                this.nonce = nonce;
                this.sendAllocate();
                return;
            }
            this.emit("error", new Error("TURN Allocate rejected"));
        } else if (stun.messageType === StunMessageType.AllocateSuccess) {
            const relayed = findAttr(stun.attributes, StunAttribute.XorRelayedAddress);
            if (!relayed) {
                this.emit("error", new Error("Allocate success without XOR-RELAYED-ADDRESS"));
                return;
            }
            const addr = decodeXorAddress(relayed, stun.transactionId);
            this.relayCandidate = {
                foundation: "turn",
                component: 1,
                transport: "udp",
                priority: 16777215, // low local-pref relay priority
                ip: addr.ip,
                port: addr.port,
                type: "relay",
            };
            this.emit("allocated", this.relayCandidate);
        }
    }

    public close(): void {
        this.socket?.close();
        this.socket = undefined;
    }
}

/** STUN long-term credential key: MD5(username:realm:password). */
function longTermKey(username: string, realm: string, password: string): Buffer {
    return createHash("md5").update(`${username}:${realm}:${password}`).digest();
}

/** Decode a XOR-MAPPED/RELAYED-ADDRESS attribute (IPv4). */
function decodeXorAddress(value: Buffer, txid: Buffer): { ip: string; port: number } {
    const port = value.readUInt16BE(2) ^ 0x2112;
    const magic = Buffer.from([0x21, 0x12, 0xa4, 0x42]);
    const ipBytes = Buffer.from([
        value[4] ^ magic[0],
        value[5] ^ magic[1],
        value[6] ^ magic[2],
        value[7] ^ magic[3],
    ]);
    return { ip: ipBytes.join("."), port };
}

function findAttr(attrs: StunAttr[], type: number): Buffer | undefined {
    return attrs.find((a) => a.type === type)?.value;
}

const STUN_ATTR_REALM = 0x0014;
const STUN_ATTR_NONCE = 0x0015;

const u32 = (n: number): Buffer => {
    const b = Buffer.alloc(4);
    b.writeUInt32BE(n >>> 0, 0);
    return b;
};
