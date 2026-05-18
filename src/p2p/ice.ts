/**
 * STUN / ICE / TURN message codec — foundation for the WebRTC-based transport
 * used by S4 Max NVR (type 300) stations. See issue #863.
 *
 * The S4 Max NVR does not use the legacy Throughtek P2P (`P2PClientProtocol`)
 * connectivity path. It bootstraps via PPCS rendezvous (UDP 32100-32102), then
 * an ICE exchange: STUN connectivity checks to host candidates and a TURN
 * `Allocate` against the station's `signaling_servers`. This module implements
 * the STUN/ICE/TURN wire format that layer needs.
 *
 * Status: codec complete; the ICE agent state machine + PPCS-32100 rendezvous
 * integration + media handoff are still to be built on top.
 */
import { createHmac } from "crypto";

export const STUN_MAGIC_COOKIE = 0x2112a442;

export enum StunMessageType {
    BindingRequest = 0x0001,
    BindingIndication = 0x0011,
    BindingSuccess = 0x0101,
    BindingError = 0x0111,
    AllocateRequest = 0x0003,
    AllocateSuccess = 0x0103,
    AllocateError = 0x0113,
    RefreshRequest = 0x0004,
    CreatePermissionRequest = 0x0008,
}

export enum StunAttribute {
    MappedAddress = 0x0001,
    Username = 0x0006,
    MessageIntegrity = 0x0008,
    ErrorCode = 0x0009,
    Lifetime = 0x000d,
    XorPeerAddress = 0x0012,
    XorRelayedAddress = 0x0016,
    RequestedTransport = 0x0019,
    XorMappedAddress = 0x0020,
    Priority = 0x0024,
    UseCandidate = 0x0025,
    Software = 0x8022,
    Fingerprint = 0x8028,
    IceControlled = 0x8029,
    IceControlling = 0x802a,
}

export interface StunAttr {
    type: number;
    value: Buffer;
}

export interface StunMessage {
    messageType: number;
    transactionId: Buffer; // 12 bytes
    attributes: StunAttr[];
}

const pad4 = (n: number): number => (4 - (n % 4)) % 4;

/** CRC-32 (IEEE) — needed for the STUN FINGERPRINT attribute. */
const CRC_TABLE: number[] = (() => {
    const t: number[] = [];
    for (let n = 0; n < 256; n++) {
        let c = n;
        for (let k = 0; k < 8; k++) c = c & 1 ? 0xedb88320 ^ (c >>> 1) : c >>> 1;
        t[n] = c >>> 0;
    }
    return t;
})();
export function crc32(buf: Buffer): number {
    let c = 0xffffffff;
    for (let i = 0; i < buf.length; i++) c = CRC_TABLE[(c ^ buf[i]) & 0xff] ^ (c >>> 8);
    return (c ^ 0xffffffff) >>> 0;
}

/** Encode a STUN message. Attributes are emitted in order. */
export function encodeStun(msg: StunMessage): Buffer {
    const parts: Buffer[] = [];
    for (const a of msg.attributes) {
        const hdr = Buffer.alloc(4);
        hdr.writeUInt16BE(a.type, 0);
        hdr.writeUInt16BE(a.value.length, 2);
        parts.push(hdr, a.value, Buffer.alloc(pad4(a.value.length)));
    }
    const body = Buffer.concat(parts);
    const header = Buffer.alloc(20);
    header.writeUInt16BE(msg.messageType, 0);
    header.writeUInt16BE(body.length, 2);
    header.writeUInt32BE(STUN_MAGIC_COOKIE, 4);
    msg.transactionId.copy(header, 8, 0, 12);
    return Buffer.concat([header, body]);
}

/** Append a MESSAGE-INTEGRITY attribute (HMAC-SHA1 over the message, short-term creds). */
export function appendMessageIntegrity(message: Buffer, key: Buffer): Buffer {
    const newLen = message.length - 20 + 24; // +4 attr header +20 HMAC
    const hashInput = Buffer.from(message);
    hashInput.writeUInt16BE(newLen, 2);
    const mac = createHmac("sha1", key).update(hashInput).digest();
    const attr = Buffer.alloc(24);
    attr.writeUInt16BE(StunAttribute.MessageIntegrity, 0);
    attr.writeUInt16BE(20, 2);
    mac.copy(attr, 4);
    const out = Buffer.concat([message, attr]);
    out.writeUInt16BE(newLen, 2);
    return out;
}

/** Append a FINGERPRINT attribute (CRC-32 of the message XOR 0x5354554e). */
export function appendFingerprint(message: Buffer): Buffer {
    const newLen = message.length - 20 + 8;
    const hashInput = Buffer.from(message);
    hashInput.writeUInt16BE(newLen, 2);
    const fp = (crc32(hashInput) ^ 0x5354554e) >>> 0;
    const attr = Buffer.alloc(8);
    attr.writeUInt16BE(StunAttribute.Fingerprint, 0);
    attr.writeUInt16BE(4, 2);
    attr.writeUInt32BE(fp, 4);
    const out = Buffer.concat([message, attr]);
    out.writeUInt16BE(newLen, 2);
    return out;
}

/** Parse a STUN message; returns undefined if not a valid STUN packet. */
export function parseStun(data: Buffer): StunMessage | undefined {
    if (data.length < 20 || data.readUInt32BE(4) !== STUN_MAGIC_COOKIE) return undefined;
    const messageType = data.readUInt16BE(0);
    const length = data.readUInt16BE(2);
    const transactionId = data.subarray(8, 20);
    const attributes: StunAttr[] = [];
    let o = 20;
    const end = Math.min(20 + length, data.length);
    while (o + 4 <= end) {
        const type = data.readUInt16BE(o);
        const len = data.readUInt16BE(o + 2);
        if (o + 4 + len > data.length) break;
        attributes.push({ type, value: data.subarray(o + 4, o + 4 + len) });
        o += 4 + len + pad4(len);
    }
    return { messageType, transactionId, attributes };
}

export const isStun = (data: Buffer): boolean =>
    data.length >= 8 && data.readUInt32BE(4) === STUN_MAGIC_COOKIE;

/** Build an ICE connectivity-check Binding Request (USERNAME + PRIORITY + ICE role,
 *  then MESSAGE-INTEGRITY keyed by the peer password, then FINGERPRINT). */
export function buildConnectivityCheck(opts: {
    transactionId: Buffer;
    username: string;
    priority: number;
    controlling: boolean;
    tieBreaker: Buffer; // 8 bytes
    integrityKey: Buffer;
}): Buffer {
    const attrs: StunAttr[] = [
        { type: StunAttribute.Username, value: Buffer.from(opts.username, "utf8") },
        { type: StunAttribute.Priority, value: u32(opts.priority) },
        {
            type: opts.controlling ? StunAttribute.IceControlling : StunAttribute.IceControlled,
            value: opts.tieBreaker,
        },
    ];
    let msg = encodeStun({
        messageType: StunMessageType.BindingRequest,
        transactionId: opts.transactionId,
        attributes: attrs,
    });
    msg = appendMessageIntegrity(msg, opts.integrityKey);
    msg = appendFingerprint(msg);
    return msg;
}

const u32 = (n: number): Buffer => {
    const b = Buffer.alloc(4);
    b.writeUInt32BE(n >>> 0, 0);
    return b;
};
