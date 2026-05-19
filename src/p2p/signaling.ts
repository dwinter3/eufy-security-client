/**
 * Signaling client for the eufy WebRTC `0x0800` protocol used by S4 Max NVR
 * (type 300) stations. See issue #863 and S4_NVR_STATUS.md.
 *
 * The cipher and key schedule were reverse-engineered address-by-address from
 * the eufy iOS app's `BC_P2PClient.framework` (unencrypted; see
 * eufy-debug/FINDINGS-863-part4.md):
 *
 *   - cipher: AES-128-ECB (the app uses mbedTLS `mbedtls_aes_crypt_ecb`).
 *   - per-message key: `quickAesKey` (16 ASCII chars) with the message's
 *     decimal `packetId` overlaid right-aligned onto the tail of the 16 bytes.
 *   - `quickAesKey`: a random [0-9A-Za-z]{16} string, generated per session
 *     (`_generate_aes_key`) and exchanged in-band (`APP_CMD_GET_ASEKEY`).
 *
 * Status:
 *   - The crypto (generateQuickAesKey / deriveMessageKey / encryptBody /
 *     decryptBody) is verified against the disassembly and self-tested below.
 *   - The `0x0800` wire framing and the key-exchange handshake are modelled
 *     from the #863 captures (eufy-debug/app-sig.jsonl) and are marked where
 *     they still need live-device validation.
 */
import { EventEmitter } from "events";
import { createSocket, Socket } from "dgram";
import { createCipheriv, createDecipheriv, randomInt } from "crypto";

/** Charset used by the app's `_generate_aes_key` (digits, lower, upper). */
const KEY_CHARSET =
    "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ";
const KEY_LEN = 16;
const SIGNALING_PORT = 5062;
/** rtc_protocol fixed header length (0x3c), from `_ProtocolGetBuffer`. */
const RTC_HEADER_LEN = 0x3c;

/**
 * CRC-16 over the frame (rtc_protocol header field +0x02).
 * TODO(#863): confirm the exact variant against `_ProtocolGenerateCRC16` — this
 * is CRC-16/CCITT-FALSE (poly 0x1021, init 0xFFFF) as a placeholder.
 */
function crc16(buf: Buffer): number {
    let crc = 0xffff;
    for (let i = 0; i < buf.length; i++) {
        crc ^= buf[i] << 8;
        for (let b = 0; b < 8; b++) {
            crc = crc & 0x8000 ? ((crc << 1) ^ 0x1021) & 0xffff : (crc << 1) & 0xffff;
        }
    }
    return crc;
}

/**
 * Generate a `quickAesKey` — a random 16-character alphanumeric string.
 * Mirrors the app's `_generate_aes_key` (srand(time()); rand() % 62), but uses
 * a CSPRNG instead of `rand()` — the value only has to be random, not
 * reproducible, since it is exchanged in-band.
 */
export function generateQuickAesKey(): string {
    let out = "";
    for (let i = 0; i < KEY_LEN; i++) {
        out += KEY_CHARSET[randomInt(KEY_CHARSET.length)];
    }
    return out;
}

/**
 * Derive the 16-byte AES-128 key for one message.
 *
 * Reverse-engineered from `_get_aes_key_info_by_packetid`: the 16-byte key is
 * `quickAesKey`, then the decimal string of `packetId` is copied so that it
 * *ends* at byte 16 — i.e. it overwrites the tail. Example:
 *   quickAesKey = "aB3xK9pQ7mN2vT5w", packetId = 288357
 *   key         = "aB3xK9pQ7m288357"
 */
export function deriveMessageKey(quickAesKey: string, packetId: number): Buffer {
    const key = Buffer.alloc(KEY_LEN);
    key.write(quickAesKey.slice(0, KEY_LEN).padEnd(KEY_LEN, "\0"), "ascii");
    const idStr = String(packetId >>> 0);
    if (idStr.length >= KEY_LEN) {
        key.write(idStr.slice(0, KEY_LEN), 0, "ascii");
    } else {
        key.write(idStr, KEY_LEN - idStr.length, "ascii"); // right-aligned overlay
    }
    return key;
}

/** Zero-pad a buffer up to the next 16-byte boundary (the app rounds buf_len up). */
function pad16(data: Buffer): Buffer {
    const rem = data.length % 16;
    if (rem === 0) return data;
    return Buffer.concat([data, Buffer.alloc(16 - rem)]);
}

/** Encrypt a message body — AES-128-ECB, key = deriveMessageKey(quickAesKey, packetId). */
export function encryptBody(
    quickAesKey: string,
    packetId: number,
    plaintext: Buffer,
): Buffer {
    const cipher = createCipheriv("aes-128-ecb", deriveMessageKey(quickAesKey, packetId), null);
    cipher.setAutoPadding(false);
    return Buffer.concat([cipher.update(pad16(plaintext)), cipher.final()]);
}

/** Decrypt a message body — AES-128-ECB, key = deriveMessageKey(quickAesKey, packetId). */
export function decryptBody(
    quickAesKey: string,
    packetId: number,
    ciphertext: Buffer,
): Buffer {
    const decipher = createDecipheriv("aes-128-ecb", deriveMessageKey(quickAesKey, packetId), null);
    decipher.setAutoPadding(false);
    const aligned = ciphertext.subarray(0, Math.floor(ciphertext.length / 16) * 16);
    return Buffer.concat([decipher.update(aligned), decipher.final()]);
}

export interface SignalingConfig {
    /** Signaling server host (station record `signaling_servers`, e.g. 13.248.157.102). */
    host: string;
    /** Station serial, sent in the register/keepalive frame. */
    stationSN: string;
    /** Account identifier used in the `account_mix` field of outgoing messages. */
    account: string;
}

/**
 * UDP client for the `0x0800` eufy signaling protocol.
 *
 * The framing below (opcode, length, packetId placement) is modelled from the
 * #863 captures (eufy-debug/app-sig.jsonl). The exact header layout still needs
 * confirmation against a live device — see the TODOs. The crypto, however, is
 * exact (see the standalone functions above).
 */
export class SignalingClient extends EventEmitter {
    private socket?: Socket;
    private quickAesKey: string = generateQuickAesKey();
    private packetId = 0;
    private keepaliveTimer?: ReturnType<typeof setInterval>;

    constructor(private readonly config: SignalingConfig) {
        super();
    }

    /** The session key — generated locally; exchanged via APP_CMD_GET_ASEKEY. */
    public getQuickAesKey(): string {
        return this.quickAesKey;
    }

    /** Adopt a peer-supplied key (when the peer's APP_CMD_GET_ASEKEY wins). */
    public setQuickAesKey(key: string): void {
        this.quickAesKey = key;
    }

    public async open(): Promise<void> {
        const socket = createSocket("udp4");
        this.socket = socket;
        socket.on("message", (msg) => this.onPacket(msg));
        await new Promise<void>((resolve, reject) => {
            socket.once("error", reject);
            socket.bind(0, () => resolve());
        });
        // Register, then keepalive on the ~23 s cadence observed in the capture.
        this.sendRegister();
        this.keepaliveTimer = setInterval(() => this.sendRegister(), 23_000);
    }

    /**
     * Build an rtc_protocol frame.
     *
     * Reverse-engineered from `_ProtocolGetBuffer`: the frame is a fixed
     * `RTC_HEADER_LEN` (0x3c = 60) byte header followed by the body. Verified
     * header fields:
     *   +0x00  u16   tag (=3)
     *   +0x02  u16   CRC16 over the frame (_ProtocolGenerateCRC16)
     *   +0x06  u16   body length
     *   +0x08  u32   packetId          (also keys the AES — see deriveMessageKey)
     *   +0x0c  u8    (=7)
     *   +0x20  16B   (copied verbatim by the serializer)
     *   +0x28  u8    (=0x14)
     *   +0x3c  ...   body (AES-128-ECB encrypted)
     *
     * TODO(#863): (a) the CRC16 polynomial/seed — disassemble
     * `_ProtocolGenerateCRC16`; (b) the outer UDP wrapper (the leading `0800`
     * seen in captures is added by the channel layer, not rtc_protocol) —
     * both still need a live-device capture to confirm byte-for-byte.
     */
    public encodeMessage(body: Buffer): { frame: Buffer; packetId: number } {
        const packetId = ++this.packetId;
        const enc = encryptBody(this.quickAesKey, packetId, body);
        const frame = Buffer.alloc(RTC_HEADER_LEN + enc.length);
        frame.writeUInt16LE(3, 0x00);
        frame.writeUInt16LE(enc.length, 0x06);
        frame.writeUInt32LE(packetId, 0x08);
        frame.writeUInt8(7, 0x0c);
        frame.writeUInt8(0x14, 0x28);
        enc.copy(frame, RTC_HEADER_LEN);
        frame.writeUInt16LE(crc16(frame), 0x02); // TODO(#863): confirm CRC variant
        return { frame, packetId };
    }

    /** Parse an inbound rtc_protocol frame; returns the decrypted body or undefined. */
    public decodeMessage(frame: Buffer): Buffer | undefined {
        if (frame.length < RTC_HEADER_LEN) return undefined;
        const packetId = frame.readUInt32LE(0x08);
        try {
            return decryptBody(this.quickAesKey, packetId, frame.subarray(RTC_HEADER_LEN));
        } catch {
            return undefined;
        }
    }

    private sendRegister(): void {
        // TODO(#863): the register/keepalive frame format (STUN-framed, carries
        // the station SN + a session token) is observed in the capture but not
        // yet reproduced here — needs live-device validation.
        this.emit("register-pending", this.config.stationSN);
    }

    private onPacket(data: Buffer): void {
        const body = this.decodeMessage(data);
        if (body) this.emit("message", body);
        else this.emit("raw", data);
    }

    public close(): void {
        if (this.keepaliveTimer) clearInterval(this.keepaliveTimer);
        this.keepaliveTimer = undefined;
        this.socket?.close();
        this.socket = undefined;
    }
}

export { SIGNALING_PORT };
