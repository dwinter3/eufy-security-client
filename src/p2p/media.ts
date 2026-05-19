/**
 * Media-leg crypto for the eufy WebRTC transport (S4 Max NVR / type 300).
 * See issue #863 and S4_NVR_STATUS.md.
 *
 * Reverse-engineered from the eufy iOS app's `BC_WebRTC.framework`
 * (`ZXRTCManager`, `ZXRTCBaseVideoPlayer`):
 *
 *   - Once the ICE channel is up, video frames are encrypted with **AES-GCM**
 *     (`-setEnableMediaAesGcm:`, `-setMediaChannelAesKey:iv:`).
 *   - The GCM key is *not* shared directly — it is agreed via an **ECC key
 *     exchange**: each side publishes an ECC public key
 *     (`-getAccGcmPublicKeyPlay:` / `…Download:`, `zx_rtc_get_ecc_crypto`,
 *     `is_support_media_ecc_encrypt`) and derives a shared secret.
 *   - A `crypto_type` field selects the scheme (logged as
 *     `AnkeRTC setAesKey:%@ aes_iv:%@ crypto_type:%d`).
 *
 * Status: the AES-GCM frame primitives below are implemented and self-testable.
 * The ECC key-agreement (curve, KDF from the shared secret to the GCM key/IV)
 * and the exact `crypto_type` values still need a focused disassembly pass and
 * a live-device capture — see the TODOs.
 */
import { createCipheriv, createDecipheriv } from "crypto";

/** GCM parameters — standard sizes; key length still to be confirmed (TODO). */
export const GCM_IV_LEN = 12;
export const GCM_TAG_LEN = 16;

/** crypto_type values observed in the `AnkeRTC setAesKey … crypto_type:%d` log. */
export enum MediaCryptoType {
    NONE = 0,
    AES_GCM = 1, // TODO(#863): confirm the numeric value against BC_WebRTC
    AES_GCM_ECC = 2, // TODO(#863): confirm
}

export interface MediaKey {
    /** Negotiated AES key (16 or 32 bytes — see TODO). */
    key: Buffer;
    /** Base IV for the GCM nonce. */
    iv: Buffer;
    cryptoType: MediaCryptoType;
}

/**
 * Decrypt one media frame — AES-GCM. Ciphertext layout assumed `[ct || tag]`
 * with the 16-byte GCM tag appended (the common WebRTC-style framing).
 *
 * TODO(#863): confirm the per-frame nonce construction — eufy likely mixes a
 * frame counter into `key.iv`; pin this from `setMediaChannelAesKey:iv:` usage.
 */
export function decryptMediaFrame(mk: MediaKey, frame: Buffer, frameSeq = 0): Buffer {
    const algo = mk.key.length === 32 ? "aes-256-gcm" : "aes-128-gcm";
    const ct = frame.subarray(0, frame.length - GCM_TAG_LEN);
    const tag = frame.subarray(frame.length - GCM_TAG_LEN);
    const decipher = createDecipheriv(algo, mk.key, nonceFor(mk.iv, frameSeq));
    decipher.setAuthTag(tag);
    return Buffer.concat([decipher.update(ct), decipher.final()]);
}

/** Encrypt one media frame — AES-GCM; returns `[ct || tag]`. */
export function encryptMediaFrame(mk: MediaKey, plaintext: Buffer, frameSeq = 0): Buffer {
    const algo = mk.key.length === 32 ? "aes-256-gcm" : "aes-128-gcm";
    const cipher = createCipheriv(algo, mk.key, nonceFor(mk.iv, frameSeq));
    const ct = Buffer.concat([cipher.update(plaintext), cipher.final()]);
    return Buffer.concat([ct, cipher.getAuthTag()]);
}

/**
 * Build the 12-byte GCM nonce for a frame: base IV XOR the frame sequence in
 * the trailing bytes (RFC 8452 / SRTP-style). TODO(#863): confirm against the
 * app — this is the standard construction, not yet verified for eufy.
 */
function nonceFor(baseIv: Buffer, frameSeq: number): Buffer {
    const nonce = Buffer.alloc(GCM_IV_LEN);
    baseIv.copy(nonce, 0, 0, Math.min(baseIv.length, GCM_IV_LEN));
    const seq = Buffer.alloc(4);
    seq.writeUInt32BE(frameSeq >>> 0, 0);
    for (let i = 0; i < 4; i++) nonce[GCM_IV_LEN - 4 + i] ^= seq[i];
    return nonce;
}
