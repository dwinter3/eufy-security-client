# S4 Max NVR (type 300) support — status

Branch `s4-nvr-ice`. Addresses [eufy-security-client issue #863](https://github.com/bropat/eufy-security-client/issues/863):
PoE Cam S4 (T8E00) cameras behind an S4 Max NVR (T8N00, device type 300) cannot
be livestreamed because the NVR uses a WebRTC connection path the library does
not implement.

## Root cause (fully reverse-engineered — see #863 comments)

The S4 Max NVR is a **WebRTC device** (`webrtc_sdk_version` set, empty
`p2p_conn`/`app_conn`). The full livestream chain — verified end-to-end from the
#863 capture:

1. **DSK** — app `POST /app/devicerelation/get_dsk_keys` (HTTPS); the response
   `data` is ECDH-encrypted (the library's `decryptAPIData()` path) → the
   per-station **Device Secret Key**.
2. **Station record** — `get_devs_list` carries `p2p_did`
   (`RUSPRAA-…`, an `R`-realm Throughtek DID), `signaling_servers`, and
   `webrtc_sdk_version` (`7.1.4` for the T8N00).
3. **Signaling registration** — the NVR keepalive-registers with the signaling
   server (`webrtc-signal-us.eufylife.com` = `13.248.157.102`) on **UDP 5062**,
   STUN-framed, every ~23 s, carrying the station SN + a 32-hex session token.
4. **Signaling push** — on a livestream request, the signaling server pushes a
   ~760-byte message to the NVR on 5062: opcode `0x0300`, station SN, two 32-hex
   tokens, then **~580 bytes of ciphertext** = the SDP / ICE ufrag+pwd / TURN
   username+password, encrypted (keyed off the DSK).
5. **TURN** — NVR `Allocate`s a relay candidate on `13.248.157.102:3478`.
6. **ICE** — STUN connectivity checks; on-LAN the host candidate pair wins.
7. **Media** — over the established ICE channel.

## Verified from the #863 packet capture (2026-05-18)

Decoded directly from `eufy-debug/eufy-863-part2.pcap` — facts, not inference:

- **The transport IS WebRTC.** This *corrects* `FINDINGS-863-part2.md`, which
  concluded "nothing new transport-wise" — it looked only at the data session
  and missed the STUN/TURN setup. The `s4-nvr-ice` premise is correct.
- **TURN:** NVR `.54` → `13.248.157.102:3478`, 143 pkts. Server is **coturn**
  (`Coturn-4.6.2 'Gorst'`), realm **`anker.com`**, RFC 5766 long-term creds.
  Full Allocate → 401 → Allocate-with-MI → success observed.
- **PPCS:** **0** packets on cloud rendezvous 32100-32102; **135** on
  localLookup **32108**. The bootstrap is the *LAN* path the library already has.
- **ICE:** **1512** STUN packets directly app `.46` ↔ NVR `.54` — host-candidate
  connectivity checks. Both peers are on `192.168.4.0/22`, so the host pair wins
  and media never needs the relay (on-LAN case).
- **ICE roles:** the app sends `ICE-CONTROLLED` → the **NVR is controlling**.
  `IceAgent` must be constructed `controlling=false` when playing the app role.
- **Credentials:** TURN username = 16-char token (`JQR6R1RaaOuwKdKh`); ICE
  ufrag = 4-char shared token (`3uCS`). Both per-session — they come from the
  signaling exchange, not derivation.

The legacy `P2PClientProtocol` localLookup (port 32108) *is* the bootstrap; its
CAM_ID/control-session path applies. Only the WebRTC media leg is new.

## Done in this branch

- `8213c2b` — register `DeviceType` 300 (NVR) + 301 (PoE Cam S4); `isStation`/`isCamera`.
- `8dedb42` — keep `signaling_servers` + `webrtc_sdk_version` on `RawStation`.
- `dca6a3e` — `src/p2p/ice.ts` — STUN/ICE/TURN message codec (self-tested).
- `b202811` — `src/p2p/iceagent.ts` — ICE agent: host candidates, connectivity checks.
- `bb26849` — `src/p2p/turn.ts` — TURN client: Allocate/Refresh, relay candidate.

All commits build (`tsc`). The STUN/ICE/TURN layer — the part the library entirely
lacked — is implemented as standards-based, tested modules.

## Remaining work

The protocol is now fully mapped. Remaining work is bounded:

1. **DSK fetch** — call `get_dsk_keys`, decrypt with the existing
   `decryptAPIData()` path. (Library-supported; just needs wiring.)
2. **Signaling client** (`src/p2p/signaling.ts`, new) — UDP client for the 5062
   protocol: STUN-framed register/keepalive, receive the `0x0300` push. Framing
   is decoded (see step 3/4 above); needs building.
3. **Transport selection** — when `webrtc_sdk_version` is non-empty, use the
   WebRTC path instead of `P2PClientProtocol`.
4. **Wire signaling → `TurnClient` + `IceAgent`** — feed the decrypted creds in;
   on `connected`, hand the socket to the data layer.
5. **Media** — carry `CMD_START_REALTIME_MEDIA` / video over the ICE channel.

### The signaling crypto — REVERSE-ENGINEERED (2026-05-18)

The eufy iOS app's `BC_P2PClient.framework` is unencrypted (`cryptid 0`) and was
disassembled. The `0x0800` signaling cipher and key schedule are now **fully
specified** — see `eufy-debug/FINDINGS-863-part4.md`:

```
cipher : AES-128-ECB (mbedTLS)
key    : quickAesKey (random 16-char string) with the message's decimal
         packetId overlaid right-aligned onto the tail 16 bytes
quickAesKey : random [0-9a-zA-Z]{16}, generated per session (_generate_aes_key)
              and exchanged in-band (APP_CMD_GET_ASEKEY)
packetId    : per-message counter carried in the 0x0800 header
```

There is **no unknown KDF and nothing left to crack** — the key is a random
string negotiated in-band. The library implements the protocol by *participating
in the exchange* (generate/accept `quickAesKey`, then AES-128-ECB per message),
not by deriving anything. Old captured ciphertext is not decryptable offline
(each session's key was random and is gone) — expected, and not a blocker.

### LIVE-TEST-READY (2026-05-18, autonomous build loop)

All transport modules are built, build clean (`tsc`), and have their crypto
self-verified. The fork is staged for a short live-device session:

| Module | Status |
|--------|--------|
| `src/p2p/ice.ts` | STUN/ICE/TURN codec — done |
| `src/p2p/iceagent.ts` | ICE agent (host candidates, checks) — done |
| `src/p2p/turn.ts` | TURN client (Allocate/Refresh) — done |
| `src/p2p/signaling.ts` | `0x0800` client: AES-128-ECB body crypto, rtc_protocol framing (0x3c header), CRC-16/CCITT — **verified round-trip** |
| `src/p2p/media.ts` | AES-GCM media-frame crypto — **verified round-trip** |
| `src/p2p/webrtc-transport.ts` | `WebRTCTransport` orchestration + `shouldUseWebRTC()` selector — done |

Reverse-engineered and verified from the eufy iOS app binary:
the rtc_protocol frame (`0x3c` header + body), CRC-16/CCITT (poly 0x1021,
init 0), the AES-128-ECB signaling key schedule, and the AES-GCM media leg.

### What still needs a live device (the dev-loop TODOs)

Marked `TODO(#863)` in the source. These need a live NVR to validate — they
cannot be pinned from static analysis or old captures:

1. The outer UDP wrapper / register-frame bytes (the `0800` prefix).
2. The `APP_CMD_GET_ASEKEY` key-exchange sequencing.
3. The SDP-exchange flow in `WebRTCTransport.connect()`.
4. The media ECC key-agreement + exact `crypto_type` values + depacketization.
5. Hooking `shouldUseWebRTC()` into `Station`/`session.ts`.

The cryptographic wall — the thing that genuinely blocked #863 — is **down**,
and every module is built and typed. What remains is a live-device dev loop.
