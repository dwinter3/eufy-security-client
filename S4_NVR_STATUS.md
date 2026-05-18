# S4 Max NVR (type 300) support — status

Branch `s4-nvr-ice`. Addresses [eufy-security-client issue #863](https://github.com/bropat/eufy-security-client/issues/863):
PoE Cam S4 (T8E00) cameras behind an S4 Max NVR (T8N00, device type 300) cannot
be livestreamed because the NVR uses a WebRTC connection path the library does
not implement.

## Root cause (fully reverse-engineered — see #863 comments)

The S4 Max NVR is a **WebRTC device** (`webrtc_sdk_version` set, empty
`p2p_conn`/`app_conn`). It connects via:
1. **PPCS rendezvous** — UDP 32100-32102 to eufy P2P servers (Throughtek `f1…`).
2. **TURN** — STUN `Allocate` to the station's `signaling_servers`.
3. **ICE** — STUN connectivity checks to host + relay candidates.
4. Media over the established channel.

The legacy `P2PClientProtocol` (localLookup → CAM_ID, port 32108) does not apply.

## Done in this branch

- `8213c2b` — register `DeviceType` 300 (NVR) + 301 (PoE Cam S4); `isStation`/`isCamera`.
- `8dedb42` — keep `signaling_servers` + `webrtc_sdk_version` on `RawStation`.
- `dca6a3e` — `src/p2p/ice.ts` — STUN/ICE/TURN message codec (self-tested).
- `b202811` — `src/p2p/iceagent.ts` — ICE agent: host candidates, connectivity checks.
- `bb26849` — `src/p2p/turn.ts` — TURN client: Allocate/Refresh, relay candidate.

All commits build (`tsc`). The STUN/ICE/TURN layer — the part the library entirely
lacked — is implemented as standards-based, tested modules.

## Remaining work (the real integration)

This is deep work in the existing P2P code, not new standalone modules:

1. **PPCS for type 300** — the library *already* has the PPCS message types and
   `buildLookupWithKeyPayload()`. Needed: route type-300 stations through the
   cloud-lookup variant on 32100-32102 with the `R`-prefixed DID, and surface the
   discovered candidates instead of failing them as "Unwanted device".
2. **Wire ICE+TURN into the connection** — feed PPCS-discovered + TURN-relay
   candidates to `IceAgent`; on `connected`, hand the socket to the data layer.
3. **Transport selection** — when `webrtc_sdk_version` is non-empty, use this
   path instead of `P2PClientProtocol`.
4. **Media** — carry `CMD_START_REALTIME_MEDIA` and the video over the ICE channel.

### Genuine unknowns (need a live-device dev loop)
- Exact PPCS rendezvous packet construction for the type-300 NVR / `R`-DID.
- The ICE credential derivation (ufrag / MESSAGE-INTEGRITY key source).
- The post-connection media framing.

These require iterative testing against a real S4 Max NVR — captures of a working
session are available from the device owner (see #863).
