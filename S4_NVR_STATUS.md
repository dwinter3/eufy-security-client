# S4 Max NVR (type 300) support — status

Branch `s4-nvr-ice`. Addresses [eufy-security-client issue #863](https://github.com/bropat/eufy-security-client/issues/863):
PoE Cam S4 (T8E00) cameras behind an S4 Max NVR (T8N00, device type 300) cannot
be livestreamed because the NVR uses a WebRTC connection path the library does
not implement.

## Root cause (fully reverse-engineered — see #863 comments)

The S4 Max NVR is a **WebRTC device** (`webrtc_sdk_version` set, empty
`p2p_conn`/`app_conn`). It connects via:
1. **PPCS localLookup** — UDP 32108 LAN discovery, then a P2P control session.
2. **Signaling** — SDP/ICE/TURN credentials exchanged *inside* that control session.
3. **TURN** — STUN `Allocate` to the station's `signaling_servers`.
4. **ICE** — STUN connectivity checks to host + relay candidates; media follows.

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

### Genuine unknowns — narrowed by the capture

The capture collapsed three vague unknowns into **one**: the **signaling exchange**.

- ~~PPCS rendezvous packet construction~~ — resolved: it's localLookup 32108.
- ~~ICE credential *derivation*~~ — resolved: they're not derived, they're
  *signaled* (per-session tokens).
- **Open:** the control-session messages that carry the SDP / ICE ufrag+pwd /
  TURN username+password. This is encrypted P2P control traffic — needs the
  decrypted control session (the `p2p-trace-*.log` traces, or live RE).
- **Open:** the post-connection media framing on the established ICE channel.

These two need the decrypted P2P control session — captures of a working session
are available from the device owner (see #863).
