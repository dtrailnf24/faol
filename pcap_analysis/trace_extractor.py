"""
trace_extractor.py
==================
Parse a LoRaWAN PCAP file (LoRaTap v1 encapsulation) using tshark and
extract a structured session history per device for Scyther scenario
generation and anomaly detection.

Usage:
    python trace_extractor.py <pcap_file> [output.json]

Output (observed_sessions.json):
    {
      "devices": {
        "<DevEUI>": {
          "join_attempts": [{"frame": int, "devnonce": str, "has_response": bool}],
          "data_sessions": [{"devaddr": str, "fcnt_sequence": [...], "anomaly": str|null}],
          "uses_default_key": bool
        }
      },
      "anomalies": [
        {"type": str, "frame": int, "deveui": str, ...}
      ],
      "stats": {"total_frames": int, "join_req": int, "join_accept": int, "data": int}
    }

Requirements:
    - tshark (brew install wireshark, or installed at
              /Applications/Wireshark.app/Contents/MacOS/tshark)
    - Python 3.8+

tshark LoRaWAN field names (LoRaTap dissector, Wireshark 4.x):
    lorawan.mhdr.ftype       MType (0=JoinReq, 1=JoinAccept, 2=UnconfUp, 3=UnconfDown,
                                    4=ConfUp, 5=ConfDown)
    lorawan.join_request.joineui   (JoinEUI / AppEUI)
    lorawan.join_request.deveui
    lorawan.join_request.devnonce  (decimal integer)
    lorawan.join_accept.joinnonce  (v1.1; JoinAccept encrypted without keys — usually absent)
    lorawan.fhdr.devaddr
    lorawan.fhdr.fcnt
    lorawan.frmpayload             (raw MAC payload — fallback for malformed JoinReq frames)
"""

import json
import shutil
import subprocess
import sys
import os
from collections import defaultdict

# Known default AppKeys (Povalac et al., Sensors 2023, doi:10.3390/s23177333)
# Any device using these keys is trivially compromised — session keys derivable by anyone
DEFAULT_APPKEYS = {
    "Semtech":   "2b7e151628aed2a6abf7158809cf4f3c",  # Semtech reference default
    "Milesight": "5572404c696e6b4c6f52613230313823",  # Milesight IoT factory default
}
# Backward-compat alias used by scenario_builder
DEFAULT_APPKEY = DEFAULT_APPKEYS["Semtech"]

# AES-CMAC for JoinReq MIC verification — requires cryptography library
try:
    from cryptography.hazmat.primitives.cmac import CMAC
    from cryptography.hazmat.primitives.ciphers import algorithms
    _CMAC_AVAILABLE = True
except ImportError:
    _CMAC_AVAILABLE = False


def _check_default_key(payload_hex: str) -> str | None:
    """Return vendor name if this JoinReq's MIC verifies with a known default AppKey.

    LoRaWAN JoinReq MIC = AES128_CMAC(AppKey, MHDR | frmpayload[0:18])[:4]
    frmpayload layout: JoinEUI(8) | DevEUI(8) | DevNonce(2) | MIC(4) = 22 bytes
    """
    if not _CMAC_AVAILABLE or len(payload_hex) < 44:
        return None
    try:
        msg = bytes.fromhex("00") + bytes.fromhex(payload_hex[:36])
        received_mic = bytes.fromhex(payload_hex[36:44])
        for vendor, key_hex in DEFAULT_APPKEYS.items():
            c = CMAC(algorithms.AES(bytes.fromhex(key_hex)))
            c.update(msg)
            if c.finalize()[:4] == received_mic:
                return vendor
    except Exception:
        pass
    return None

# LoRaWAN MType values
MTYPE_JOIN_REQ    = "0"
MTYPE_JOIN_ACCEPT = "1"
MTYPE_UNCONF_UP   = "2"
MTYPE_UNCONF_DOWN = "3"
MTYPE_CONF_UP     = "4"
MTYPE_CONF_DOWN   = "5"

DATA_MTYPES = {MTYPE_UNCONF_UP, MTYPE_UNCONF_DOWN, MTYPE_CONF_UP, MTYPE_CONF_DOWN}

TSHARK_FIELDS = [
    "frame.number",
    "lorawan.mhdr.ftype",            # correct field name in Wireshark 4.x
    "lorawan.join_request.joineui",  # JoinEUI (replaces AppEUI field name)
    "lorawan.join_request.deveui",
    "lorawan.join_request.devnonce",
    "lorawan.join_accept.joinnonce",
    "lorawan.fhdr.devaddr",
    "lorawan.fhdr.fcnt",
    "lorawan.frmpayload",            # raw payload — used when JoinReq fields are absent
]


def find_tshark() -> str:
    """Locate the tshark binary (PATH or macOS Wireshark app bundle)."""
    path = shutil.which("tshark")
    if path:
        return path
    macos_bundle = "/Applications/Wireshark.app/Contents/MacOS/tshark"
    if os.path.exists(macos_bundle):
        return macos_bundle
    print("[ERROR] tshark not found. Install via 'brew install wireshark' "
          "or place Wireshark.app in /Applications.", file=sys.stderr)
    sys.exit(1)


def run_tshark(pcap_path: str) -> list[dict]:
    """Run tshark on the PCAP and return parsed JSON frames."""
    tshark = find_tshark()
    cmd = [tshark, "-r", pcap_path, "-T", "json"]
    for field in TSHARK_FIELDS:
        cmd += ["-e", field]

    result = subprocess.run(cmd, capture_output=True, text=True)
    if result.returncode != 0:
        print(f"[ERROR] tshark failed: {result.stderr[:500]}", file=sys.stderr)
        sys.exit(1)

    try:
        return json.loads(result.stdout)
    except json.JSONDecodeError as e:
        print(f"[ERROR] Failed to parse tshark JSON: {e}", file=sys.stderr)
        sys.exit(1)


def get_field(frame: dict, field: str) -> str | None:
    """Extract a tshark field value from a parsed frame."""
    layers = frame.get("_source", {}).get("layers", {})
    val = layers.get(field)
    if val is None:
        return None
    if isinstance(val, list):
        val = val[0]
    return str(val).strip().lower().replace(":", "")


def parse_joinreq_payload(payload_hex: str) -> tuple[str | None, str | None, str | None]:
    """
    Parse JoinEUI, DevEUI, DevNonce from a raw JoinReq frmpayload hex string.

    JoinReq MAC payload layout (after MHDR, LoRaWAN 1.0/1.1):
        Bytes  0-7:  JoinEUI/AppEUI  (8 bytes, LSByte-first on wire)
        Bytes  8-15: DevEUI          (8 bytes, LSByte-first on wire)
        Bytes 16-17: DevNonce        (2 bytes, little-endian)
        Bytes 18-21: MIC             (4 bytes — not parsed here)

    Used as fallback when tshark marks the frame malformed and does not
    populate lorawan.join_request.* fields (e.g. non-zero RFU bits in MHDR).

    Returns (joineui, deveui, devnonce_hex) — all lowercase hex strings,
    EUIs in standard big-endian display order.  Returns (None, None, None)
    if the payload is too short.
    """
    if len(payload_hex) < 44:   # 22 bytes minimum
        return None, None, None
    try:
        joineui = bytes.fromhex(payload_hex[0:16])[::-1].hex()
        deveui  = bytes.fromhex(payload_hex[16:32])[::-1].hex()
        devnonce_int = int.from_bytes(bytes.fromhex(payload_hex[32:36]), "little")
        devnonce = format(devnonce_int, "04x")
    except ValueError:
        return None, None, None
    return joineui, deveui, devnonce


def kld_jamming_score(devnonces: list[str]) -> float:
    """
    Apply KLD-based jamming detection from Danish et al. (NIDS paper).
    Computes divergence of DevNonce distribution from expected uniform distribution.
    High KLD (> ~2.0) indicates possible jamming causing DevNonce to freeze/repeat.
    Returns the KLD score (0 = uniform, higher = more suspicious).
    """
    if len(devnonces) < 4:
        return 0.0

    # Convert hex DevNonce strings to integers
    values = []
    for dn in devnonces:
        try:
            values.append(int(dn, 16))
        except ValueError:
            continue

    if not values:
        return 0.0

    # Count repetitions — if DevNonce is frozen (jammer forcing same value),
    # distribution will be highly concentrated on one value
    from collections import Counter
    counts = Counter(values)
    n = len(values)

    # Compute entropy (higher = more uniform = normal)
    import math
    entropy = 0.0
    for c in counts.values():
        p = c / n
        if p > 0:
            entropy -= p * math.log2(p)

    max_entropy = math.log2(n) if n > 1 else 1.0
    kld_approx = max(0.0, max_entropy - entropy)  # deviation from uniform
    return round(kld_approx, 4)


def analyze_fcnt(fcnt_sequence: list[int]) -> str | None:
    """Detect anomalies in an FCnt sequence."""
    if len(fcnt_sequence) < 2:
        return None

    for i in range(1, len(fcnt_sequence)):
        if fcnt_sequence[i] < fcnt_sequence[i - 1]:
            return "fcnt_decrease"  # potential replay attack
        if fcnt_sequence[i] == fcnt_sequence[i - 1]:
            return "fcnt_repeat"    # duplicate / replay

    return None


def extract_sessions(pcap_path: str) -> dict:
    """Main extraction logic."""
    print(f"[*] Running tshark on {pcap_path} ...")
    raw_frames = run_tshark(pcap_path)
    print(f"[*] Got {len(raw_frames)} total frames from tshark")

    # Per-device tracking
    devices = defaultdict(lambda: {
        "join_attempts": [],
        "data_sessions": [],
        "uses_default_key": False,
    })

    anomalies = []
    stats = {"total_frames": 0, "join_req": 0, "join_accept": 0, "data": 0, "other": 0}

    # Track join context: map DevNonce -> frame# for reply matching
    pending_joins = {}   # devnonce -> {frame, deveui}
    seen_devnonces = defaultdict(set)  # deveui -> set of devnonces seen

    # Track data sessions: devaddr -> list of fcnt values
    data_sessions = defaultdict(list)
    data_frame_map = defaultdict(list)  # devaddr -> [(frame#, fcnt)]

    for frame in raw_frames:
        stats["total_frames"] += 1
        frame_num = get_field(frame, "frame.number")
        mtype = get_field(frame, "lorawan.mhdr.ftype")

        if mtype is None:
            stats["other"] += 1
            continue

        # ── JOIN REQUEST ────────────────────────────────────────────────
        if mtype == MTYPE_JOIN_REQ:
            stats["join_req"] += 1
            deveui   = get_field(frame, "lorawan.join_request.deveui")
            joineui  = get_field(frame, "lorawan.join_request.joineui")
            devnonce_raw = get_field(frame, "lorawan.join_request.devnonce")

            # Wireshark 4.x returns devnonce as a decimal integer string;
            # convert to 4-char hex for consistent replay detection.
            if devnonce_raw is not None:
                try:
                    devnonce = format(int(devnonce_raw), "04x")
                except ValueError:
                    devnonce = devnonce_raw
            else:
                devnonce = None

            # Fallback: if the dissector marked the frame malformed and did not
            # populate join fields, parse AppEUI/DevEUI/DevNonce from raw payload.
            if deveui is None or devnonce is None:
                payload = get_field(frame, "lorawan.frmpayload")
                if payload:
                    fb_joineui, fb_deveui, fb_devnonce = parse_joinreq_payload(payload)
                    joineui  = joineui  or fb_joineui
                    deveui   = deveui   or fb_deveui
                    devnonce = devnonce or fb_devnonce

            deveui   = deveui   or "unknown"
            joineui  = joineui  or "unknown"
            devnonce = devnonce or "0000"

            attempt = {
                "frame": int(frame_num),
                "joineui": joineui,
                "devnonce": devnonce,
                "has_response": False,  # updated when JoinAccept seen
            }
            devices[deveui]["join_attempts"].append(attempt)

            # Replay detection: same DevNonce from same device
            if devnonce in seen_devnonces[deveui]:
                anomalies.append({
                    "type": "DevNonce_Replay",
                    "frame": int(frame_num),
                    "deveui": deveui,
                    "devnonce": devnonce,
                    "detail": "DevNonce already seen for this device — join replay attack",
                })
            seen_devnonces[deveui].add(devnonce)
            pending_joins[devnonce] = {"frame": int(frame_num), "deveui": deveui}

            # Default key detection: verify JoinReq MIC against known default AppKeys
            if not devices[deveui]["uses_default_key"]:
                raw_payload = get_field(frame, "lorawan.frmpayload")
                if raw_payload:
                    vendor = _check_default_key(raw_payload)
                    if vendor:
                        devices[deveui]["uses_default_key"] = True
                        devices[deveui]["detected_appkey"] = DEFAULT_APPKEYS[vendor]
                        anomalies.append({
                            "type": "uses_default_key",
                            "frame": int(frame_num),
                            "deveui": deveui,
                            "vendor": vendor,
                            "detail": f"JoinReq MIC verified with {vendor} default AppKey — session keys are derivable",
                        })

        # ── JOIN ACCEPT ──────────────────────────────────────────────────
        elif mtype == MTYPE_JOIN_ACCEPT:
            stats["join_accept"] += 1
            # JoinAccept is AES-encrypted; without keys tshark cannot decrypt it
            # and lorawan.join_accept.joinnonce is absent.  We still match the
            # JoinAccept to its JoinReq by DevNonce proximity (oldest pending first).
            joinnonce = get_field(frame, "lorawan.join_accept.joinnonce")

            # Try to match to a pending JoinReq (oldest first)
            matched = False
            for dn, ctx in list(pending_joins.items()):
                deveui = ctx["deveui"]
                for attempt in devices[deveui]["join_attempts"]:
                    if attempt["devnonce"] == dn and not attempt["has_response"]:
                        attempt["has_response"] = True
                        if joinnonce is not None:
                            attempt["joinnonce"] = joinnonce
                        matched = True
                        del pending_joins[dn]
                        break
                if matched:
                    break

            if not matched:
                # JoinAccept with no matching JoinReq — possible rogue NS
                anomalies.append({
                    "type": "Unsolicited_JoinAccept",
                    "frame": int(frame_num),
                    "detail": "JoinAccept with no matching JoinReq — possible rogue NS or MITM",
                })

        # ── DATA FRAMES (uplink/downlink) ────────────────────────────────
        elif mtype in DATA_MTYPES:
            stats["data"] += 1
            devaddr = get_field(frame, "lorawan.fhdr.devaddr") or "unknown"
            fcnt_str = get_field(frame, "lorawan.fhdr.fcnt")
            if fcnt_str is not None:
                try:
                    fcnt = int(fcnt_str, 16) if fcnt_str.startswith("0x") else int(fcnt_str)
                except ValueError:
                    fcnt = None
                if fcnt is not None:
                    data_sessions[devaddr].append(fcnt)
                    data_frame_map[devaddr].append((int(frame_num), fcnt))

        else:
            stats["other"] += 1

    # ── POST-PROCESS DATA SESSIONS ────────────────────────────────────────
    for devaddr, fcnt_seq in data_sessions.items():
        anomaly = analyze_fcnt(fcnt_seq)
        session_entry = {
            "devaddr": devaddr,
            "fcnt_sequence": fcnt_seq,
            "frame_map": data_frame_map[devaddr],
            "anomaly": anomaly,
        }
        # Attach to device if we know the devaddr -> deveui mapping
        # (for OTAA devices this is available from join; for ABP it's pre-configured)
        # For now, store under a synthetic key
        devices[f"devaddr:{devaddr}"]["data_sessions"].append(session_entry)
        if anomaly:
            frames_with_anomaly = [
                f for f, c in data_frame_map[devaddr]
                if c < (data_frame_map[devaddr][data_frame_map[devaddr].index((f, c)) - 1][1]
                        if data_frame_map[devaddr].index((f, c)) > 0 else c + 1)
            ]
            anomalies.append({
                "type": f"FCnt_{anomaly}",
                "devaddr": devaddr,
                "detail": f"FCnt {anomaly.replace('_', ' ')} detected — data frame replay indicator",
                "fcnt_sequence": fcnt_seq[:20],  # first 20 for brevity
            })

    # ── JAMMING DETECTION via KLD ─────────────────────────────────────────
    for deveui, device in devices.items():
        if deveui.startswith("devaddr:"):
            continue
        devnonces = [a["devnonce"] for a in device["join_attempts"]]
        kld = kld_jamming_score(devnonces)
        device["devnonce_kld"] = kld
        if kld > 2.0 and len(devnonces) >= 4:
            anomalies.append({
                "type": "Possible_Jamming",
                "deveui": deveui,
                "kld_score": kld,
                "detail": f"DevNonce distribution divergence = {kld} (>2.0 threshold) — possible jamming",
            })

    # ── UNANSWERED JOIN REQUESTS ──────────────────────────────────────────
    for devnonce, ctx in pending_joins.items():
        # These JoinReqs got no JoinAccept — could be normal (NS rejected) or
        # could indicate the NS received the join but the JoinAccept was jammed
        pass  # Not flagged as anomaly by default — too many false positives

    result = {
        "pcap": os.path.basename(pcap_path),
        "devices": {k: dict(v) for k, v in devices.items()},
        "anomalies": anomalies,
        "stats": stats,
    }
    return result


def main():
    if len(sys.argv) < 2:
        print("Usage: python trace_extractor.py <pcap_file> [output.json]")
        sys.exit(1)

    pcap_path = sys.argv[1]
    if not os.path.exists(pcap_path):
        print(f"[ERROR] File not found: {pcap_path}", file=sys.stderr)
        sys.exit(1)

    output_path = sys.argv[2] if len(sys.argv) > 2 else "observed_sessions.json"

    sessions = extract_sessions(pcap_path)

    with open(output_path, "w") as f:
        json.dump(sessions, f, indent=2)

    print(f"\n[+] Results written to {output_path}")
    print(f"    Frames:      {sessions['stats']['total_frames']}")
    print(f"    JoinReq:     {sessions['stats']['join_req']}")
    print(f"    JoinAccept:  {sessions['stats']['join_accept']}")
    print(f"    Data frames: {sessions['stats']['data']}")
    print(f"    Anomalies:   {len(sessions['anomalies'])}")

    if sessions["anomalies"]:
        print("\n[!] Anomalies detected:")
        for a in sessions["anomalies"]:
            print(f"    [{a['type']}] {a.get('detail', '')}")


if __name__ == "__main__":
    main()
