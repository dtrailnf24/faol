#!/usr/bin/env python3
"""
semtech_extractor.py — Parse Semtech UDP/1700 PCAPs into sessions JSON.

LWN-Simulator (and many real gateway captures) use the Semtech packet
forwarder protocol on UDP port 1700.  tshark's LoRaWAN dissector cannot
parse these frames directly (it requires LoRaTap v1 encapsulation).

This script:
  1. Reads the PCAP with tshark, extracting raw UDP/1700 payloads.
  2. Parses the Semtech binary protocol header.
  3. Extracts the embedded LoRaWAN PHY payloads (base64 in JSON).
  4. Manually parses JoinReq / Data frames.
  5. Runs the same anomaly detection as trace_extractor.py.
  6. Outputs the same _sessions.json schema, ready for scenario_builder.py.

Usage:
  python3 semtech_extractor.py <input.pcap> <output_sessions.json>

Example (LWN-Simulator capture):
  python3 semtech_extractor.py sim_capture.pcap data/output/sim_sessions.json

Example (joinacceptreplay.pcap — gateway-level JoinAccept replay):
  python3 semtech_extractor.py joinacceptreplay.pcap data/output/jar_sessions.json

Semtech packet forwarder protocol reference:
  https://github.com/Lora-net/packet_forwarder/blob/master/PROTOCOL.TXT
"""

import sys
import os
import json
import base64
import struct
import subprocess
from collections import defaultdict

# ── Semtech protocol identifiers ─────────────────────────────────────────────
PUSH_DATA = 0x00   # gateway → NS: contains rxpk (uplinks)
PUSH_ACK  = 0x01
PULL_DATA = 0x02   # gateway → NS: keepalive
PULL_RESP = 0x03   # NS → gateway: downlink (JoinAccept etc.)
PULL_ACK  = 0x04
TX_ACK    = 0x05

# ── LoRaWAN MType values (bits 7-5 of MHDR) ──────────────────────────────────
MTYPE_JOIN_REQ     = 0b000
MTYPE_JOIN_ACCEPT  = 0b001
MTYPE_UNCNF_UP     = 0b010
MTYPE_UNCNF_DOWN   = 0b011
MTYPE_CNF_UP       = 0b100
MTYPE_CNF_DOWN     = 0b101

# Known default AppKeys (Povalac et al., Sensors 2023)
DEFAULT_APPKEYS = {
    "Semtech":   bytes.fromhex("2b7e151628aed2a6abf7158809cf4f3c"),
    "Milesight": bytes.fromhex("5572404c696e6b4c6f52613230313823"),
}

try:
    from cryptography.hazmat.primitives.cmac import CMAC
    from cryptography.hazmat.primitives.ciphers import algorithms
    _CMAC_AVAILABLE = True
except ImportError:
    _CMAC_AVAILABLE = False


def _check_default_key_phy(phy: bytes) -> str | None:
    """Return vendor name if this JoinReq's MIC matches a known default AppKey.
    phy is the full raw LoRaWAN PHY frame (MHDR at byte 0).
    JoinReq: MHDR(1)+AppEUI(8)+DevEUI(8)+DevNonce(2)+MIC(4) = 23 bytes.
    MIC = AES128_CMAC(AppKey, phy[0:19])[:4]
    """
    if not _CMAC_AVAILABLE or len(phy) < 23:
        return None
    try:
        msg = phy[0:19]
        received_mic = phy[19:23]
        for vendor, key in DEFAULT_APPKEYS.items():
            c = CMAC(algorithms.AES(key))
            c.update(msg)
            if c.finalize()[:4] == received_mic:
                return vendor
    except Exception:
        pass
    return None

TSHARK = (
    os.environ.get("TSHARK")
    or "/Applications/Wireshark.app/Contents/MacOS/tshark"
)


def run_tshark(pcap: str) -> list[dict]:
    """Extract all UDP/1700 payloads from a PCAP via tshark.

    Returns a list of dicts: {"frame": int, "hex_payload": str}.
    """
    cmd = [
        TSHARK, "-r", pcap,
        "-Y", "udp.port == 1700",
        "-T", "fields",
        "-e", "frame.number",
        "-e", "udp.payload",
    ]
    result = subprocess.run(cmd, capture_output=True, text=True)
    packets = []
    for line in result.stdout.splitlines():
        parts = line.strip().split("\t")
        if len(parts) == 2 and parts[1]:
            packets.append({"frame": int(parts[0]), "hex_payload": parts[1]})
    return packets


def parse_semtech(hex_payload: str) -> list[dict]:
    """Parse one Semtech UDP/1700 packet.

    Returns a list of LoRaWAN PHY frames found (may be empty or multiple).
    Each item: {"direction": "up"|"down", "phy_bytes": bytes, "frame_no": int}
    """
    raw = bytes.fromhex(hex_payload)
    if len(raw) < 4:
        return []

    version, token_hi, token_lo, identifier = raw[0], raw[1], raw[2], raw[3]
    if version != 0x02:
        return []

    results = []

    if identifier == PUSH_DATA:
        # Bytes 4-11: Gateway EUI, then JSON payload
        if len(raw) < 12:
            return []
        json_bytes = raw[12:]
        try:
            obj = json.loads(json_bytes.decode("utf-8", errors="replace"))
        except json.JSONDecodeError:
            return []
        for rxpk in obj.get("rxpk", []):
            data_b64 = rxpk.get("data", "")
            if data_b64:
                try:
                    phy = base64.b64decode(data_b64)
                    results.append({"direction": "up", "phy_bytes": phy})
                except Exception:
                    pass

    elif identifier == PULL_RESP:
        # Bytes 4+: JSON payload (txpk downlink)
        json_bytes = raw[4:]
        try:
            obj = json.loads(json_bytes.decode("utf-8", errors="replace"))
        except json.JSONDecodeError:
            return []
        txpk = obj.get("txpk", {})
        data_b64 = txpk.get("data", "")
        if data_b64:
            try:
                phy = base64.b64decode(data_b64)
                results.append({"direction": "down", "phy_bytes": phy})
            except Exception:
                pass

    return results


def parse_lorawan_phy(phy: bytes) -> dict | None:
    """Parse a LoRaWAN PHY payload.

    Returns a dict with parsed fields, or None if unrecognised.
    """
    if len(phy) < 1:
        return None

    mhdr = phy[0]
    mtype = (mhdr >> 5) & 0x07

    if mtype == MTYPE_JOIN_REQ:
        # MHDR(1) + AppEUI(8LE) + DevEUI(8LE) + DevNonce(2LE) + MIC(4) = 23 bytes
        if len(phy) < 23:
            return None
        app_eui = phy[1:9][::-1]          # reverse byte order (LSB → MSB)
        dev_eui = phy[9:17][::-1]
        dev_nonce = struct.unpack_from("<H", phy, 17)[0]
        mic = phy[19:23]
        return {
            "mtype": "JoinReq",
            "appeui": app_eui.hex(),
            "deveui": dev_eui.hex(),
            "devnonce": f"{dev_nonce:04x}",
            "mic": mic.hex(),
        }

    elif mtype == MTYPE_JOIN_ACCEPT:
        # Payload is AES-ECB encrypted with AppKey — we cannot decrypt without the key.
        # Record size only; mark as JoinAccept.
        return {
            "mtype": "JoinAccept",
            "size": len(phy),
        }

    elif mtype in (MTYPE_UNCNF_UP, MTYPE_CNF_UP):
        # MHDR(1) + DevAddr(4LE) + FCtrl(1) + FCnt(2LE) + FOpts(0-15B) + ...
        if len(phy) < 8:
            return None
        dev_addr = struct.unpack_from("<I", phy, 1)[0]
        fctrl = phy[5]
        fopts_len = fctrl & 0x0F
        fcnt = struct.unpack_from("<H", phy, 6)[0]
        return {
            "mtype": "DataUp",
            "devaddr": f"0x{dev_addr:08x}",
            "fcnt": fcnt,
            "confirmed": mtype == MTYPE_CNF_UP,
        }

    elif mtype in (MTYPE_UNCNF_DOWN, MTYPE_CNF_DOWN):
        if len(phy) < 8:
            return None
        dev_addr = struct.unpack_from("<I", phy, 1)[0]
        fcnt = struct.unpack_from("<H", phy, 6)[0]
        return {
            "mtype": "DataDown",
            "devaddr": f"0x{dev_addr:08x}",
            "fcnt": fcnt,
        }

    return None


def detect_anomalies(frames: list[dict]) -> tuple[dict, list[dict]]:
    """Run the same anomaly detection as trace_extractor.py.

    Args:
        frames: list of {"frame_no": int, "direction": str, "parsed": dict}

    Returns:
        (devices, anomalies) matching the sessions JSON schema.
    """
    devices: dict = {}                          # deveui → {...}
    anomalies: list[dict] = []
    seen_devnonces: dict = defaultdict(set)     # deveui → set of devnonces seen
    fcnt_map: dict = defaultdict(list)          # devaddr → [fcnt, ...]
    pending_join_reqs: set = set()              # deveuiseen with JoinReq, awaiting Accept
    joinaccept_frames: list = []               # frames that are JoinAccepts

    for item in frames:
        fn = item["frame_no"]
        p = item["parsed"]
        direction = item["direction"]

        if p["mtype"] == "JoinReq":
            deveui = p["deveui"]
            devnonce = p["devnonce"]
            raw_phy = item.get("phy_bytes", b"")
            if deveui not in devices:
                devices[deveui] = {
                    "join_attempts": [],
                    "data_sessions": [],
                    "uses_default_key": False,
                    "devnonce_kld": 0.0,
                }
            devices[deveui]["join_attempts"].append({
                "frame": fn,
                "joineui": p["appeui"],
                "devnonce": devnonce,
                "has_response": False,
            })
            pending_join_reqs.add(deveui)

            # DevNonce replay detection
            if devnonce in seen_devnonces[deveui]:
                anomalies.append({
                    "type": "DevNonce_Replay",
                    "frame": fn,
                    "deveui": deveui,
                    "devnonce": devnonce,
                    "detail": "DevNonce already seen for this device — join replay attack",
                })
            seen_devnonces[deveui].add(devnonce)

            # Default key detection via MIC verification
            if not devices[deveui]["uses_default_key"] and raw_phy:
                vendor = _check_default_key_phy(raw_phy)
                if vendor:
                    devices[deveui]["uses_default_key"] = True
                    devices[deveui]["detected_appkey"] = DEFAULT_APPKEYS[vendor].hex()
                    anomalies.append({
                        "type": "uses_default_key",
                        "frame": fn,
                        "deveui": deveui,
                        "vendor": vendor,
                        "detail": f"JoinReq MIC verified with {vendor} default AppKey — session keys are derivable",
                    })

        elif p["mtype"] == "JoinAccept":
            joinaccept_frames.append(fn)
            # Match this JoinAccept to exactly ONE pending JoinReq (FIFO).
            # If no pending JoinReq exists, this JoinAccept is unsolicited.
            if pending_join_reqs:
                deveui = next(iter(pending_join_reqs))
                if devices[deveui]["join_attempts"]:
                    devices[deveui]["join_attempts"][-1]["has_response"] = True
                pending_join_reqs.discard(deveui)
            else:
                anomalies.append({
                    "type": "Unsolicited_JoinAccept",
                    "frame": fn,
                    "detail": "JoinAccept with no matching JoinReq — possible rogue NS or MITM",
                })

        elif p["mtype"] in ("DataUp", "DataDown") and direction == "up":
            devaddr = p["devaddr"]
            fcnt = p["fcnt"]
            key = devaddr
            key_id = f"devaddr:{devaddr}"

            # Ensure device entry exists for data-only devices
            if key_id not in devices:
                devices[key_id] = {
                    "join_attempts": [],
                    "data_sessions": [],
                    "uses_default_key": False,
                    "devnonce_kld": 0.0,
                }

            fcnt_map[key].append((fn, fcnt))

            # Update or create data session
            dev_sessions = devices[key_id]["data_sessions"]
            if not dev_sessions:
                dev_sessions.append({
                    "devaddr": devaddr,
                    "fcnt_sequence": [],
                    "frame_map": [],
                    "anomaly": None,
                })
            session = dev_sessions[-1]
            session["fcnt_sequence"].append(fcnt)
            session["frame_map"].append([fn, fcnt])

    # Unsolicited JoinAccept detection is now handled inline (per-JoinAccept).

    # FCnt anomaly detection (per-device)
    for devaddr, seq in fcnt_map.items():
        flist = [fcnt for _, fcnt in seq]
        key_id = f"devaddr:{devaddr}"

        # Detect decrease (rollback / replay)
        for i in range(1, len(flist)):
            if flist[i] < flist[i - 1]:
                anomalies.append({
                    "type": "FCnt_fcnt_decrease",
                    "devaddr": devaddr,
                    "detail": "FCnt decrease detected — data frame replay indicator",
                    "fcnt_sequence": flist[:20],
                })
                if key_id in devices:
                    for s in devices[key_id]["data_sessions"]:
                        if s["devaddr"] == devaddr:
                            s["anomaly"] = "fcnt_decrease"
                break

        # Detect repeat
        seen_fcnts: set = set()
        for fcnt in flist:
            if fcnt in seen_fcnts:
                anomalies.append({
                    "type": "FCnt_fcnt_repeat",
                    "devaddr": devaddr,
                    "detail": f"FCnt {fcnt} repeated — data frame replay",
                    "fcnt_sequence": flist[:20],
                })
                if key_id in devices:
                    for s in devices[key_id]["data_sessions"]:
                        if s["devaddr"] == devaddr and s["anomaly"] is None:
                            s["anomaly"] = "fcnt_repeat"
                break
            seen_fcnts.add(fcnt)

    return devices, anomalies


def extract(pcap: str, output: str) -> None:
    """Main extraction pipeline."""
    print(f"[semtech_extractor] Reading {pcap}")

    raw_packets = run_tshark(pcap)
    if not raw_packets:
        print("[semtech_extractor] No UDP/1700 packets found. "
              "Is this a Semtech gateway capture?")

    # Parse all Semtech packets → LoRaWAN PHY frames
    all_frames: list[dict] = []
    total_semtech = 0
    for pkt in raw_packets:
        phy_frames = parse_semtech(pkt["hex_payload"])
        total_semtech += len(phy_frames)
        for frame in phy_frames:
            parsed = parse_lorawan_phy(frame["phy_bytes"])
            if parsed:
                all_frames.append({
                    "frame_no": pkt["frame"],
                    "phy_bytes": frame["phy_bytes"],
                    "direction": frame["direction"],
                    "parsed": parsed,
                })

    # Count frame types
    join_req_count    = sum(1 for f in all_frames if f["parsed"]["mtype"] == "JoinReq")
    join_accept_count = sum(1 for f in all_frames if f["parsed"]["mtype"] == "JoinAccept")
    data_up_count     = sum(1 for f in all_frames if f["parsed"]["mtype"] == "DataUp")
    data_down_count   = sum(1 for f in all_frames if f["parsed"]["mtype"] == "DataDown")

    print(f"  UDP/1700 packets : {len(raw_packets)}")
    print(f"  LoRaWAN PHY frames found : {total_semtech}")
    print(f"  JoinReq={join_req_count}  JoinAccept={join_accept_count}  "
          f"DataUp={data_up_count}  DataDown={data_down_count}")

    devices, anomalies = detect_anomalies(all_frames)

    result = {
        "pcap": os.path.basename(pcap),
        "source": "semtech_extractor",
        "devices": devices,
        "anomalies": anomalies,
        "stats": {
            "total_udp1700_packets": len(raw_packets),
            "lorawan_phy_frames": total_semtech,
            "join_req": join_req_count,
            "join_accept": join_accept_count,
            "data_up": data_up_count,
            "data_down": data_down_count,
        },
    }

    with open(output, "w") as f:
        json.dump(result, f, indent=2)

    print(f"  Anomalies detected: {len(anomalies)}")
    print(f"  Devices tracked: {len(devices)}")
    print(f"  Wrote → {output}")


if __name__ == "__main__":
    if len(sys.argv) != 3:
        print(f"Usage: {sys.argv[0]} <input.pcap> <output_sessions.json>")
        sys.exit(1)
    extract(sys.argv[1], sys.argv[2])
