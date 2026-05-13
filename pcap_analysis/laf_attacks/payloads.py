"""
Pure-Python Semtech UDP PUSH_DATA frame builders.

Each function returns bytes ready to send to UDP port 1700.
Used as a fallback when LAF's Go bindings are unavailable, and as the
canonical packet source for reproducible attack scenarios.

Semtech PUSH_DATA wire format:
  [0]      Protocol version  = 0x02
  [1-2]    Random token      (2 bytes, big-endian)
  [3]      Identifier        = 0x00 (PUSH_DATA)
  [4-11]   Gateway EUI       (8 bytes)
  [12+]    JSON payload      {"rxpk":[...]}

LoRaWAN PHY payload is base64-encoded inside the JSON "data" field.
MICs in this module are FAKE (0x00000000) — we are generating anomaly
traffic for structural analysis, not live network injection.
"""

import json
import os
import struct
import base64
import time

# ---------------------------------------------------------------------------
# Fixed device constants — reproducible across runs → stable Scyther IDs
# ---------------------------------------------------------------------------

GATEWAY_EUI = bytes.fromhex("aabbccddeeff0000")

DEVICE_A = {
    "deveui":   "aabbccddeeff0011",
    "joineui":  "aabbccddeeff0000",
    "appkey":   "00" * 16,
    "nwkskey":  "01" * 16,
    "appskey":  "02" * 16,
    "devaddr":  "01020304",
    "devnonce": 0xAB01,
}

DEVICE_B = {
    "deveui":   "aabbccddeeff0022",
    "joineui":  "aabbccddeeff0000",
    "appkey":   "00" * 16,
    "nwkskey":  "03" * 16,
    "appskey":  "04" * 16,
    "devaddr":  "05060708",
    "devnonce": 0xAB02,
}

# Known-bad "default" AppKey (Semtech example key — publicly documented)
DEFAULT_APPKEY = "2B7E151628AED2A6ABF7158809CF4F3C"

# ---------------------------------------------------------------------------
# Low-level helpers
# ---------------------------------------------------------------------------

def _token() -> bytes:
    return os.urandom(2)


def _timestamp() -> int:
    return int(time.monotonic() * 1_000_000) & 0xFFFFFFFF


def _semtech_push_data(phy_b64: str, freq_mhz: float = 868.1) -> bytes:
    """Wrap a base64 LoRaWAN PHY payload in a Semtech PUSH_DATA packet.

    Wire format: version(1) | token(2) | identifier(1) | GW_EUI(8) | JSON
    Identifier 0x00 = PUSH_DATA (uplink frames from gateway to NS).
    """
    rxpk = {
        "tmst": _timestamp(),
        "chan": 0,
        "rfch": 0,
        "freq": freq_mhz,
        "stat": 1,
        "modu": "LORA",
        "datr": "SF7BW125",
        "codr": "4/5",
        "lsnr": 9.5,
        "rssi": -76,
        "size": len(base64.b64decode(phy_b64)),
        "data": phy_b64,
    }
    payload_json = json.dumps({"rxpk": [rxpk]}).encode()
    tok = _token()
    header = bytes([0x02, tok[0], tok[1], 0x00]) + GATEWAY_EUI   # 12 bytes
    return header + payload_json


def _b64(data: bytes) -> str:
    return base64.b64encode(data).decode()


def _fake_mic() -> bytes:
    return b"\x00\x00\x00\x00"

# ---------------------------------------------------------------------------
# LoRaWAN frame builders
# ---------------------------------------------------------------------------

def build_join_request(
    deveui: str,
    joineui: str,
    devnonce: int,
    appkey: str | None = None,
) -> bytes:
    """
    Build a Semtech PUSH_DATA wrapping a JoinRequest.

    MHdr=0x00 | JoinEUI(8B LE) | DevEUI(8B LE) | DevNonce(2B LE) | MIC(4B)
    If appkey is provided, computes a real AES128-CMAC MIC so MIC-based
    default key detection can verify the frame. Otherwise uses 0x00000000.
    """
    join_eui_b = bytes.fromhex(joineui)[::-1]   # little-endian on wire
    dev_eui_b  = bytes.fromhex(deveui)[::-1]
    nonce_b    = struct.pack("<H", devnonce & 0xFFFF)
    msg = bytes([0x00]) + join_eui_b + dev_eui_b + nonce_b
    if appkey:
        try:
            from cryptography.hazmat.primitives.cmac import CMAC
            from cryptography.hazmat.primitives.ciphers import algorithms
            c = CMAC(algorithms.AES(bytes.fromhex(appkey)))
            c.update(msg)
            mic = c.finalize()[:4]
        except Exception:
            mic = _fake_mic()
    else:
        mic = _fake_mic()
    phy = msg + mic
    return _semtech_push_data(_b64(phy))


def build_join_accept(
    joinnonce: int = 0x000001,
    netid: int = 0x000000,
    devaddr: str = "01020304",
) -> bytes:
    """
    Build a Semtech PUSH_DATA wrapping a JoinAccept (downlink, unencrypted stub).

    MHdr=0x20 | JoinNonce(3B LE) | NetID(3B LE) | DevAddr(4B LE) |
    DLSettings(1B) | RxDelay(1B) | MIC(4B)

    Note: In real LoRaWAN the JoinAccept body is encrypted with AppKey.
    Here we leave it in plaintext — sufficient for anomaly triggering
    (the extractor detects unsolicited JoinAccept by frame type, not content).
    """
    jn_b  = struct.pack("<I", joinnonce & 0xFFFFFF)[:3]
    ni_b  = struct.pack("<I", netid & 0xFFFFFF)[:3]
    da_b  = bytes.fromhex(devaddr)[::-1]
    phy   = bytes([0x20]) + jn_b + ni_b + da_b + bytes([0x00, 0x00]) + _fake_mic()
    return _semtech_push_data(_b64(phy))


def build_data_up(
    devaddr: str,
    fcnt: int,
    payload_hex: str = "DEADBEEF",
    nwkskey: str = "01" * 16,
    fport: int = 1,
    confirmed: bool = False,
) -> bytes:
    """
    Build a Semtech PUSH_DATA wrapping an UnconfirmedDataUp (or ConfirmedDataUp).

    MHdr | DevAddr(4B LE) | FCtrl(1B) | FCnt(2B LE) | FPort(1B) | FRMPayload | MIC(4B)
    MIC is fake — extractor checks sequence/FCnt, not MIC.
    """
    mhdr    = 0x80 if confirmed else 0x40
    da_b    = bytes.fromhex(devaddr)[::-1]
    fctrl   = 0x00
    fcnt_b  = struct.pack("<H", fcnt & 0xFFFF)
    frm     = bytes.fromhex(payload_hex)
    phy = (
        bytes([mhdr])
        + da_b
        + bytes([fctrl])
        + fcnt_b
        + bytes([fport])
        + frm
        + _fake_mic()
    )
    return _semtech_push_data(_b64(phy))


# ---------------------------------------------------------------------------
# Pre-built attack scenario packet sequences
# ---------------------------------------------------------------------------

def packets_baseline(device: dict = DEVICE_A) -> list:
    """Normal OTAA join + 3 uplink data frames."""
    pkts = []
    pkts.append(("JoinReq",  build_join_request(device["deveui"], device["joineui"], device["devnonce"])))
    pkts.append(("JoinAccept", build_join_accept(devaddr=device["devaddr"])))
    for fcnt in (1, 2, 3):
        pkts.append((f"DataUp FCnt={fcnt}", build_data_up(device["devaddr"], fcnt, nwkskey=device["nwkskey"])))
    return pkts


def packets_fcnt_replay(device: dict = DEVICE_A, fcnt: int = 10) -> list:
    """Send same FCnt twice → FCnt_fcnt_repeat anomaly."""
    pkts = []
    pkts.append(("JoinReq",   build_join_request(device["deveui"], device["joineui"], device["devnonce"])))
    pkts.append(("JoinAccept", build_join_accept(devaddr=device["devaddr"])))
    pkts.append((f"DataUp FCnt={fcnt} (first)",  build_data_up(device["devaddr"], fcnt, nwkskey=device["nwkskey"])))
    pkts.append((f"DataUp FCnt={fcnt} (replay)", build_data_up(device["devaddr"], fcnt, nwkskey=device["nwkskey"])))
    return pkts


def packets_fcnt_rollback(device: dict = DEVICE_B, high: int = 50, low: int = 5) -> list:
    """Send FCnt=high then FCnt=low → FCnt_fcnt_decrease anomaly."""
    pkts = []
    pkts.append(("JoinReq",   build_join_request(device["deveui"], device["joineui"], device["devnonce"])))
    pkts.append(("JoinAccept", build_join_accept(devaddr=device["devaddr"])))
    pkts.append((f"DataUp FCnt={high}", build_data_up(device["devaddr"], high, nwkskey=device["nwkskey"])))
    pkts.append((f"DataUp FCnt={low} (rollback)", build_data_up(device["devaddr"], low, nwkskey=device["nwkskey"])))
    return pkts


def packets_devnonce_replay(device: dict = DEVICE_B, devnonce: int = 0xABCD) -> list:
    """Send same JoinReq DevNonce twice → DevNonce_Replay anomaly."""
    pkts = []
    pkts.append(("JoinReq (first)",  build_join_request(device["deveui"], device["joineui"], devnonce)))
    pkts.append(("JoinAccept",       build_join_accept(devaddr=device["devaddr"])))
    pkts.append(("JoinReq (replay)", build_join_request(device["deveui"], device["joineui"], devnonce)))
    pkts.append(("JoinAccept",       build_join_accept(devaddr=device["devaddr"])))
    return pkts


def packets_rogue_ns(devaddr: str = "DEADC0DE") -> list:
    """Send a JoinAccept with no preceding JoinReq → Unsolicited_JoinAccept anomaly."""
    return [
        ("JoinAccept (unsolicited)", build_join_accept(devaddr=devaddr)),
    ]


def packets_default_key(device: dict = DEVICE_A) -> list:
    """Normal OTAA join using the publicly-known Semtech default AppKey.
    Uses a real CMAC MIC so semtech_extractor's MIC verification can confirm it."""
    pkts = []
    pkts.append(("JoinReq (default key)", build_join_request(device["deveui"], device["joineui"], device["devnonce"], appkey=DEFAULT_APPKEY)))
    pkts.append(("JoinAccept",            build_join_accept(devaddr=device["devaddr"])))
    pkts.append(("DataUp FCnt=1",         build_data_up(device["devaddr"], 1, nwkskey=DEFAULT_APPKEY[:32])))
    return pkts
