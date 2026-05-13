#!/usr/bin/env python3
"""
lwn_validator.py — End-to-end pipeline validation for LoRaWAN-SecFW.

Validates the full analysis pipeline:
  sessions JSON → scenario_builder.py → Scyther SPDL → security claims

Two modes:

  SYNTHETIC (default — no hardware required):
    Injects ground-truth sessions JSON for 5 controlled attack scenarios,
    runs the pipeline, and checks Scyther's output against known-correct results.
    This validates the pipeline logic independently of any capture tool.

  LIVE (--live, requires LWN-Simulator + tshark):
    Starts LWN-Simulator, configures devices via its REST API, captures
    Semtech UDP/1700 traffic with tshark, runs semtech_extractor.py to
    parse it into sessions JSON, then continues the same pipeline.

Usage:
  python3 lwn_validator.py                     # synthetic validation only
  python3 lwn_validator.py --live              # also run LWN-Simulator capture
  python3 lwn_validator.py --pcap <file.pcap>  # validate an existing capture

Ground-truth test cases (synthetic):
  1. BASELINE          — Normal OTAA join; ED Nisynch FAILS (known LoRaWAN flaw)
  2. DEVNONCE_REPLAY   — Same DevNonce used twice; ED Nisynch FAILS
  3. FCNT_REPEAT       — FCnt repeated in data session; Receiver Nisynch FAILS
  4. UNSOLICITED_JOIN  — JoinAccept with no prior JoinReq (rogue NS); ED Nisynch FAILS
  5. FCNT_DECREASE     — FCnt rolls back (device reset); Receiver Nisynch FAILS
"""

import sys
import os
import json
import time
import shutil
import signal
import tempfile
import argparse
import subprocess
import platform
from pathlib import Path
from dataclasses import dataclass, field

# Windows console defaults to cp1252 which can't encode Unicode box-drawing chars etc.
if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
if hasattr(sys.stderr, "reconfigure"):
    sys.stderr.reconfigure(encoding="utf-8", errors="replace")

# ── Paths ──────────────────────────────────────────────────────────────────────
HERE = Path(__file__).parent
ROOT = HERE.parent
SCENARIO_BUILDER = HERE / "scenario_builder.py"
SEMTECH_EXTRACTOR = HERE / "semtech_extractor.py"
LWN_SIM_DIR = ROOT / "LWN-Simulator-main"

_sys = platform.system()

_scyther_fallback = {
    "Windows": str(Path.home() / "scyther/gui/Scyther/scyther-w32.exe"),
    "Linux":   str(Path.home() / "scyther/gui/Scyther/scyther-linux64"),
}.get(_sys, str(Path.home() / "scyther/gui/Scyther/scyther-mac-arm"))

_tshark_fallback = {
    "Windows": r"C:\Program Files\Wireshark\tshark.exe",
    "Linux":   "/usr/bin/tshark",
}.get(_sys, "/Applications/Wireshark.app/Contents/MacOS/tshark")

LWN_SIM_BIN = ROOT / ("lwnsimulator.exe" if _sys == "Windows" else "lwnsimulator")
SCYTHER = Path(os.environ.get("SCYTHER_BIN", shutil.which("scyther") or _scyther_fallback))
TSHARK = Path(os.environ.get("TSHARK", shutil.which("tshark") or _tshark_fallback))
LOOPBACK = os.environ.get("LOOPBACK_IFACE", {
    "Linux":   "lo",
    "Windows": r"\Device\NPF_Loopback",
}.get(_sys, "lo0"))

# ── LWN-Simulator REST API ─────────────────────────────────────────────────────
LWN_API = "http://127.0.0.1:8000/api"

# ── Colour helpers ─────────────────────────────────────────────────────────────
GREEN  = "\033[32m"
RED    = "\033[31m"
YELLOW = "\033[33m"
RESET  = "\033[0m"
BOLD   = "\033[1m"

def ok(msg):    return f"{GREEN}✓{RESET} {msg}"
def fail(msg):  return f"{RED}✗{RESET} {msg}"
def warn(msg):  return f"{YELLOW}!{RESET} {msg}"


# ── Live device profiles ───────────────────────────────────────────────────────
# Used by --live mode. Select profiles with --devices normal,replay,abp,...
# Each profile's "info" dict is POSTed directly to /api/add-device.

def _dev_cfg(region=1, otaa=True, interval=10, ack_timeout=5, nb_retx=1,
             class_b=False, class_c=False, adr=False, frag=False,
             data_rate=0, rx1_offset=0, fcnt_down=False, range_=100.0):
    return {
        "region": region,
        "supportedOtaa": otaa,
        "sendInterval": interval,
        "ackTimeout": ack_timeout,
        "nbRetransmission": nb_retx,
        "supportedClassB": class_b,
        "supportedClassC": class_c,
        "supportedADR": adr,
        "supportedFragment": frag,
        "dataRate": data_rate,
        "rx1DROffset": rx1_offset,
        "disableFCntDown": fcnt_down,
        "range": range_,
    }

LIVE_DEVICE_PROFILES: dict[str, dict] = {
    # Normal OTAA device — EU868, 10s interval
    "normal": {
        "name": "ED_Normal",
        "devEUI": "aabbccddeeff0011",
        "appKey": "00000000000000000000000000000001",
        "devAddr": "00000000",
        "nwkSKey": "00000000000000000000000000000000",
        "appSKey": "00000000000000000000000000000000",
        "status": {"joined": False, "active": True},
        "configuration": _dev_cfg(),
        "location": {"latitude": 50.0, "longitude": 14.0, "altitude": 200},
    },
    # Replay attacker — simulates DevNonce reuse
    "replay": {
        "name": "ED_Replay",
        "devEUI": "aabbccddeeff0022",
        "appKey": "00000000000000000000000000000002",
        "devAddr": "00000000",
        "nwkSKey": "00000000000000000000000000000000",
        "appSKey": "00000000000000000000000000000000",
        "status": {"joined": False, "active": True},
        "configuration": _dev_cfg(),
        "location": {"latitude": 50.0, "longitude": 14.0, "altitude": 200},
    },
    # ABP device — pre-provisioned keys, no OTAA join
    "abp": {
        "name": "ED_ABP",
        "devEUI": "aabbccddeeff0033",
        "appKey": "00000000000000000000000000000000",
        "devAddr": "01020304",
        "nwkSKey": "deadbeefdeadbeefdeadbeefdeadbeef",
        "appSKey": "cafebabecafebabecafebabecafebabe",
        "status": {"joined": True, "active": True},
        "configuration": _dev_cfg(otaa=False, interval=15),
        "location": {"latitude": 50.1, "longitude": 14.1, "altitude": 200},
    },
    # Confirmed uplink — nbRetransmission=3, forces ConfirmedDataUp + ACK wait
    "confirmed": {
        "name": "ED_Confirmed",
        "devEUI": "aabbccddeeff0044",
        "appKey": "00000000000000000000000000000004",
        "devAddr": "00000000",
        "nwkSKey": "00000000000000000000000000000000",
        "appSKey": "00000000000000000000000000000000",
        "status": {"joined": False, "active": True},
        "configuration": _dev_cfg(nb_retx=3, ack_timeout=10),
        "location": {"latitude": 50.2, "longitude": 14.2, "altitude": 200},
    },
    # Class C device — continuous receive window
    "class_c": {
        "name": "ED_ClassC",
        "devEUI": "aabbccddeeff0055",
        "appKey": "00000000000000000000000000000005",
        "devAddr": "00000000",
        "nwkSKey": "00000000000000000000000000000000",
        "appSKey": "00000000000000000000000000000000",
        "status": {"joined": False, "active": True},
        "configuration": _dev_cfg(class_c=True, interval=20),
        "location": {"latitude": 50.3, "longitude": 14.3, "altitude": 200},
    },
    # AU915 regional parameters (Australia)
    "au915": {
        "name": "ED_AU915",
        "devEUI": "aabbccddeeff0066",
        "appKey": "00000000000000000000000000000006",
        "devAddr": "00000000",
        "nwkSKey": "00000000000000000000000000000000",
        "appSKey": "00000000000000000000000000000000",
        "status": {"joined": False, "active": True},
        "configuration": _dev_cfg(region=5, interval=10),
        "location": {"latitude": -33.8, "longitude": 151.2, "altitude": 10},
    },
    # US902 regional parameters (North America)
    "us902": {
        "name": "ED_US902",
        "devEUI": "aabbccddeeff0077",
        "appKey": "00000000000000000000000000000007",
        "devAddr": "00000000",
        "nwkSKey": "00000000000000000000000000000000",
        "appSKey": "00000000000000000000000000000000",
        "status": {"joined": False, "active": True},
        "configuration": _dev_cfg(region=4, interval=10),
        "location": {"latitude": 40.7, "longitude": -74.0, "altitude": 10},
    },
    # High-frequency uplink — 5s interval, stress-tests FCnt tracking
    "fast": {
        "name": "ED_Fast",
        "devEUI": "aabbccddeeff0088",
        "appKey": "00000000000000000000000000000008",
        "devAddr": "00000000",
        "nwkSKey": "00000000000000000000000000000000",
        "appSKey": "00000000000000000000000000000000",
        "status": {"joined": False, "active": True},
        "configuration": _dev_cfg(interval=5),
        "location": {"latitude": 50.0, "longitude": 14.0, "altitude": 200},
    },
}

VALID_PROFILES = list(LIVE_DEVICE_PROFILES.keys())


# ── Ground-truth test cases ────────────────────────────────────────────────────

def sessions_baseline() -> dict:
    """One device, one clean OTAA join — no anomalies."""
    return {
        "pcap": "synthetic_baseline.pcap",
        "source": "lwn_validator",
        "devices": {
            "aabbccddeeff0011": {
                "join_attempts": [
                    {"frame": 1, "joineui": "0102030405060708",
                     "devnonce": "0a1b", "has_response": True}
                ],
                "data_sessions": [],
                "uses_default_key": False,
                "devnonce_kld": 0.0,
            }
        },
        "anomalies": [],
        "stats": {"total_frames": 10, "join_req": 1,
                  "join_accept": 1, "data": 0, "other": 8},
    }


def sessions_devnonce_replay() -> dict:
    """One device replays the same DevNonce — DevNonce_Replay anomaly."""
    return {
        "pcap": "synthetic_devnonce_replay.pcap",
        "source": "lwn_validator",
        "devices": {
            "aabbccddeeff0022": {
                "join_attempts": [
                    {"frame": 1,  "joineui": "0102030405060708",
                     "devnonce": "dead", "has_response": True},
                    {"frame": 50, "joineui": "0102030405060708",
                     "devnonce": "dead", "has_response": True},   # replay!
                ],
                "data_sessions": [],
                "uses_default_key": False,
                "devnonce_kld": 0.0,
            }
        },
        "anomalies": [
            {
                "type": "DevNonce_Replay",
                "frame": 50,
                "deveui": "aabbccddeeff0022",
                "devnonce": "dead",
                "detail": "DevNonce already seen for this device — join replay attack",
            }
        ],
        "stats": {"total_frames": 100, "join_req": 2,
                  "join_accept": 2, "data": 0, "other": 96},
    }


def sessions_fcnt_repeat() -> dict:
    """Three devices each repeat an FCnt — triggers 3 DataReplay protocols.

    The Receiver Nisynch attack in Scyther's symbolic model only manifests
    when 3+ DataReplay protocols are present simultaneously (cross-protocol
    multi-session attack). This mirrors real captures where multiple devices
    show FCnt anomalies concurrently.
    """
    def _device(devaddr: str, fcnt_dup: int) -> dict:
        seq = [1, 2, fcnt_dup, 3, 4, fcnt_dup]
        return {
            "join_attempts": [],
            "data_sessions": [{"devaddr": devaddr, "fcnt_sequence": seq,
                                "frame_map": [[i+1, v] for i, v in enumerate(seq)],
                                "anomaly": "fcnt_repeat"}],
            "uses_default_key": False, "devnonce_kld": 0.0,
        }

    return {
        "pcap": "synthetic_fcnt_repeat.pcap",
        "source": "lwn_validator",
        "devices": {
            "devaddr:0xdeadbeef": _device("0xdeadbeef", 3),
            "devaddr:0xcafecafe": _device("0xcafecafe", 7),
            "devaddr:0xbeefc0de": _device("0xbeefc0de", 2),
        },
        "anomalies": [
            {"type": "FCnt_fcnt_repeat", "devaddr": "0xdeadbeef",
             "detail": "FCnt 3 repeated", "fcnt_sequence": [1,2,3,3,4,3]},
            {"type": "FCnt_fcnt_repeat", "devaddr": "0xcafecafe",
             "detail": "FCnt 7 repeated", "fcnt_sequence": [1,2,7,3,4,7]},
            {"type": "FCnt_fcnt_repeat", "devaddr": "0xbeefc0de",
             "detail": "FCnt 2 repeated", "fcnt_sequence": [1,2,2,3,4,2]},
        ],
        "stats": {"total_frames": 30, "join_req": 0,
                  "join_accept": 0, "data": 18, "other": 12},
    }


def sessions_unsolicited_joinaccept() -> dict:
    """JoinAccept arrives with no prior JoinReq — rogue NS attack."""
    return {
        "pcap": "synthetic_unsolicited_joinaccept.pcap",
        "source": "lwn_validator",
        "devices": {},
        "anomalies": [
            {
                "type": "Unsolicited_JoinAccept",
                "frame": 17,
                "detail": "JoinAccept with no matching JoinReq — possible rogue NS or MITM",
            }
        ],
        "stats": {"total_frames": 30, "join_req": 0,
                  "join_accept": 1, "data": 0, "other": 29},
    }


def sessions_fcnt_decrease() -> dict:
    """Three devices with FCnt rollback — same multi-protocol reasoning as fcnt_repeat."""
    def _device(devaddr: str) -> dict:
        seq = [100, 101, 102, 1, 2, 3]   # rollback after reset
        return {
            "join_attempts": [],
            "data_sessions": [{"devaddr": devaddr, "fcnt_sequence": seq,
                                "frame_map": [[i+1, v] for i, v in enumerate(seq)],
                                "anomaly": "fcnt_decrease"}],
            "uses_default_key": False, "devnonce_kld": 0.0,
        }

    return {
        "pcap": "synthetic_fcnt_decrease.pcap",
        "source": "lwn_validator",
        "devices": {
            "devaddr:0xcafebabe": _device("0xcafebabe"),
            "devaddr:0xfeedface": _device("0xfeedface"),
            "devaddr:0xabcdef01": _device("0xabcdef01"),
        },
        "anomalies": [
            {"type": "FCnt_fcnt_decrease", "devaddr": "0xcafebabe",
             "detail": "FCnt decrease detected", "fcnt_sequence": [100,101,102,1,2,3]},
            {"type": "FCnt_fcnt_decrease", "devaddr": "0xfeedface",
             "detail": "FCnt decrease detected", "fcnt_sequence": [100,101,102,1,2,3]},
            {"type": "FCnt_fcnt_decrease", "devaddr": "0xabcdef01",
             "detail": "FCnt decrease detected", "fcnt_sequence": [100,101,102,1,2,3]},
        ],
        "stats": {"total_frames": 30, "join_req": 0,
                  "join_accept": 0, "data": 18, "other": 12},
    }


# ── Expected Scyther claim outcomes ───────────────────────────────────────────

@dataclass
class ClaimExpectation:
    """One expected Scyther claim outcome."""
    protocol_prefix: str   # protocol name starts with this
    role_keyword: str      # "ED", "NS", "Receiver", "Sender", "AS"
    claim_keyword: str     # "Nisynch", "Secret", "Alive"
    expected: str          # "Fail" or "Ok"
    description: str       # human-readable reason


TESTS: list[dict] = [
    {
        "name": "BASELINE",
        "description": "Normal OTAA join — no attacks",
        "sessions_fn": sessions_baseline,
        "expectations": [
            ClaimExpectation("Baseline", "ED", "Weakagree", "Ok",
                             "NS participated in the protocol"),
            ClaimExpectation("Baseline", "ED", "Niagree",   "Fail",
                             "JoinAccept not bound to DevNonce — non-injective agreement broken"),
            ClaimExpectation("Baseline", "ED", "Nisynch",   "Fail",
                             "LoRaWAN 1.0 design flaw: ED cannot authenticate NS"),
            ClaimExpectation("Baseline", "ED", "Secret",    "Ok",
                             "Session keys protected from external adversary"),
            ClaimExpectation("Baseline", "NS", "Secret",    "Ok",
                             "Session keys protected from external adversary"),
        ],
    },
    {
        "name": "DEVNONCE_REPLAY",
        "description": "DevNonce replayed → Replay scenario",
        "sessions_fn": sessions_devnonce_replay,
        "expectations": [
            ClaimExpectation("Replay", "ED", "Weakagree", "Ok",
                             "NS participated in the protocol"),
            ClaimExpectation("Replay", "ED", "Niagree",   "Ok",
                             "NS ran once with this DevNonce — non-injective agreement holds"),
            ClaimExpectation("Replay", "ED", "Nisynch",   "Fail",
                             "Replayed const DevNonce: two ED sessions per one NS session"),
            ClaimExpectation("Replay", "ED", "Secret",    "Ok",
                             "AppKey still secret from external adversary"),
        ],
    },
    {
        "name": "FCNT_REPEAT",
        "description": "FCnt repeated → DataReplay scenario",
        "sessions_fn": sessions_fcnt_repeat,
        "expectations": [
            ClaimExpectation("DataReplay", "Receiver", "Nisynch", "Fail",
                             "const FCnt breaks injective sync on Receiver"),
            ClaimExpectation("DataReplay", "Sender",   "Secret",  "Ok",
                             "Payload secret from external adversary"),
        ],
    },
    {
        "name": "UNSOLICITED_JOINACCEPT",
        "description": "JoinAccept with no JoinReq → RogueNS scenario",
        "sessions_fn": sessions_unsolicited_joinaccept,
        "expectations": [
            ClaimExpectation("RogueNS", "ED", "Weakagree", "Ok",
                             "Rogue NS ran its role — weak agreement with adversary"),
            ClaimExpectation("RogueNS", "ED", "Niagree",   "Fail",
                             "Rogue NS impersonation breaks non-injective agreement"),
            ClaimExpectation("RogueNS", "ED", "Nisynch",   "Fail",
                             "Rogue NS impersonation breaks Nisynch on ED"),
        ],
    },
    {
        "name": "FCNT_DECREASE",
        "description": "FCnt rollback → DataReplay scenario",
        "sessions_fn": sessions_fcnt_decrease,
        "expectations": [
            ClaimExpectation("DataReplay", "Receiver", "Nisynch", "Fail",
                             "FCnt rollback (device reset) breaks injective sync"),
        ],
    },
]


# ── Scyther output parser ──────────────────────────────────────────────────────

def parse_scyther_output(output: str) -> list[dict]:
    """Parse Scyther's tab-separated claim lines.

    Scyther output format (tab-separated):
      claim  <Protocol>,<Role>  <ClaimID>  <Term>  <Result>  <Details>

    Returns list of dicts:
      {"protocol": str, "role": str, "claim_id": str, "term": str, "result": str}
    """
    claims = []
    for line in output.splitlines():
        if not line.startswith("claim"):
            continue
        parts = line.split("\t")
        if len(parts) < 5:
            continue
        # parts[1]: "Protocol,Role"
        # parts[2]: ClaimID  (e.g. "Nisynch_ED...", "Secret_ED...", "Alive_NS...")
        # parts[3]: Term     (e.g. "-" or "appSKey(...)")
        # parts[4]: Result   (e.g. "[32mOk[0m" or "[31mFail[0m")
        proto_role = parts[1].strip()
        claim_id   = parts[2].strip()
        term       = parts[3].strip()
        result_raw = parts[4].strip()
        result     = "Ok" if "Ok" in result_raw else "Fail"

        # Split "Protocol,Role" on last comma
        comma = proto_role.rfind(",")
        if comma >= 0:
            protocol = proto_role[:comma]
            role     = proto_role[comma+1:]
        else:
            protocol = proto_role
            role     = ""

        claims.append({
            "protocol": protocol,
            "role":     role,
            "claim_id": claim_id,
            "term":     term,
            "result":   result,
        })
    return claims


def check_expectation(claims: list[dict], exp: ClaimExpectation) -> tuple[bool, str]:
    """Check one ClaimExpectation against parsed Scyther claims.

    Returns (passed, detail_message).
    """
    matching = [
        c for c in claims
        if c["protocol"].startswith(exp.protocol_prefix)
        and exp.role_keyword in c["role"]
        and exp.claim_keyword in c["claim_id"]
    ]
    if not matching:
        return False, (f"No claim found for {exp.protocol_prefix}/*{exp.role_keyword}*"
                       f"/*{exp.claim_keyword}*")
    for c in matching:
        if c["result"] != exp.expected:
            return False, (f"{c['protocol']},{c['role']}: "
                           f"{exp.claim_keyword} = {c['result']} "
                           f"(expected {exp.expected})")
    return True, (f"{exp.protocol_prefix}/{exp.role_keyword}/{exp.claim_keyword}"
                  f" = {exp.expected}")


# ── Pipeline runner ────────────────────────────────────────────────────────────

def run_scenario_builder(sessions_json: Path, spdl_out: Path) -> bool:
    """Run scenario_builder.py, return True if SPDL was generated."""
    result = subprocess.run(
        [sys.executable, str(SCENARIO_BUILDER), str(sessions_json), str(spdl_out)],
        capture_output=True, text=True,
    )
    return spdl_out.exists() and spdl_out.stat().st_size > 0


def run_scyther(spdl: Path) -> tuple[int, str]:
    """Run Scyther on an SPDL file.  Returns (returncode, stdout+stderr)."""
    result = subprocess.run(
        [str(SCYTHER), str(spdl)],
        capture_output=True, text=True,
    )
    return result.returncode, result.stdout + result.stderr


def _attack_type_label(protocol: str) -> str:
    p = protocol.lower()
    if p.startswith("datareplay"):
        return "Frame-counter replay / rollback (FCnt reuse)"
    if p.startswith("replay"):
        return "DevNonce replay (stale join request reused)"
    if p.startswith("roguens"):
        return "Rogue network server (unsolicited JoinAccept)"
    if p.startswith("baseline"):
        return "Baseline OTAA join — design-level vulnerability"
    return "Unknown attack type"


def _why_nisynch_fails(protocol: str) -> str:
    p = protocol.lower()
    if p.startswith("datareplay"):
        return (
            "The frame counter is modeled as a constant (same FCnt value reused), "
            "representing a replay or rollback. Injective synchronisation requires "
            "each Receiver run to correspond to a distinct Sender run. Because FCnt "
            "is not fresh, the adversary can replay a frame from a different session "
            "and the Receiver accepts it — breaking the 1-to-1 correspondence."
        )
    if p.startswith("replay"):
        return (
            "The DevNonce is modeled as a constant (same value across sessions), "
            "representing deployments that do not enforce DevNonce uniqueness. "
            "The adversary replays an ED JoinReq from a different session into "
            "the NS, which responds. The NS ran once but satisfied two ED sessions — "
            "injective synchronisation is broken."
        )
    if p.startswith("roguens"):
        return (
            "A rogue NS sends a JoinAccept with no preceding JoinReq from this ED. "
            "The ED accepts it and derives session keys with the adversary. "
            "Injective synchronisation fails because the ED believes it completed "
            "a join with a legitimate NS, but no such NS run exists."
        )
    if p.startswith("baseline"):
        return (
            "This is a known design flaw in LoRaWAN 1.0/1.1: the JoinAccept is "
            "not authenticated to the ED — any party with knowledge of the AppKey "
            "can forge one. The adversary intercepts the JoinReq, sends a crafted "
            "JoinAccept, and the ED completes a join with adversary-chosen keys."
        )
    return "See Scyther attack trace diagram for details."


def _summarize_dot_graph(dot: str, proto: str, role: str, claim: str) -> str:
    import re

    # ── Parse run summary nodes (s0, s2, s3 …) ──────────────────────────────
    runs: dict[int, dict] = {}
    for m in re.finditer(r's(\d+)\s*\[label="(\{[^"]+\})"', dot):
        raw = (m.group(2)
               .replace(r'\l', '\n')
               .replace(r'\>', '>')
               .replace(r'\|', '|'))
        run_m  = re.search(r'Run #(\d+)', raw)
        actor_m = re.search(r'(\w+) in role (\S+)', raw)
        fresh_m = re.findall(r'Fresh (\S+)', raw)
        var_m   = re.findall(r'Var (\S+) -> (\S+)', raw)
        if run_m and actor_m:
            rn = int(run_m.group(1))
            runs[rn] = {
                'actor': actor_m.group(1),
                'role':  actor_m.group(2),
                'fresh': fresh_m,
                'vars':  var_m,
                'node_prefix': f"r{int(m.group(1))}i",
            }

    # ── Parse action nodes (r0i0, r2i1 …) ───────────────────────────────────
    actions: dict[str, str] = {}
    for m in re.finditer(r'(r\d+i\d+)\s*\[.*?label="([^"]+)"', dot):
        label = m.group(2).replace(r'\n', '\n').replace(r'\{', '{').replace(r'\}', '}')
        actions[m.group(1)] = label

    # Map node prefix (r0i) → run number for step attribution
    prefix_to_run: dict[str, int] = {}
    for rn, info in runs.items():
        prefix_to_run[info['node_prefix']] = rn

    # ── Parse adversary (green) edges ────────────────────────────────────────
    adv_edges: list[tuple[str, str]] = []
    for m in re.finditer(
        r'(r\d+i\d+)\s*->\s*(r\d+i\d+)\s*\[style=bold,color="forestgreen"\]', dot
    ):
        adv_edges.append((m.group(1), m.group(2)))

    # ── Build human-readable summary ─────────────────────────────────────────
    out: list[str] = []
    sep = "=" * 56

    out.append(sep)
    out.append("ATTACK TRACE SUMMARY")
    out.append(sep)
    out.append(f"Protocol : {proto}")
    out.append(f"Role     : {role}")
    out.append(f"Claim    : {claim}  [VIOLATED]")
    out.append(f"Attack   : {_attack_type_label(proto)}")
    out.append("")

    if runs:
        out.append(f"Scyther found a {len(runs)}-run attack using the Dolev-Yao adversary model.")
        out.append("")
        for rn in sorted(runs):
            info = runs[rn]
            actor_label = "End Device" if "ED" in info['role'] or "Dev" in info['role'] else \
                          "Network Server" if "NS" in info['role'] or "Srv" in info['role'] else \
                          info['actor']
            out.append(f"  Run {rn} — {info['role']} ({actor_label}):")
            # List steps for this run
            prefix = info['node_prefix']
            steps = sorted(
                [(nid, lbl) for nid, lbl in actions.items() if nid.startswith(prefix)],
                key=lambda x: int(re.search(r'i(\d+)', x[0]).group(1))
            )
            for nid, lbl in steps:
                first_line = lbl.split('\n')[0]
                if first_line.startswith("claim_"):
                    out.append(f"    ✗ {claim} claim FAILS (violation point)")
                elif first_line.startswith("send_"):
                    out.append(f"    → {first_line}")
                elif first_line.startswith("recv_"):
                    out.append(f"    ← {first_line}")
            out.append("")

    if adv_edges:
        out.append(f"Adversary moves ({len(adv_edges)} message interceptions/replays):")
        for idx, (src, dst) in enumerate(adv_edges, 1):
            src_lbl = actions.get(src, src).split('\n')[0]
            dst_lbl = actions.get(dst, dst).split('\n')[0]
            out.append(f"  {idx}. Takes [{src}] {src_lbl}")
            out.append(f"     → delivers to [{dst}] {dst_lbl}")
        out.append("")

    out.append("Why this breaks injective synchronisation:")
    for line in _why_nisynch_fails(proto).split('. '):
        line = line.strip().rstrip('.')
        if line:
            out.append(f"  {line}.")
    out.append("")
    out.append(sep)

    return '\n'.join(out)


def save_attack_traces(spdl: Path, output_dir: Path) -> list[Path]:
    """Run Scyther with --dot-output, convert dot graphs to PNG, save to output_dir/attack_traces/.

    Returns list of files written (PNG if graphviz is available, .dot otherwise).
    Only FAIL claims produce attack trace graphs — OK claims produce nothing.
    """
    import re

    traces_dir = output_dir / "attack_traces"
    traces_dir.mkdir(parents=True, exist_ok=True)

    result = subprocess.run(
        [str(SCYTHER), "--dot-output", str(spdl)],
        capture_output=True, text=True,
    )
    dot_content = result.stdout
    if not dot_content.strip():
        return []

    # Extract complete digraph blocks by counting braces — regex .*? stops at first }
    graphs = []
    for match in re.finditer(r'digraph\s+\S+\s*\{', dot_content):
        start = match.start()
        depth = 0
        for i, ch in enumerate(dot_content[match.start():], match.start()):
            if ch == '{':
                depth += 1
            elif ch == '}':
                depth -= 1
                if depth == 0:
                    graphs.append(dot_content[start:i + 1].strip())
                    break

    written = []
    dot_bin = shutil.which("dot")
    name_counts: dict[str, int] = {}

    for i, graph in enumerate(graphs):
        # Extract protocol, role, claim from the label line for a meaningful filename
        label_match = re.search(
            r'Protocol\s+(\S+),\s*role\s+(\S+),\s*claim type\s+(\S+)', graph
        )
        if label_match:
            proto = re.sub(r'[^A-Za-z0-9_-]', '', label_match.group(1))
            role  = re.sub(r'[^A-Za-z0-9_-]', '', label_match.group(2))
            claim = re.sub(r'[^A-Za-z0-9_-]', '', label_match.group(3))
            base = f"{proto}_{role}_{claim}"
        else:
            base = f"attack_trace_{i + 1}"

        # Deduplicate if same proto/role/claim appears multiple times
        name_counts[base] = name_counts.get(base, 0) + 1
        stem = base if name_counts[base] == 1 else f"{base}_{name_counts[base]}"

        dot_path = traces_dir / f"{stem}.dot"
        dot_path.write_text(graph, encoding="utf-8")

        # Write text summary alongside the image
        _clean = lambda s: re.sub(r'[^A-Za-z0-9]', '', s)
        proto_raw  = _clean(label_match.group(1)) if label_match else stem
        role_raw   = _clean(label_match.group(2)) if label_match else ""
        claim_raw  = _clean(label_match.group(3)) if label_match else ""
        summary_txt = _summarize_dot_graph(graph, proto_raw, role_raw, claim_raw)
        (traces_dir / f"{stem}.txt").write_text(summary_txt, encoding="utf-8")

        if dot_bin:
            png_path = traces_dir / f"{stem}.png"
            subprocess.run(
                [dot_bin, "-Tpng", str(dot_path), "-o", str(png_path)],
                capture_output=True,
            )
            if png_path.exists():
                written.append(png_path)
                dot_path.unlink()
            else:
                written.append(dot_path)
        else:
            written.append(dot_path)

    if not dot_bin and written:
        print(warn("graphviz 'dot' not found — saved .dot files instead of PNG. Install with: brew install graphviz"))

    return written


def check_spdl_has_protocol(spdl: Path, prefix: str) -> bool:
    """Return True if the SPDL file contains a protocol starting with prefix."""
    text = spdl.read_text()
    return f"protocol {prefix}" in text


# ── Synthetic validation ───────────────────────────────────────────────────────

def run_synthetic_tests(tmpdir: Path, verbose: bool = False) -> tuple[int, int]:
    """Run all synthetic ground-truth test cases.

    Returns (passed, total).
    """
    passed = 0
    total  = len(TESTS)

    print(f"\n{BOLD}{'─'*64}{RESET}")
    print(f"{BOLD}  Synthetic Validation — {total} ground-truth test cases{RESET}")
    print(f"{BOLD}{'─'*64}{RESET}\n")

    for test in TESTS:
        name        = test["name"]
        description = test["description"]
        sessions    = test["sessions_fn"]()
        expectations= test["expectations"]

        # Write synthetic sessions JSON
        sessions_path = tmpdir / f"{name.lower()}_sessions.json"
        spdl_path     = tmpdir / f"{name.lower()}.spdl"
        sessions_path.write_text(json.dumps(sessions, indent=2))

        print(f"  [{name}] {description}")

        # Step 1: scenario_builder
        ok_build = run_scenario_builder(sessions_path, spdl_path)
        if not ok_build:
            print(f"    {fail('scenario_builder produced no output')}")
            print()
            continue

        # Step 2: check the right protocol type was emitted
        exp_prefix = expectations[0].protocol_prefix if expectations else ""
        has_proto  = check_spdl_has_protocol(spdl_path, exp_prefix)
        if not has_proto:
            spdl_text = spdl_path.read_text()
            proto_line = next(
                (l for l in spdl_text.splitlines() if "protocol" in l), "none"
            )
            print(f"    {warn(f'Expected protocol prefix {exp_prefix!r}, got: {proto_line.strip()!r}')}")

        # Step 3: Scyther
        retcode, scyther_out = run_scyther(spdl_path)
        save_attack_traces(spdl_path, tmpdir)
        if verbose:
            for line in scyther_out.splitlines():
                if line.startswith("claim"):
                    print(f"    {line}")

        claims = parse_scyther_output(scyther_out)
        if not claims:
            print(f"    {fail('Scyther produced no claim output')}")
            if verbose:
                print(f"    stdout: {scyther_out[:300]}")
            print()
            continue

        # Step 4: check each expectation
        all_passed = True
        for exp in expectations:
            passed_exp, detail = check_expectation(claims, exp)
            icon = ok(detail) if passed_exp else fail(detail)
            print(f"    {icon}")
            if not passed_exp:
                all_passed = False
                if exp.description:
                    print(f"      → expected: {exp.description}")

        if all_passed:
            passed += 1
            print(f"    {GREEN}{BOLD}PASS{RESET}")
        else:
            print(f"    {RED}{BOLD}FAIL{RESET}")
        print()

    return passed, total


# ── Live capture with LWN-Simulator ───────────────────────────────────────────

def api_post(endpoint: str, data: dict) -> dict:
    """POST to LWN-Simulator REST API."""
    import urllib.request, urllib.error
    body = json.dumps(data).encode()
    req = urllib.request.Request(
        f"{LWN_API}/{endpoint}",
        data=body,
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    try:
        with urllib.request.urlopen(req, timeout=5) as resp:
            return json.loads(resp.read())
    except Exception as e:
        return {"error": str(e)}


def api_get(endpoint: str) -> dict:
    """GET from LWN-Simulator REST API."""
    import urllib.request
    try:
        with urllib.request.urlopen(f"{LWN_API}/{endpoint}", timeout=5) as resp:
            return json.loads(resp.read())
    except Exception as e:
        return {"error": str(e)}


def wait_for_simulator(timeout: int = 15) -> bool:
    """Poll until LWN-Simulator's /api/status responds."""
    import urllib.request, urllib.error
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            urllib.request.urlopen(f"{LWN_API}/status", timeout=2)
            return True
        except Exception:
            time.sleep(0.5)
    return False


def run_live_capture(
    tmpdir: Path, duration: int = 30, profiles: list[str] | None = None
) -> Path | None:
    """Start LWN-Simulator, configure devices from selected profiles,
    capture Semtech UDP/1700 traffic, run semtech_extractor.py.

    profiles: list of keys from LIVE_DEVICE_PROFILES (default: ["normal","replay"])
    Returns path to sessions JSON, or None on failure.
    """
    if profiles is None:
        profiles = ["normal", "replay"]
    print(f"\n{BOLD}{'─'*64}{RESET}")
    print(f"{BOLD}  Live Capture — LWN-Simulator + tshark ({duration}s){RESET}")
    print(f"{BOLD}{'─'*64}{RESET}\n")

    if not LWN_SIM_BIN.exists():
        print(f"  {fail(f'LWN-Simulator binary not found: {LWN_SIM_BIN}')}")
        print("  Build it first: cd LWN-Simulator-main && go build -o ../lwnsimulator ./cmd/main.go")
        return None

    if not TSHARK.exists():
        print(f"  {fail(f'tshark not found: {TSHARK}')}")
        return None

    # Copy config.json to tmpdir so LWN-Sim finds it
    config_src = LWN_SIM_DIR / "config.json"
    config_dst = tmpdir / "config.json"
    shutil.copy(config_src, config_dst)

    # Start LWN-Simulator
    print("  Starting LWN-Simulator...")
    sim_proc = subprocess.Popen(
        [str(LWN_SIM_BIN)],
        cwd=str(tmpdir),
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    if not wait_for_simulator(timeout=15):
        print(f"  {fail('LWN-Simulator did not start within 15s')}")
        sim_proc.kill()
        return None
    print(f"  {ok('LWN-Simulator started (pid {sim_proc.pid})')}")

    # Configure gateway pointing to localhost:1700
    gw_resp = api_post("add-gateway", {
        "info": {
            "name": "ValidatorGW",
            "macAddress": "aabbccddeeff0000",
            "active": True,
            "typeGateway": False,
            "ip": "127.0.0.1",
            "port": "1700",
            "keepAlive": 10,
            "location": {"latitude": 50.0, "longitude": 14.0, "altitude": 200},
        }
    })
    print(f"  Gateway: {gw_resp}")

    # Configure devices from selected profiles
    for profile_name in profiles:
        if profile_name not in LIVE_DEVICE_PROFILES:
            print(f"  {warn(f'Unknown profile {profile_name!r}, skipping')}")
            continue
        resp = api_post("add-device", {"info": LIVE_DEVICE_PROFILES[profile_name]})
        print(f"  Device [{profile_name}]: {resp}")

    # Start simulator
    api_get("start")
    print("  Simulator running. Starting tshark capture...")

    pcap_path = tmpdir / "sim_capture.pcap"
    tshark_proc = subprocess.Popen([
        str(TSHARK), "-i", LOOPBACK,
        "-f", "udp port 1700",
        "-w", str(pcap_path),
    ], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

    print(f"  Capturing for {duration}s on {LOOPBACK} (UDP port 1700)...")
    time.sleep(duration)

    tshark_proc.send_signal(signal.SIGINT)
    tshark_proc.wait(timeout=5)
    api_get("stop")
    sim_proc.terminate()
    sim_proc.wait(timeout=5)

    if not pcap_path.exists() or pcap_path.stat().st_size == 0:
        print(f"  {fail(f'No PCAP captured — is {LOOPBACK} the right loopback interface?')}")
        return None

    print(f"  {ok(f'Captured {pcap_path.stat().st_size} bytes')}")

    # Run semtech_extractor on the capture
    sessions_path = tmpdir / "sim_sessions.json"
    result = subprocess.run(
        [sys.executable, str(SEMTECH_EXTRACTOR), str(pcap_path), str(sessions_path)],
        env={**os.environ, "TSHARK": str(TSHARK)},
        capture_output=True, text=True,
    )
    print(result.stdout)
    if result.returncode != 0:
        print(f"  {fail('semtech_extractor failed')}: {result.stderr[:300]}")
        return None

    return sessions_path


def run_pcap_validation(pcap: str, tmpdir: Path) -> None:
    """Validate an existing Semtech PCAP through the full pipeline."""
    print(f"\n{BOLD}{'─'*64}{RESET}")
    print(f"{BOLD}  PCAP Validation — {Path(pcap).name}{RESET}")
    print(f"{BOLD}{'─'*64}{RESET}\n")

    sessions_path = tmpdir / "pcap_sessions.json"
    result = subprocess.run(
        [sys.executable, str(SEMTECH_EXTRACTOR), pcap, str(sessions_path)],
        env={**os.environ, "TSHARK": str(TSHARK)},
        capture_output=True, text=True,
    )
    print(result.stdout)
    if result.returncode != 0 or not sessions_path.exists():
        print(f"  {fail('semtech_extractor failed')}")
        return

    _validate_sessions_file(sessions_path, tmpdir, label=Path(pcap).stem)


def _validate_sessions_file(
    sessions_path: Path, tmpdir: Path, label: str = "capture"
) -> None:
    """Run scenario_builder + Scyther on a sessions JSON and report."""
    with open(sessions_path) as f:
        data = json.load(f)

    anomaly_types = {a["type"] for a in data.get("anomalies", [])}
    print(f"  Anomaly types detected: {anomaly_types or 'none'}")

    spdl_path = tmpdir / f"{label}.spdl"
    ok_build = run_scenario_builder(sessions_path, spdl_path)
    if not ok_build:
        print(f"  {fail('scenario_builder produced no SPDL output')}")
        return

    spdl_text = spdl_path.read_text()
    proto_names = [
        l.split()[1].split("(")[0]
        for l in spdl_text.splitlines()
        if l.startswith("protocol ")
    ]
    print(f"  SPDL protocols generated: {proto_names}")

    _, scyther_out = run_scyther(spdl_path)
    traces = save_attack_traces(spdl_path, tmpdir)
    claims = parse_scyther_output(scyther_out)

    fail_claims = [c for c in claims if c["result"] == "Fail"]
    ok_claims   = [c for c in claims if c["result"] == "Ok"]
    print(f"  Scyther: {len(ok_claims)} Ok, {len(fail_claims)} Fail")
    for c in fail_claims:
        print(f"    {RED}Fail{RESET}  {c['protocol']},{c['role']}  {c['claim_id']}")
    if traces:
        print(f"  Attack traces: {len(traces)} image(s) → {tmpdir / 'attack_traces'}/")
    print()


# ── LAF mode helper ────────────────────────────────────────────────────────────

def _run_laf_mode(args, tmpdir: Path) -> None:
    """Delegate to laf_integration.py as a subprocess."""
    laf_script = HERE / "laf_integration.py"
    if not laf_script.exists():
        print(f"  {fail('laf_integration.py not found — cannot run --laf mode')}")
        return

    print(f"\n{BOLD}{'─'*64}{RESET}")
    print(f"{BOLD}  LAF Mode — Controlled Attack Injection{RESET}")
    print(f"{BOLD}{'─'*64}{RESET}\n")

    cmd = [
        sys.executable, str(laf_script),
        "--attacks", args.laf_attacks,
        "--duration", str(args.duration),
        "--output", str(tmpdir / "laf_output"),
    ]
    if args.verbose:
        cmd.append("--verbose")

    result = subprocess.run(cmd, text=True)
    # laf_integration.py handles its own output; just surface the return code
    if result.returncode != 0:
        print(f"  {fail('laf_integration.py exited with code ' + str(result.returncode))}")


# ── Main ───────────────────────────────────────────────────────────────────────

def main() -> None:
    parser = argparse.ArgumentParser(
        description="LoRaWAN-SecFW pipeline validation via LWN-Simulator."
    )
    parser.add_argument("--live",    action="store_true",
                        help="Run LWN-Simulator + tshark live capture")
    parser.add_argument("--pcap",    metavar="FILE",
                        help="Validate an existing Semtech UDP/1700 PCAP")
    parser.add_argument("--duration", type=int, default=30,
                        help="Live capture duration in seconds (default: 30)")
    parser.add_argument("--devices", default="normal,replay",
                        metavar="PROFILES",
                        help=f"Comma-separated device profiles for --live mode "
                             f"(default: normal,replay). "
                             f"Available: {', '.join(VALID_PROFILES)}")
    parser.add_argument("--output", metavar="DIR",
                        help="Persist output (sessions JSON, SPDL, attack_traces/) to this directory")
    parser.add_argument("--verbose", action="store_true",
                        help="Print all Scyther claim lines")
    parser.add_argument("--laf", action="store_true",
                        help="Inject controlled attack traffic via LAF instead of "
                             "(or in addition to) the LWN-Simulator live capture")
    parser.add_argument("--laf-attacks", default="all", metavar="ATTACKS",
                        help="Comma-separated attack types for --laf mode (default: all). "
                             "Choices: baseline, fcnt_replay, fcnt_rollback, "
                             "devnonce_replay, rogue_ns, default_key, fuzzing")
    args = parser.parse_args()

    tmpdir = Path(tempfile.mkdtemp(prefix="lwn_validator_"))
    print(f"\n{BOLD}LoRaWAN-SecFW Pipeline Validator{RESET}")
    print(f"Temp dir: {tmpdir}")
    print(f"Scyther:  {SCYTHER}")

    try:
        # Always run synthetic validation
        passed, total = run_synthetic_tests(tmpdir, verbose=args.verbose)

        # Optionally run live capture
        if args.live:
            selected = [p.strip() for p in args.devices.split(",") if p.strip()]
            live_sessions = run_live_capture(tmpdir, duration=args.duration, profiles=selected)
            if live_sessions:
                _validate_sessions_file(live_sessions, tmpdir, label="live")

        # Optionally run LAF attack injection
        if args.laf:
            _run_laf_mode(args, tmpdir)

        # Optionally validate a provided PCAP
        if args.pcap:
            run_pcap_validation(args.pcap, tmpdir)

        # Final summary
        print(f"\n{BOLD}{'═'*64}{RESET}")
        status = (f"{GREEN}{BOLD}ALL PASSED{RESET}" if passed == total
                  else f"{RED}{BOLD}{passed}/{total} PASSED{RESET}")
        print(f"  Synthetic validation: {status}")
        print(f"{BOLD}{'═'*64}{RESET}\n")

        sys.exit(0 if passed == total else 1)

    finally:
        if args.output:
            out = Path(args.output)
            out.mkdir(parents=True, exist_ok=True)
            for item in tmpdir.iterdir():
                dest = out / item.name
                if item.is_dir():
                    if dest.exists():
                        shutil.rmtree(dest)
                    shutil.copytree(item, dest)
                else:
                    shutil.copy2(item, dest)
            print(f"Output saved to: {out}/")
        shutil.rmtree(tmpdir, ignore_errors=True)


if __name__ == "__main__":
    main()
