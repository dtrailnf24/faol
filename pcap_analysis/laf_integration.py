#!/usr/bin/env python3
"""
laf_integration.py — LAF-based controlled attack traffic → formal analysis pipeline.

Generates LoRaWAN traffic with configurable per-attack injection, then feeds
it through the existing pipeline: semtech_extractor.py → scenario_builder.py → Scyther.

Strategy:
  1. For each selected attack, send crafted Semtech UDP/1700 packets to 127.0.0.1:1700.
  2. tshark passively captures on lo0 → PCAP.
  3. semtech_extractor.py parses PCAP → sessions JSON.
  4. scenario_builder.py generates Scyther SPDL.
  5. Scyther evaluates security claims; results are printed.

Packet generation tries LAF's UdpSender.py first (if ~/laf is present and the
Go shared library is compiled).  Falls back to laf_attacks/payloads.py (pure
Python, no Go bindings required).

Usage:
  python3 laf_integration.py [options]

  --attacks baseline,fcnt_replay,...   Attacks to inject (default: all)
  --exclude rogue_ns,...               Attacks to skip
  --duration SECONDS                   tshark capture time (default: 30)
  --output DIR                         Where to write PCAP / JSON / SPDL
  --with-simulator                     Also run LWN-Simulator for realistic background traffic
  --sim-devices PROFILES               Simulator device profiles (default: normal)
  --verbose                            Print every Scyther claim line
  --list-attacks                       Print available attack names and exit

Available attacks:
  baseline        Normal OTAA join + data uplinks (no anomaly)
  fcnt_replay     Repeat same FCnt → FCnt_fcnt_repeat
  fcnt_rollback   Lower FCnt after high one → FCnt_fcnt_decrease
  devnonce_replay Same DevNonce in two JoinReqs → DevNonce_Replay
  rogue_ns        JoinAccept with no prior JoinReq → Unsolicited_JoinAccept
  default_key     Join with publicly-known AppKey → uses_default_key
"""

import argparse
import json
import os
import shutil
import signal
import socket
import subprocess
import sys
import tempfile
import time
from pathlib import Path

# Windows console defaults to cp1252 which can't encode Unicode arrows etc.
if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
if hasattr(sys.stderr, "reconfigure"):
    sys.stderr.reconfigure(encoding="utf-8", errors="replace")

# ── Paths ─────────────────────────────────────────────────────────────────────

HERE      = Path(__file__).parent
ROOT      = HERE.parent
import platform as _platform
_sys = _platform.system()

_scyther_fallback = {
    "Windows": str(Path.home() / "scyther/gui/Scyther/scyther-w32.exe"),
    "Linux":   str(Path.home() / "scyther/gui/Scyther/scyther-linux64"),
}.get(_sys, str(Path.home() / "scyther/gui/Scyther/scyther-mac-arm"))

_tshark_fallback = {
    "Windows": r"C:\Program Files\Wireshark\tshark.exe",
    "Linux":   "/usr/bin/tshark",
}.get(_sys, "/Applications/Wireshark.app/Contents/MacOS/tshark")

SCYTHER  = Path(os.environ.get("SCYTHER_BIN", shutil.which("scyther") or _scyther_fallback))
TSHARK   = Path(os.environ.get("TSHARK", shutil.which("tshark") or _tshark_fallback))
LOOPBACK = os.environ.get("LOOPBACK_IFACE", {
    "Linux":   "lo",
    "Windows": r"\Device\NPF_Loopback",
}.get(_sys, "lo0"))
SEMTECH_EXTRACTOR = HERE / "semtech_extractor.py"
SCENARIO_BUILDER  = HERE / "scenario_builder.py"
LWN_SIM_RUN       = Path.home() / "lwnsim_run"
LWN_SIM_BIN       = LWN_SIM_RUN / ("lwnsimulator.exe" if _sys == "Windows" else "lwnsimulator")
LWN_SIM_DIR       = ROOT / "LWN-Simulator-main"
LWN_API           = "http://127.0.0.1:8000/api"

# ── Colours ───────────────────────────────────────────────────────────────────

GREEN  = "\033[32m"
RED    = "\033[31m"
YELLOW = "\033[33m"
CYAN   = "\033[36m"
RESET  = "\033[0m"
BOLD   = "\033[1m"

def _ok(msg):   return f"{GREEN}✓{RESET} {msg}"
def _fail(msg): return f"{RED}✗{RESET} {msg}"
def _warn(msg): return f"{YELLOW}!{RESET} {msg}"
def _info(msg): return f"{CYAN}>{RESET} {msg}"

# ── Attack registry ───────────────────────────────────────────────────────────

ALL_ATTACKS = [
    "baseline",
    "fcnt_replay",
    "fcnt_rollback",
    "devnonce_replay",
    "rogue_ns",
    "default_key",
]

# ── UDP sender ────────────────────────────────────────────────────────────────

def _udp_send(packet: bytes, host: str = "127.0.0.1", port: int = 1700) -> None:
    """Fire-and-forget UDP send."""
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        sock.sendto(packet, (host, port))
    finally:
        sock.close()


def _send_sequence(label: str, packets: list, delay: float = 0.4) -> None:
    """Send a list of (name, bytes) packets with a short delay between each."""
    for name, pkt in packets:
        print(f"    → {name}")
        _udp_send(pkt)
        time.sleep(delay)


# ── Attack implementations ────────────────────────────────────────────────────

def inject_baseline(payloads, verbose):
    print(f"\n  {BOLD}[baseline]{RESET} Normal OTAA join + 3 data uplinks")
    pkts = payloads.packets_baseline()
    _send_sequence("baseline", pkts)


def inject_fcnt_replay(payloads, verbose):
    print(f"\n  {BOLD}[fcnt_replay]{RESET} Repeat FCnt=10 twice → FCnt_fcnt_repeat")
    pkts = payloads.packets_fcnt_replay(fcnt=10)
    _send_sequence("fcnt_replay", pkts)


def inject_fcnt_rollback(payloads, verbose):
    print(f"\n  {BOLD}[fcnt_rollback]{RESET} Send FCnt=50 then FCnt=5 → FCnt_fcnt_decrease")
    pkts = payloads.packets_fcnt_rollback(high=50, low=5)
    _send_sequence("fcnt_rollback", pkts)


def inject_devnonce_replay(payloads, verbose):
    print(f"\n  {BOLD}[devnonce_replay]{RESET} Same DevNonce 0xABCD in two JoinReqs → DevNonce_Replay")
    pkts = payloads.packets_devnonce_replay(devnonce=0xABCD)
    _send_sequence("devnonce_replay", pkts)


def inject_rogue_ns(payloads, verbose):
    print(f"\n  {BOLD}[rogue_ns]{RESET} JoinAccept with no prior JoinReq → Unsolicited_JoinAccept")
    pkts = payloads.packets_rogue_ns()
    _send_sequence("rogue_ns", pkts)


def inject_default_key(payloads, verbose):
    print(f"\n  {BOLD}[default_key]{RESET} Join with publicly-known Semtech AppKey")
    pkts = payloads.packets_default_key()
    _send_sequence("default_key", pkts)


ATTACK_FUNCS = {
    "baseline":        inject_baseline,
    "fcnt_replay":     inject_fcnt_replay,
    "fcnt_rollback":   inject_fcnt_rollback,
    "devnonce_replay": inject_devnonce_replay,
    "rogue_ns":        inject_rogue_ns,
    "default_key":     inject_default_key,
}

# ── Pipeline helpers ──────────────────────────────────────────────────────────

def run_semtech_extractor(pcap: Path, sessions_out: Path) -> bool:
    result = subprocess.run(
        [sys.executable, str(SEMTECH_EXTRACTOR), str(pcap), str(sessions_out)],
        env={**os.environ, "TSHARK": str(TSHARK)},
        capture_output=True, text=True,
    )
    if result.stdout:
        for line in result.stdout.strip().splitlines():
            print(f"    {line}")
    if result.returncode != 0:
        print(f"  {_fail('semtech_extractor failed')}: {result.stderr[:300]}")
        return False
    return sessions_out.exists() and sessions_out.stat().st_size > 0


def run_scenario_builder(sessions: Path, spdl_out: Path) -> bool:
    result = subprocess.run(
        [sys.executable, str(SCENARIO_BUILDER), str(sessions), str(spdl_out)],
        capture_output=True, text=True,
    )
    if result.stdout:
        for line in result.stdout.strip().splitlines():
            print(f"    {line}")
    return spdl_out.exists() and spdl_out.stat().st_size > 0


def run_scyther(spdl: Path) -> tuple[int, str]:
    result = subprocess.run(
        [str(SCYTHER), str(spdl)],
        capture_output=True, text=True,
    )
    return result.returncode, result.stdout + result.stderr


def parse_claims(scyther_out: str) -> list[dict]:
    """Parse Scyther tab-separated claim lines.

    Scyther embeds ANSI colour codes in the result field
    ("[32mOk[0m" / "[31mFail[0m"), so we use `in` rather than equality.

    Format: claim  <Protocol,Role>  <ClaimID>  <Term>  <Result>  <Details>
    """
    claims = []
    for line in scyther_out.splitlines():
        if not line.startswith("claim"):
            continue
        parts = line.split("\t")
        if len(parts) < 5:
            continue
        proto_role = parts[1].strip()
        result_raw = parts[4].strip()
        result     = "Ok" if "Ok" in result_raw else "Fail"

        comma = proto_role.rfind(",")
        protocol = proto_role[:comma] if comma >= 0 else proto_role
        role     = proto_role[comma+1:] if comma >= 0 else ""

        claims.append({
            "protocol": protocol,
            "role":     role,
            "claim_id": parts[2].strip(),
            "term":     parts[3].strip(),
            "result":   result,
        })
    return claims


# ── LWN-Simulator helpers ─────────────────────────────────────────────────────

# Minimal device profiles for simulator background traffic.
# Keys come from lwn_validator.py LIVE_DEVICE_PROFILES.
_SIM_PROFILES = {
    "normal": {
        "name": "ED_Normal",
        "devEUI": "aabbccddeeff0099",
        "appKey": "00000000000000000000000000000099",
        "devAddr": "00000000",
        "nwkSKey": "00000000000000000000000000000000",
        "appSKey": "00000000000000000000000000000000",
        "status": {"joined": False, "active": True},
        "configuration": {
            "region": 1, "supportedOtaa": True, "sendInterval": 8,
            "ackTimeout": 5, "nbRetransmission": 1,
            "supportedClassB": False, "supportedClassC": False,
            "supportedADR": False, "supportedFragment": False,
            "dataRate": 0, "rx1DROffset": 0, "disableFCntDown": False,
            "range": 100.0,
        },
        "location": {"latitude": 50.0, "longitude": 14.0, "altitude": 200},
    },
    "fast": {
        "name": "ED_Fast",
        "devEUI": "aabbccddeeff00aa",
        "appKey": "000000000000000000000000000000aa",
        "devAddr": "00000000",
        "nwkSKey": "00000000000000000000000000000000",
        "appSKey": "00000000000000000000000000000000",
        "status": {"joined": False, "active": True},
        "configuration": {
            "region": 1, "supportedOtaa": True, "sendInterval": 4,
            "ackTimeout": 5, "nbRetransmission": 1,
            "supportedClassB": False, "supportedClassC": False,
            "supportedADR": False, "supportedFragment": False,
            "dataRate": 0, "rx1DROffset": 0, "disableFCntDown": False,
            "range": 100.0,
        },
        "location": {"latitude": 50.1, "longitude": 14.1, "altitude": 200},
    },
    # ABP device — pre-provisioned keys, no join needed, sends data immediately.
    # DevAddr aabb0001 avoids conflict with DEVICE_A (01020304) / DEVICE_B (05060708).
    "abp": {
        "name": "ED_ABP",
        "devEUI": "aabbccddeeff00bb",
        "appKey": "00000000000000000000000000000000",
        "devAddr": "aabb0001",
        "nwkSKey": "deadbeefdeadbeefdeadbeefdeadbeef",
        "appSKey": "cafebabecafebabecafebabecafebabe",
        "status": {
            "joined": True, "active": True,
            # infoUplink must include fport; without it the lorawan lib panics on nil FPort
            "infoUplink": {"fport": 1, "fcnt": 0},
            "mtype": "UnConfirmedDataUp",
            "payload": "DEADBEEF",
            "base64": False,
        },
        "configuration": {
            "region": 1, "supportedOtaa": False, "sendInterval": 5,
            "ackTimeout": 5, "nbRetransmission": 1,
            "supportedClassB": False, "supportedClassC": False,
            "supportedADR": False, "supportedFragment": False,
            "dataRate": 0, "rx1DROffset": 0, "disableFCntDown": False,
            "range": 100.0,
        },
        "location": {"latitude": 50.0, "longitude": 14.0, "altitude": 200},
    },
}


def _api_post(endpoint: str, data: dict) -> dict:
    import urllib.request, urllib.error
    body = json.dumps(data).encode()
    req = urllib.request.Request(
        f"{LWN_API}/{endpoint}", data=body,
        headers={"Content-Type": "application/json"}, method="POST",
    )
    try:
        with urllib.request.urlopen(req, timeout=5) as resp:
            return json.loads(resp.read())
    except Exception as e:
        return {"error": str(e)}


def _api_get(endpoint: str) -> dict:
    import urllib.request
    try:
        with urllib.request.urlopen(f"{LWN_API}/{endpoint}", timeout=5) as resp:
            return json.loads(resp.read())
    except Exception as e:
        return {"error": str(e)}


def _wait_for_simulator(timeout: int = 15) -> bool:
    import urllib.request, urllib.error
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            urllib.request.urlopen(f"{LWN_API}/status", timeout=2)
            return True
        except Exception:
            time.sleep(0.5)
    return False


def start_simulator(outdir: Path, profiles: list[str]) -> subprocess.Popen | None:
    """Start LWN-Simulator, configure gateway + devices, return the process."""
    if not LWN_SIM_BIN.exists():
        print(f"  {_warn(f'LWN-Simulator binary not found: {LWN_SIM_BIN} — skipping simulator')}")
        return None

    # Kill any leftover simulator processes so ports 8000/8001 are free
    subprocess.run(["pkill", "-f", "lwnsimulator"], capture_output=True)
    time.sleep(1.0)

    # Clean stale simulator data so it doesn't conflict
    import shutil
    stale = LWN_SIM_RUN / "lwnsim_data"
    if stale.exists():
        shutil.rmtree(stale)

    print(f"  Starting LWN-Simulator ({', '.join(profiles)} profiles)...")
    proc = subprocess.Popen(
        [str(LWN_SIM_BIN)],
        cwd=str(LWN_SIM_RUN),   # run from its own dir where config.json lives
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )

    if not _wait_for_simulator(timeout=15):
        print(f"  {_warn('LWN-Simulator did not respond in 15s — continuing without it')}")
        proc.kill()
        return None

    print(f"  {_ok(f'LWN-Simulator up (pid {proc.pid})')}")

    # The simulator uses a single global BridgeAddress (NS endpoint).
    # This MUST be set before add-gateway; otherwise add-gateway returns "No gateway bridge configured".
    _api_post("bridge/save", {"ip": "127.0.0.1", "port": "1700"})

    _api_post("add-gateway", {"info": {
        "name": "LAF_GW",
        "macAddress": "aabbccddeeff0000",
        "active": True,
        "typeGateway": False,
        "keepAlive": 10,
        "location": {"latitude": 50.0, "longitude": 14.0, "altitude": 200},
    }})

    for profile in profiles:
        if profile not in _SIM_PROFILES:
            print(f"  {_warn(f'Unknown sim profile {profile!r}, skipping')}")
            continue
        _api_post("add-device", {"info": _SIM_PROFILES[profile]})
        print(f"  {_ok(f'Simulator device [{profile}] configured')}")

    _api_get("start")
    return proc


# ── tshark capture ────────────────────────────────────────────────────────────

def start_tshark(pcap_path: Path) -> subprocess.Popen:
    return subprocess.Popen(
        [str(TSHARK), "-i", LOOPBACK, "-f", "udp port 1700", "-w", str(pcap_path)],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )


# ── Main ──────────────────────────────────────────────────────────────────────

def parse_args():
    parser = argparse.ArgumentParser(
        description="LAF-based LoRaWAN attack traffic → formal analysis pipeline.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=f"Available attacks: {', '.join(ALL_ATTACKS)}",
    )
    parser.add_argument(
        "--attacks", default="all", metavar="ATTACKS",
        help="Comma-separated attacks to run (default: all). "
             f"Choices: {', '.join(ALL_ATTACKS)}",
    )
    parser.add_argument(
        "--exclude", default="", metavar="ATTACKS",
        help="Comma-separated attacks to skip.",
    )
    parser.add_argument(
        "--duration", type=int, default=30,
        help="tshark capture duration in seconds (default: 30). "
             "Injection happens in the first few seconds; rest is buffer.",
    )
    parser.add_argument(
        "--output", metavar="DIR", default=None,
        help="Write PCAP, sessions JSON, and SPDL here (default: temp dir).",
    )
    parser.add_argument(
        "--verbose", action="store_true",
        help="Print all Scyther claim lines.",
    )
    parser.add_argument(
        "--list-attacks", action="store_true",
        help="Print available attack names and exit.",
    )
    parser.add_argument(
        "--with-simulator", action="store_true",
        help="Also run LWN-Simulator to generate realistic background LoRaWAN "
             "traffic alongside the injected attacks.",
    )
    parser.add_argument(
        "--sim-devices", default="normal", metavar="PROFILES",
        help="Comma-separated LWN-Simulator device profiles when --with-simulator "
             f"is set (default: normal). Available: {', '.join(_SIM_PROFILES)}",
    )
    return parser.parse_args()


def main():
    args = parse_args()

    if args.list_attacks:
        print("Available attacks:")
        for name in ALL_ATTACKS:
            print(f"  {name}")
        return

    # Resolve attack list
    if args.attacks.lower() == "all":
        selected = list(ALL_ATTACKS)
    else:
        selected = [a.strip() for a in args.attacks.split(",") if a.strip()]
    if args.exclude:
        excluded = {a.strip() for a in args.exclude.split(",") if a.strip()}
        selected = [a for a in selected if a not in excluded]

    unknown = [a for a in selected if a not in ALL_ATTACKS]
    if unknown:
        print(f"Unknown attacks: {', '.join(unknown)}")
        print(f"Available: {', '.join(ALL_ATTACKS)}")
        sys.exit(1)

    if not selected:
        print("No attacks selected. Exiting.")
        return

    # Output directory
    if args.output:
        outdir = Path(args.output)
        outdir.mkdir(parents=True, exist_ok=True)
        _tmpdir_obj = None
    else:
        import tempfile as _tf
        _tmpdir_obj = _tf.TemporaryDirectory(prefix="laf_integration_")
        outdir = Path(_tmpdir_obj.name)

    pcap_path     = outdir / "laf_capture.pcap"
    sessions_path = outdir / "laf_sessions.json"
    spdl_path     = outdir / "laf_scenario.spdl"

    sim_profiles = [p.strip() for p in args.sim_devices.split(",") if p.strip()] \
                   if args.with_simulator else []

    # Print header
    print(f"\n{BOLD}LoRaWAN-SecFW — LAF Integration{RESET}")
    print(f"  Attacks:    {', '.join(selected)}")
    print(f"  Duration:   {args.duration}s capture")
    print(f"  Output:     {outdir}")
    print(f"  Simulator:  {'enabled (' + ', '.join(sim_profiles) + ')' if args.with_simulator else 'disabled'}")
    print(f"  Scyther:    {SCYTHER}")

    if not TSHARK.exists():
        print(f"\n{_fail(f'tshark not found: {TSHARK}')}")
        print("Install Wireshark or set TSHARK env var.")
        sys.exit(1)

    if not SCYTHER.exists():
        print(f"\n{_fail(f'Scyther not found: {SCYTHER}')}")
        sys.exit(1)

    # Import pure-Python payloads module
    sys.path.insert(0, str(HERE))
    import laf_attacks.payloads as payloads

    # ── Phase 1: tshark capture + injection ───────────────────────────────────
    print(f"\n{BOLD}{'─'*64}{RESET}")
    print(f"{BOLD}  Phase 1 — Capturing + Injecting{RESET}")
    print(f"{BOLD}{'─'*64}{RESET}")

    print(f"\n  Starting tshark on {LOOPBACK}:1700...")
    tshark_proc = start_tshark(pcap_path)
    time.sleep(1.0)  # let tshark open the capture file before anything sends

    sim_proc = None
    if args.with_simulator:
        print()
        sim_proc = start_simulator(outdir, sim_profiles)
        time.sleep(2.0)  # let simulator emit a few JoinReqs before attack injection

    try:
        for attack_name in selected:
            fn = ATTACK_FUNCS[attack_name]
            fn(payloads, args.verbose)
            time.sleep(0.5)  # brief gap between attack types

        # Let remaining duration act as buffer
        injection_time = len(selected) * 3  # rough estimate
        remaining = max(0, args.duration - injection_time - 1)
        if remaining > 0:
            print(f"\n  Waiting {remaining}s for packet delivery...")
            time.sleep(remaining)

    finally:
        tshark_proc.send_signal(signal.SIGINT)
        try:
            tshark_proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            tshark_proc.kill()

        if sim_proc is not None:
            _api_get("stop")
            sim_proc.terminate()
            try:
                sim_proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                sim_proc.kill()
            print(f"  {_ok('LWN-Simulator stopped')}")

    if not pcap_path.exists() or pcap_path.stat().st_size == 0:
        print(f"\n{_fail(f'No PCAP captured — is {LOOPBACK} the right loopback interface?')}")
        print(f"Try: sudo tshark -i {LOOPBACK} -f 'udp port 1700' -w /tmp/test.pcap")
        sys.exit(1)

    print(f"\n  {_ok(f'Captured {pcap_path.stat().st_size:,} bytes → {pcap_path.name}')}")

    # ── Phase 2: Extract sessions ─────────────────────────────────────────────
    print(f"\n{BOLD}{'─'*64}{RESET}")
    print(f"{BOLD}  Phase 2 — Extracting sessions (semtech_extractor.py){RESET}")
    print(f"{BOLD}{'─'*64}{RESET}\n")

    if not run_semtech_extractor(pcap_path, sessions_path):
        print(_fail("semtech_extractor produced no output."))
        sys.exit(1)

    with open(sessions_path) as f:
        sessions_data = json.load(f)

    anomaly_types = {a["type"] for a in sessions_data.get("anomalies", [])}
    n_devices     = len(sessions_data.get("devices", {}))
    n_anomalies   = len(sessions_data.get("anomalies", []))
    print(f"\n  Devices seen:    {n_devices}")
    print(f"  Anomalies found: {n_anomalies}  →  {anomaly_types or 'none'}")

    # ── Phase 3: Generate SPDL ────────────────────────────────────────────────
    print(f"\n{BOLD}{'─'*64}{RESET}")
    print(f"{BOLD}  Phase 3 — Generating Scyther SPDL (scenario_builder.py){RESET}")
    print(f"{BOLD}{'─'*64}{RESET}\n")

    if not run_scenario_builder(sessions_path, spdl_path):
        print(_fail("scenario_builder produced no SPDL."))
        sys.exit(1)

    spdl_text  = spdl_path.read_text()
    proto_names = [
        line.split()[1].split("(")[0]
        for line in spdl_text.splitlines()
        if line.startswith("protocol ")
    ]
    print(f"\n  SPDL protocols: {proto_names}")

    # ── Phase 4: Scyther ─────────────────────────────────────────────────────
    print(f"\n{BOLD}{'─'*64}{RESET}")
    print(f"{BOLD}  Phase 4 — Scyther Formal Verification{RESET}")
    print(f"{BOLD}{'─'*64}{RESET}\n")

    retcode, scyther_out = run_scyther(spdl_path)
    claims = parse_claims(scyther_out)

    if not claims:
        print(f"  {_warn('Scyther produced no claim output.')}")
        if args.verbose:
            print(scyther_out[:500])
    else:
        fail_claims = [c for c in claims if c["result"] == "Fail"]
        ok_claims   = [c for c in claims if c["result"] == "Ok"]
        print(f"  Claims: {len(ok_claims)} Ok,  {len(fail_claims)} Fail\n")

        if args.verbose:
            for c in claims:
                colour = GREEN if c["result"] == "Ok" else RED
                print(f"  {colour}{c['result']:4}{RESET}  {c['protocol']:30} {c['role']:15} {c['claim_id']}")
        else:
            for c in fail_claims:
                print(f"  {RED}Fail{RESET}  {c['protocol']:30} {c['role']:15} {c['claim_id']}")
            for c in ok_claims:
                print(f"  {GREEN}Ok  {RESET}  {c['protocol']:30} {c['role']:15} {c['claim_id']}")

    # ── Summary ───────────────────────────────────────────────────────────────
    print(f"\n{BOLD}{'─'*64}{RESET}")
    print(f"{BOLD}  Summary{RESET}")
    print(f"{BOLD}{'─'*64}{RESET}")
    print(f"\n  Attacks injected:  {', '.join(selected)}")
    print(f"  Anomalies detected: {n_anomalies}  ({', '.join(anomaly_types) if anomaly_types else 'none'})")
    print(f"  Scyther protocols:  {len(proto_names)}")
    print(f"  Security claims:    {len(claims)}  "
          f"({len([c for c in claims if c['result']=='Ok'])} Ok / "
          f"{len([c for c in claims if c['result']=='Fail'])} Fail)")

    # Expected anomaly → attack mapping check
    _check_anomaly_coverage(selected, anomaly_types)

    print(f"\n  Output files:")
    print(f"    PCAP:     {pcap_path}")
    print(f"    Sessions: {sessions_path}")
    print(f"    SPDL:     {spdl_path}")
    print()

    if _tmpdir_obj:
        # Keep temp dir alive until now so user can inspect if needed
        pass


def _check_anomaly_coverage(attacks_run: list, detected: set):
    """Print a per-attack coverage check."""
    expected_map = {
        "fcnt_replay":     {"FCnt_fcnt_repeat"},
        "fcnt_rollback":   {"FCnt_fcnt_decrease"},
        "devnonce_replay": {"DevNonce_Replay"},
        "rogue_ns":        {"Unsolicited_JoinAccept"},
        "default_key":     {"uses_default_key"},
    }
    print(f"\n  Anomaly coverage check:")
    for attack in attacks_run:
        if attack not in expected_map:
            continue
        expected = expected_map[attack]
        found = expected & detected
        if found:
            print(f"    {GREEN}✓{RESET} [{attack}] detected: {', '.join(found)}")
        else:
            note = ""
            if attack == "rogue_ns" and any(
                a in attacks_run for a in ("baseline", "fcnt_replay", "fcnt_rollback", "devnonce_replay")
            ):
                note = " (run rogue_ns alone — extractor requires zero JoinReqs in capture)"
            print(f"    {YELLOW}!{RESET} [{attack}] expected {expected} — not detected{note}")


if __name__ == "__main__":
    main()
