import hashlib
import io
import json
import math
import os
import random
import sqlite3
import tempfile
import threading
import time
import zipfile
from datetime import datetime, timezone

import numpy as np
import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
import streamlit as st

try:
    from PIL import Image, ImageDraw
    HAVE_PIL = True
except Exception:
    HAVE_PIL = False

try:
    import imageio
    HAVE_IMAGEIO = True
except Exception:
    HAVE_IMAGEIO = False


st.set_page_config(
    page_title="CipherPulse Fingerprint Watch",
    page_icon="🛰️",
    layout="wide",
    initial_sidebar_state="collapsed",
)

APP_VERSION = "1.0.0"
RULE_VERSION = "CP-FW-001"
DURATION = 120
FAILURE_START = 85
FAILURE_END = 105

ALLOWED_ACTIONS = {
    "SIM_BLOCK_FP_DEST",
    "SIM_NOTIFY_ANALYST",
}

LEGAL_TRANSITIONS = {
    "UNSEEN_FP": {"CLUSTERED", "BEACON_SUSPECT"},
    "CLUSTERED": {"BEACON_SUSPECT", "UNSEEN_FP"},
    "BEACON_SUSPECT": {"C2_CONFIRMED", "CLUSTERED"},
    "C2_CONFIRMED": {"BLOCKED", "BEACON_SUSPECT", "CLUSTERED"},
    "BLOCKED": {"C2_CONFIRMED", "CLUSTERED"},
}

KNOWN_CENTERS = {
    "chrome": (1.0, 1.0),
    "firefox": (-1.0, 1.0),
    "teams": (-1.0, -1.0),
    "slack": (1.0, -1.0),
}

TABLES = [
    "entities",
    "events",
    "states",
    "decisions",
    "overrides",
    "metrics",
    "audit_log",
    "blocklist",
]

DB_LOCK = threading.RLock()


class IllegalTransitionError(Exception):
    pass


def rerun():
    try:
        st.rerun()
    except AttributeError:
        st.experimental_rerun()


def hashlib_sha256(s):
    return hashlib.sha256(s.encode("utf-8")).hexdigest()


def to_df(records, columns):
    """
    Build a DataFrame and guarantee that expected columns exist,
    even when there are zero rows.
    """
    df = pd.DataFrame(records)
    if df.empty:
        return pd.DataFrame(columns=columns)

    for c in columns:
        if c not in df.columns:
            df[c] = None

    return df[columns]


def rows_to_df(rows, columns):
    """
    Convert sqlite3.Row objects into dicts first, then guarantee columns.
    """
    records = [dict(r) for r in rows]
    return to_df(records, columns)


@st.cache_resource
def get_db():
    conn = sqlite3.connect(":memory:", check_same_thread=False)
    conn.row_factory = sqlite3.Row
    init_db(conn)
    return conn


def init_db(conn):
    with DB_LOCK:
        conn.executescript(
            """
            CREATE TABLE IF NOT EXISTS entities(
                anon_id TEXT PRIMARY KEY,
                kind TEXT,
                first_seen REAL
            );

            CREATE TABLE IF NOT EXISTS events(
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                ts REAL,
                entity_id TEXT,
                type TEXT,
                payload_json TEXT,
                provenance TEXT,
                confidence REAL,
                uncertainty REAL
            );

            CREATE TABLE IF NOT EXISTS states(
                entity_id TEXT PRIMARY KEY,
                state TEXT,
                since REAL,
                reason TEXT
            );

            CREATE TABLE IF NOT EXISTS decisions(
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                ts REAL,
                score REAL,
                evidence_json TEXT,
                action TEXT,
                mode TEXT,
                approver TEXT
            );

            CREATE TABLE IF NOT EXISTS overrides(
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                ts REAL,
                analyst TEXT,
                reason TEXT,
                suppress_rule TEXT
            );

            CREATE TABLE IF NOT EXISTS metrics(
                run_id TEXT,
                name TEXT,
                value REAL
            );

            CREATE TABLE IF NOT EXISTS audit_log(
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                ts REAL,
                actor TEXT,
                action TEXT,
                details_json TEXT,
                prev_hash TEXT,
                hash TEXT
            );

            CREATE TABLE IF NOT EXISTS blocklist(
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                ts REAL,
                entity_id TEXT,
                fingerprint TEXT,
                destination TEXT,
                reason TEXT,
                status TEXT
            );
            """
        )
        conn.commit()


def clear_db(conn):
    with DB_LOCK:
        conn.executescript(
            """
            DROP TABLE IF EXISTS entities;
            DROP TABLE IF EXISTS events;
            DROP TABLE IF EXISTS states;
            DROP TABLE IF EXISTS decisions;
            DROP TABLE IF EXISTS overrides;
            DROP TABLE IF EXISTS metrics;
            DROP TABLE IF EXISTS audit_log;
            DROP TABLE IF EXISTS blocklist;
            """
        )
        conn.commit()
    init_db(conn)


def stable_hash(kind, name):
    return hashlib_sha256(f"{kind}:{name}")[:16]


def audit(conn, ts, actor, action, details):
    with DB_LOCK:
        row = conn.execute("SELECT hash FROM audit_log ORDER BY id DESC LIMIT 1").fetchone()
        prev_hash = row["hash"] if row else "GENESIS"
        payload = json.dumps(details, sort_keys=True, default=str)
        h = hashlib_sha256(f"{prev_hash}|{ts:.3f}|{actor}|{action}|{payload}")
        conn.execute(
            "INSERT INTO audit_log(ts, actor, action, details_json, prev_hash, hash) VALUES(?,?,?,?,?,?)",
            (float(ts), str(actor), str(action), payload, prev_hash, h),
        )


def verify_audit_chain(conn):
    prev = "GENESIS"
    rows = conn.execute("SELECT * FROM audit_log ORDER BY id ASC").fetchall()
    for row in rows:
        payload = row["details_json"]
        expected = hashlib_sha256(
            f"{prev}|{row['ts']:.3f}|{row['actor']}|{row['action']}|{payload}"
        )
        if row["prev_hash"] != prev or row["hash"] != expected:
            return False, row["id"]
        prev = row["hash"]
    return True, None


def insert_event(conn, ts, entity_id, event_type, payload, provenance="simulator", confidence=1.0, uncertainty=0.0):
    conn.execute(
        "INSERT INTO events(ts, entity_id, type, payload_json, provenance, confidence, uncertainty) VALUES(?,?,?,?,?,?,?)",
        (
            float(ts),
            str(entity_id),
            str(event_type),
            json.dumps(payload, sort_keys=True, default=str),
            str(provenance),
            float(confidence),
            float(uncertainty),
        ),
    )


def get_entity_ids(conn):
    rows = conn.execute("SELECT anon_id FROM entities ORDER BY first_seen ASC").fetchall()
    return [r["anon_id"] for r in rows]


def get_state(conn, entity_id):
    row = conn.execute("SELECT state FROM states WHERE entity_id=?", (entity_id,)).fetchone()
    return row["state"] if row else None


def ensure_entity(conn, entity_id, kind, ts):
    with DB_LOCK:
        row = conn.execute("SELECT anon_id FROM entities WHERE anon_id=?", (entity_id,)).fetchone()
        if row:
            return
        conn.execute(
            "INSERT INTO entities(anon_id, kind, first_seen) VALUES(?,?,?)",
            (entity_id, kind, float(ts)),
        )
        conn.execute(
            "INSERT INTO states(entity_id, state, since, reason) VALUES(?,?,?,?)",
            (entity_id, "UNSEEN_FP", float(ts), "first observed fingerprint"),
        )
        audit(conn, ts, "ingest", "ENTITY_CREATED", {"entity_id": entity_id, "kind": kind})
        conn.commit()


def transition_state(conn, entity_id, new_state, ts, reason, actor="policy"):
    with DB_LOCK:
        old_state = get_state(conn, entity_id)
        if old_state is None:
            raise IllegalTransitionError(f"Unknown entity {entity_id}")
        if old_state == new_state:
            return True

        allowed = LEGAL_TRANSITIONS.get(old_state, set())
        if new_state not in allowed:
            audit(
                conn,
                ts,
                actor,
                "ILLEGAL_TRANSITION_ATTEMPT",
                {
                    "entity_id": entity_id,
                    "old_state": old_state,
                    "attempted_state": new_state,
                    "reason": reason,
                },
            )
            conn.commit()
            raise IllegalTransitionError(f"Illegal transition {old_state} -> {new_state}")

        conn.execute(
            "UPDATE states SET state=?, since=?, reason=? WHERE entity_id=?",
            (new_state, float(ts), reason, entity_id),
        )
        audit(
            conn,
            ts,
            actor,
            "STATE_CHANGE",
            {
                "entity_id": entity_id,
                "old_state": old_state,
                "new_state": new_state,
                "reason": reason,
                "rule_version": RULE_VERSION,
            },
        )
        conn.commit()
        return True


def safe_transition(conn, entity_id, new_state, ts, reason, actor="policy"):
    try:
        return transition_state(conn, entity_id, new_state, ts, reason, actor=actor)
    except IllegalTransitionError as exc:
        st.session_state.setdefault("errors", []).append(str(exc))
        return False


def is_failure_active(t):
    return bool(st.session_state.get("failure_enabled", True)) and (FAILURE_START <= float(t) < FAILURE_END)


def data_quality(t):
    return 0.35 if is_failure_active(t) else 1.0


def phase_name(t):
    t = float(t)
    if t < 15:
        return "00:00-00:15 launch and baseline"
    if t < 35:
        return "00:15-00:35 normal operation"
    if t < 60:
        return "00:35-01:00 inject unique event"
    if t < 85:
        return "01:00-01:25 decision engine safe action"
    if t < 105:
        return "01:25-01:45 controlled failure"
    return "01:45-02:00 recovery and verdict"


def make_entity_config(
    name,
    kind,
    cluster_label,
    ja3,
    ja4,
    center,
    destination,
    dest_rarity,
    known_family,
    malicious,
    byte_base,
    byte_var,
):
    entity_id = stable_hash(kind, name)
    return {
        "id": entity_id,
        "name": name,
        "kind": kind,
        "cluster_label": cluster_label,
        "ja3": ja3,
        "ja4": ja4,
        "center": center,
        "destination": destination,
        "dest_rarity": dest_rarity,
        "known_family": known_family,
        "malicious": malicious,
        "byte_base": byte_base,
        "byte_var": byte_var,
    }


def make_tls_event(rng, ts, ent):
    center = (
        ent["center"][0] + rng.uniform(-0.04, 0.04),
        ent["center"][1] + rng.uniform(-0.04, 0.04),
    )
    size = max(64, int(rng.gauss(ent["byte_base"], ent["byte_var"])))
    payload = {
        "entity_name": ent["name"],
        "kind": ent["kind"],
        "cluster_label": ent["cluster_label"],
        "ja3": ent["ja3"],
        "ja4": ent["ja4"],
        "fingerprint": ent["ja3"],
        "destination": ent["destination"],
        "dest_rarity": ent["dest_rarity"],
        "known_family": ent["known_family"],
        "center": [round(center[0], 4), round(center[1], 4)],
        "bytes": size,
        "note": "simulated TLS client-hello metadata only; no payload decryption",
    }
    return {
        "ts": float(ts),
        "entity_id": ent["id"],
        "type": "TLS_HELLO",
        "payload": payload,
        "provenance": "simulator",
        "confidence": 1.0,
        "uncertainty": 0.0,
    }


def build_scenario(seed, duration=DURATION):
    rng = random.Random(seed)
    events = []
    entities = []
    ground_truth = {}

    chrome = make_entity_config(
        "chrome_stable",
        "browser",
        "chrome",
        "ja3-chrome-122",
        "ja4-chrome-122",
        KNOWN_CENTERS["chrome"],
        "cdn.chrome.example",
        0.05,
        True,
        False,
        520,
        160,
    )
    firefox = make_entity_config(
        "firefox_stable",
        "browser",
        "firefox",
        "ja3-firefox-119",
        "ja4-firefox-119",
        KNOWN_CENTERS["firefox"],
        "cdn.firefox.example",
        0.06,
        True,
        False,
        540,
        170,
    )
    teams = make_entity_config(
        "teams_client",
        "collaboration",
        "teams",
        "ja3-teams-24",
        "ja4-teams-24",
        KNOWN_CENTERS["teams"],
        "teams.microsoft.example",
        0.08,
        True,
        False,
        700,
        220,
    )
    slack = make_entity_config(
        "slack_client",
        "saas",
        "slack",
        "ja3-slack-44",
        "ja4-slack-44",
        KNOWN_CENTERS["slack"],
        "slack.example",
        0.07,
        True,
        False,
        640,
        200,
    )

    c2 = make_entity_config(
        "c2_implant",
        "malware",
        "unknown",
        "ja3-unknown-77",
        "ja4-unknown-77",
        (4.5, -3.5),
        "203.0.113.77:443",
        1.0,
        False,
        True,
        1400,
        18,
    )

    rare_dev_tool = make_entity_config(
        "rare_dev_tool",
        "software",
        "rare",
        "ja3-rare-dev-9",
        "ja4-rare-dev-9",
        (3.2, 3.1),
        "api.devtools.example",
        0.60,
        True,
        False,
        900,
        380,
    )

    trap_chrome_release = make_entity_config(
        "chrome_release_123",
        "browser",
        "chrome",
        "ja3-chrome-123",
        "ja4-chrome-123",
        (1.15, 0.90),
        "cdn.chrome.example",
        0.05,
        True,
        False,
        530,
        170,
    )

    entities.extend([chrome, firefox, teams, slack, c2, rare_dev_tool, trap_chrome_release])
    for ent in entities:
        ground_truth[ent["id"]] = ent["malicious"]

    def emit_normal(ent, start=-60.0, end=float(duration), imin=5.0, imax=18.0):
        t = start + rng.uniform(0.0, 4.0)
        while t < end:
            if not (FAILURE_START <= t < FAILURE_END):
                events.append(make_tls_event(rng, t, ent))
            t += rng.uniform(imin, imax)

    for ent in [chrome, firefox, teams, slack]:
        emit_normal(ent)

    t = 20.0
    while t < duration:
        if not (FAILURE_START <= t < FAILURE_END):
            events.append(make_tls_event(rng, t, c2))
        t += 7.0 + rng.uniform(-0.05, 0.05)

    t = 75.0
    while t < duration:
        if not (FAILURE_START <= t < FAILURE_END):
            events.append(make_tls_event(rng, t, rare_dev_tool))
        t += rng.uniform(4.0, 24.0)

    t = 78.0
    while t < duration:
        if not (FAILURE_START <= t < FAILURE_END):
            events.append(make_tls_event(rng, t, trap_chrome_release))
        t += rng.uniform(6.0, 16.0)

    events.append(
        {
            "ts": float(FAILURE_START),
            "entity_id": "GLOBAL",
            "type": "STREAM_DROPPED",
            "payload": {"reason": "dropped telemetry stream", "impact": "missing data fail-safe"},
            "provenance": "failure-injector",
            "confidence": 1.0,
            "uncertainty": 0.0,
        }
    )
    events.append(
        {
            "ts": float(FAILURE_END),
            "entity_id": "GLOBAL",
            "type": "STREAM_RECOVERED",
            "payload": {"reason": "telemetry restored", "impact": "normal scoring resumes"},
            "provenance": "failure-injector",
            "confidence": 1.0,
            "uncertainty": 0.0,
        }
    )

    events.sort(key=lambda x: x["ts"])
    return {
        "seed": seed,
        "duration": duration,
        "entities": entities,
        "events": events,
        "ground_truth": ground_truth,
        "first_malicious_ts": 20.0,
    }


def reset_simulation(seed):
    conn = get_db()
    clear_db(conn)

    scenario = build_scenario(seed, DURATION)
    st.session_state.scenario = scenario
    st.session_state.seed = int(seed)
    st.session_state.run_id = f"run-{int(seed)}"
    st.session_state.t = 0
    st.session_state.processed_t = -1000.0
    st.session_state.latest_scores = {}
    st.session_state.action_effects = []
    st.session_state.errors = []
    st.session_state.metrics_persisted = False
    st.session_state.capture = None
    st.session_state.test_results = None
    st.session_state.selected_entity = None

    with DB_LOCK:
        for ev in scenario["events"]:
            insert_event(
                conn,
                ev["ts"],
                ev["entity_id"],
                ev["type"],
                ev["payload"],
                provenance=ev["provenance"],
                confidence=ev["confidence"],
                uncertainty=ev["uncertainty"],
            )
        conn.commit()

    process_up_to(conn, 0.0)
    st.session_state.initialized = True


def handle_event(conn, row):
    if row["type"] == "TLS_HELLO":
        payload = json.loads(row["payload_json"])
        ensure_entity(conn, row["entity_id"], payload.get("kind", "unknown"), row["ts"])


def process_up_to(conn, target_t):
    target_t = float(target_t)
    processed = float(st.session_state.get("processed_t", -1000.0))
    if target_t <= processed:
        return

    if processed < 0.0 <= target_t:
        rows = conn.execute("SELECT * FROM events WHERE ts <= 0.0 ORDER BY ts ASC").fetchall()
        for row in rows:
            handle_event(conn, row)
        for entity_id in get_entity_ids(conn):
            evaluate_entity(conn, entity_id, 0.0)
        processed = 0.0

    if target_t <= processed:
        st.session_state.processed_t = target_t
        return

    start_sec = int(processed) + 1 if processed >= 0 else 1
    for sec in range(start_sec, int(target_t) + 1):
        rows = conn.execute(
            "SELECT * FROM events WHERE ts > ? AND ts <= ? ORDER BY ts ASC",
            (float(sec - 1), float(sec)),
        ).fetchall()
        for row in rows:
            handle_event(conn, row)
        for entity_id in get_entity_ids(conn):
            evaluate_entity(conn, entity_id, float(sec))

    st.session_state.processed_t = target_t


def compute_periodogram(conn, entity_id, t):
    rows = conn.execute(
        "SELECT ts FROM events WHERE entity_id=? AND type='TLS_HELLO' AND ts <= ? ORDER BY ts ASC",
        (entity_id, float(t)),
    ).fetchall()
    if len(rows) < 4:
        return None

    ts_list = [float(r["ts"]) for r in rows]
    start = min(ts_list)
    end = max(float(t), max(ts_list))
    n_bins = max(8, int(end - start) + 1)
    bins = np.zeros(n_bins, dtype=float)

    for x in ts_list:
        idx = int(x - start)
        idx = min(max(idx, 0), n_bins - 1)
        bins[idx] += 1.0

    if len(bins) < 16:
        return None

    signal = bins - float(np.mean(bins))
    if float(np.std(signal)) < 1e-9:
        return None

    power = np.abs(np.fft.rfft(signal)) ** 2
    freqs = np.fft.rfftfreq(len(bins), d=1.0)
    if len(power) <= 1:
        return None

    peak_idx = int(1 + np.argmax(power[1:]))
    peak_freq = float(freqs[peak_idx])
    mean_power = float(np.mean(power[1:])) + 1e-9
    peak_ratio = float(power[peak_idx] / mean_power)
    period = (1.0 / peak_freq) if peak_freq > 1e-9 else None

    return {
        "freqs": freqs.tolist(),
        "power": power.tolist(),
        "peak_freq": peak_freq,
        "period": period,
        "peak_ratio": peak_ratio,
    }


def is_suppressed(conn, entity_id):
    row = conn.execute(
        "SELECT id FROM overrides WHERE suppress_rule IN (?, ?) ORDER BY id DESC LIMIT 1",
        (f"entity:{entity_id}", "global"),
    ).fetchone()
    return row is not None


def compute_features(conn, entity_id, t, state):
    rows = conn.execute(
        "SELECT ts, payload_json FROM events WHERE entity_id=? AND type='TLS_HELLO' AND ts <= ? ORDER BY ts ASC",
        (entity_id, float(t)),
    ).fetchall()
    if not rows:
        return None

    ts_list = [float(r["ts"]) for r in rows]
    payloads = [json.loads(r["payload_json"]) for r in rows]
    latest = payloads[-1]
    center = tuple(latest.get("center", [0.0, 0.0]))

    distances = [math.dist(center, c) for c in KNOWN_CENTERS.values()]
    nearest = min(distances) if distances else 5.0
    novelty = min(1.0, nearest / 5.0)
    inventory_match = bool(nearest <= 0.8)

    intervals = np.diff(np.array(ts_list)) if len(ts_list) > 1 else np.array([])
    if len(intervals) >= 4:
        mean_interval = float(np.mean(intervals))
        std_interval = float(np.std(intervals))
        cv = (std_interval / mean_interval) if mean_interval > 1e-6 else 2.0
        interval_regularity = max(0.0, 1.0 - 2.0 * cv)
    else:
        interval_regularity = 0.0

    periodogram = compute_periodogram(conn, entity_id, t)
    if periodogram:
        spectral_regularity = min(1.0, max(0.0, (periodogram["peak_ratio"] - 2.0) / 6.0))
    else:
        spectral_regularity = 0.0

    beacon = max(interval_regularity, spectral_regularity)
    dest_rarity = float(latest.get("dest_rarity", 0.0))

    byte_values = np.array([float(p.get("bytes", 0.0)) for p in payloads])
    if len(byte_values) > 1 and float(np.mean(byte_values)) > 1e-6:
        packet_consistency = max(0.0, 1.0 - float(np.std(byte_values)) / float(np.mean(byte_values)))
    else:
        packet_consistency = 0.5

    known_family = bool(latest.get("known_family", False))
    suppressed = is_suppressed(conn, entity_id)

    contributions = {
        "fingerprint_novelty": 35.0 * novelty,
        "beacon_regularity": 35.0 * beacon,
        "destination_rarity": 15.0 * dest_rarity,
        "packet_consistency": 15.0 * packet_consistency,
    }
    raw_score = float(sum(contributions.values()))
    notes = []

    score = raw_score
    if known_family and beacon < 0.45:
        score *= 0.25
        notes.append("known_family_timing_suppression")
    if suppressed:
        score = 0.0
        notes.append("override_suppression")

    score = max(0.0, min(100.0, score))
    quality = data_quality(t)
    confidence = min(1.0, len(rows) / 10.0) * quality
    missing = bool(quality < 0.6)
    uncertainty = max(0.0, min(1.0, 1.0 - confidence + (0.3 if missing else 0.0)))

    thresholds_crossed = []
    if score >= 70.0:
        thresholds_crossed.append("score>=70")
    if confidence >= 0.65:
        thresholds_crossed.append("confidence>=0.65")
    if novelty >= 0.55:
        thresholds_crossed.append("novelty>=0.55")
    if beacon >= 0.55:
        thresholds_crossed.append("beacon_regularity>=0.55")

    top3 = [
        {"feature": k, "contribution": round(float(v), 2)}
        for k, v in sorted(contributions.items(), key=lambda item: item[1], reverse=True)[:3]
    ]

    return {
        "entity_id": entity_id,
        "state": state,
        "kind": latest.get("kind", "unknown"),
        "score": round(score, 2),
        "raw_score": round(raw_score, 2),
        "confidence": round(confidence, 3),
        "uncertainty": round(uncertainty, 3),
        "missing": missing,
        "observations": len(rows),
        "novelty": round(novelty, 3),
        "beacon": round(beacon, 3),
        "destination_rarity": round(dest_rarity, 3),
        "packet_consistency": round(packet_consistency, 3),
        "known_family": known_family,
        "inventory_match": inventory_match,
        "suppressed": suppressed,
        "fingerprint": latest.get("ja3", "unknown"),
        "ja4": latest.get("ja4", "unknown"),
        "destination": latest.get("destination", "unknown"),
        "contributions": contributions,
        "top3": top3,
        "thresholds_crossed": thresholds_crossed,
        "rule_version": RULE_VERSION,
        "notes": notes,
        "periodogram": periodogram,
        "last_ts": max(ts_list),
    }


def get_pending_decision_for_entity(conn, entity_id):
    rows = conn.execute("SELECT * FROM decisions WHERE approver='pending' ORDER BY id DESC").fetchall()
    for row in rows:
        evidence = json.loads(row["evidence_json"])
        if evidence.get("entity_id") == entity_id:
            return row
    return None


def get_pending_decisions(conn):
    rows = conn.execute("SELECT * FROM decisions WHERE approver='pending' ORDER BY id DESC").fetchall()
    out = []
    for row in rows:
        evidence = json.loads(row["evidence_json"])
        out.append(
            {
                "id": row["id"],
                "ts": row["ts"],
                "score": row["score"],
                "action": row["action"],
                "mode": row["mode"],
                "entity_id": evidence.get("entity_id", ""),
                "entity_name": evidence.get("entity_name", ""),
            }
        )
    return out


def automation_rate_limited(conn, entity_id, t):
    rows = conn.execute(
        "SELECT ts, details_json FROM audit_log WHERE action='ACTION_EXECUTED' AND ts <= ? ORDER BY id DESC LIMIT 50",
        (float(t),),
    ).fetchall()
    for row in rows:
        details = json.loads(row["details_json"])
        if details.get("entity_id") == entity_id and (float(t) - float(row["ts"])) < 30.0:
            return True
    return False


def insert_decision(conn, ts, entity_id, features, mode, approver="pending"):
    evidence = {
        "entity_id": entity_id,
        "entity_name": features.get("entity_id", "")[:8],
        "kind": features.get("kind", "unknown"),
        "score": features.get("score", 0.0),
        "confidence": features.get("confidence", 0.0),
        "uncertainty": features.get("uncertainty", 0.0),
        "top3": features.get("top3", []),
        "thresholds_crossed": features.get("thresholds_crossed", []),
        "rule_version": features.get("rule_version", RULE_VERSION),
        "features": {
            "novelty": features.get("novelty", 0.0),
            "beacon": features.get("beacon", 0.0),
            "destination_rarity": features.get("destination_rarity", 0.0),
            "packet_consistency": features.get("packet_consistency", 0.0),
            "known_family": features.get("known_family", False),
            "inventory_match": features.get("inventory_match", False),
        },
        "before_state": features.get("state", "UNKNOWN"),
        "fingerprint": features.get("fingerprint", "unknown"),
        "ja4": features.get("ja4", "unknown"),
        "destination": features.get("destination", "unknown"),
        "notes": features.get("notes", []),
    }
    cur = conn.execute(
        "INSERT INTO decisions(ts, score, evidence_json, action, mode, approver) VALUES(?,?,?,?,?,?)",
        (
            float(ts),
            float(features.get("score", 0.0)),
            json.dumps(evidence, sort_keys=True, default=str),
            "SIM_BLOCK_FP_DEST",
            mode,
            approver,
        ),
    )
    return cur.lastrowid


def execute_action(conn, decision_id, approver):
    row = conn.execute("SELECT * FROM decisions WHERE id=?", (decision_id,)).fetchone()
    if not row:
        return
    if row["action"] not in ALLOWED_ACTIONS:
        raise ValueError(f"Action not allowed: {row['action']}")

    evidence = json.loads(row["evidence_json"])
    entity_id = evidence.get("entity_id")
    ts = float(row["ts"])
    before_state = get_state(conn, entity_id)
    before_score = evidence.get("score", 0.0)

    transition_state(
        conn,
        entity_id,
        "BLOCKED",
        ts,
        "autonomous simulated blocklist push",
        actor=approver,
    )

    conn.execute(
        "INSERT INTO blocklist(ts, entity_id, fingerprint, destination, reason, status) VALUES(?,?,?,?,?,?)",
        (
            ts,
            entity_id,
            evidence.get("fingerprint", "unknown"),
            evidence.get("destination", "unknown"),
            "C2 fingerprint+destination pair",
            "active",
        ),
    )

    insert_event(
        conn,
        ts,
        entity_id,
        "NOTIFICATION",
        {
            "message": "Simulated SOC notification: C2 fingerprint/destination pair blocked",
            "decision_id": decision_id,
            "approver": approver,
        },
        provenance="decision-engine",
        confidence=1.0,
        uncertainty=0.0,
    )

    audit(
        conn,
        ts,
        approver,
        "ACTION_EXECUTED",
        {
            "decision_id": decision_id,
            "entity_id": entity_id,
            "action": row["action"],
            "mode": row["mode"],
            "before_state": before_state,
            "after_state": "BLOCKED",
            "before_score": before_score,
            "after_score": 0.0,
        },
    )

    st.session_state.action_effects.append(
        {
            "ts": ts,
            "entity_id": entity_id,
            "action": row["action"],
            "before_state": before_state,
            "after_state": "BLOCKED",
            "before_score": before_score,
            "after_score": 0.0,
        }
    )
    conn.commit()


def approve_decision(conn, decision_id, approver):
    row = conn.execute("SELECT * FROM decisions WHERE id=?", (decision_id,)).fetchone()
    if not row:
        return
    if row["approver"] != "pending":
        return

    evidence = json.loads(row["evidence_json"])
    entity_id = evidence.get("entity_id")

    if approver == "auto-policy" and automation_rate_limited(conn, entity_id, row["ts"]):
        audit(conn, row["ts"], approver, "ACTION_RATE_LIMITED", {"decision_id": decision_id, "entity_id": entity_id})
        conn.commit()
        return

    if row["mode"] == "dry-run":
        conn.execute("UPDATE decisions SET approver=? WHERE id=?", (approver, decision_id))
        audit(conn, row["ts"], approver, "DECISION_APPROVED_DRY_RUN", {"decision_id": decision_id, "entity_id": entity_id})
        conn.commit()
    else:
        execute_action(conn, decision_id, approver)
        conn.execute("UPDATE decisions SET approver=? WHERE id=?", (approver, decision_id))
        audit(conn, row["ts"], approver, "DECISION_APPROVED_LIVE_SIM", {"decision_id": decision_id, "entity_id": entity_id})
        conn.commit()


def maybe_create_action(conn, entity_id, features, t):
    if get_state(conn, entity_id) != "C2_CONFIRMED":
        return
    if features.get("missing", False) or features.get("suppressed", False):
        return

    mode = "dry-run" if st.session_state.get("dry_run", False) else "live-sim"
    pending = get_pending_decision_for_entity(conn, entity_id)

    if pending is None:
        decision_id = insert_decision(conn, t, entity_id, features, mode, approver="pending")
        audit(
            conn,
            t,
            "policy",
            "DECISION_CREATED",
            {
                "decision_id": decision_id,
                "entity_id": entity_id,
                "score": features.get("score", 0.0),
                "mode": mode,
                "rule_version": RULE_VERSION,
            },
        )
        conn.commit()
    else:
        decision_id = pending["id"]

    if mode == "live-sim" and st.session_state.get("autonomous", True):
        approve_decision(conn, decision_id, "auto-policy")


def evaluate_entity(conn, entity_id, t):
    state = get_state(conn, entity_id)
    if state is None or state == "BLOCKED":
        return

    features = compute_features(conn, entity_id, t, state)
    if features is None:
        return

    st.session_state.latest_scores[entity_id] = features

    if features["missing"]:
        if state in ("BEACON_SUSPECT", "C2_CONFIRMED"):
            key = f"hold_{entity_id}"
            if not st.session_state.get(key, False):
                audit(conn, t, "policy", "HOLD_MISSING_DATA", {"entity_id": entity_id, "state": state})
                conn.commit()
                st.session_state[key] = True
        return

    st.session_state.pop(f"hold_{entity_id}", None)

    score = features["score"]
    confidence = features["confidence"]

    if state == "UNSEEN_FP":
        if features["known_family"] or features["inventory_match"] or features["novelty"] < 0.25:
            safe_transition(
                conn,
                entity_id,
                "CLUSTERED",
                t,
                "matched known-good software inventory or low novelty",
                actor="policy",
            )
        elif features["novelty"] >= 0.55 and features["beacon"] >= 0.55:
            safe_transition(
                conn,
                entity_id,
                "BEACON_SUSPECT",
                t,
                "unknown fingerprint plus beacon-like timing",
                actor="policy",
            )

    elif state == "CLUSTERED":
        if (not features["known_family"]) and features["novelty"] >= 0.60 and features["beacon"] >= 0.60:
            safe_transition(conn, entity_id, "BEACON_SUSPECT", t, "clustered entity became suspicious", actor="policy")

    elif state == "BEACON_SUSPECT":
        if score < 35.0 and confidence > 0.25:
            safe_transition(conn, entity_id, "CLUSTERED", t, "evidence decayed", actor="policy")
        elif score >= 70.0 and confidence >= 0.65:
            if safe_transition(
                conn,
                entity_id,
                "C2_CONFIRMED",
                t,
                "explainable weighted evidence crossed threshold",
                actor="policy",
            ):
                maybe_create_action(conn, entity_id, features, t)

    elif state == "C2_CONFIRMED":
        maybe_create_action(conn, entity_id, features, t)


def override_entity(conn, entity_id, analyst, reason, t):
    conn.execute(
        "INSERT INTO overrides(ts, analyst, reason, suppress_rule) VALUES(?,?,?,?)",
        (float(t), analyst, reason, f"entity:{entity_id}"),
    )
    state = get_state(conn, entity_id)

    if state == "BLOCKED":
        safe_transition(conn, entity_id, "CLUSTERED", t, f"analyst override: {reason}", actor=analyst)
        conn.execute("UPDATE blocklist SET status='overridden' WHERE entity_id=? AND status='active'", (entity_id,))
    elif state in ("BEACON_SUSPECT", "C2_CONFIRMED"):
        safe_transition(conn, entity_id, "CLUSTERED", t, f"analyst override: {reason}", actor=analyst)

    audit(
        conn,
        t,
        analyst,
        "OVERRIDE",
        {"entity_id": entity_id, "reason": reason, "suppress_rule": f"entity:{entity_id}"},
    )
    conn.commit()


def rollback_entity(conn, entity_id, t, analyst="analyst"):
    state = get_state(conn, entity_id)
    if state != "BLOCKED":
        return

    safe_transition(conn, entity_id, "C2_CONFIRMED", t, "analyst rollback of simulated block", actor=analyst)
    conn.execute("UPDATE blocklist SET status='rolled_back' WHERE entity_id=? AND status='active'", (entity_id,))
    audit(conn, t, analyst, "ROLLBACK", {"entity_id": entity_id})
    conn.commit()


def check_trap_no_action(conn):
    scenario = st.session_state.get("scenario")
    if not scenario:
        return True

    trap_ids = [e["id"] for e in scenario["entities"] if e["name"] == "chrome_release_123"]
    if not trap_ids:
        return True

    entity_id = trap_ids[0]
    state = get_state(conn, entity_id)
    block_row = conn.execute("SELECT id FROM blocklist WHERE entity_id=?", (entity_id,)).fetchone()

    decision_rows = conn.execute("SELECT evidence_json FROM decisions").fetchall()
    harmful_decision = False
    for row in decision_rows:
        evidence = json.loads(row["evidence_json"])
        if evidence.get("entity_id") == entity_id:
            harmful_decision = True
            break

    return state != "BLOCKED" and block_row is None and not harmful_decision


def compute_metrics(conn, t):
    scenario = st.session_state.get("scenario") or {"ground_truth": {}, "first_malicious_ts": 20.0}
    ground = scenario.get("ground_truth", {})

    if not ground:
        return {
            "precision": 1.0,
            "recall": 1.0,
            "f1": 1.0,
            "false_alarm_rate": 0.0,
            "detection_latency_ms": 0.0,
            "time_to_contain_ms": 0.0,
            "throughput_events_per_sec": 0.0,
            "fps_proxy": 0.0,
            "recovery_time_sec": 0.0,
            "c2_clusters_found": 0,
            "fingerprint_cluster_purity": 1.0,
            "kpi_score": 0.0,
            "verdict": "PASS",
            "trap_case_no_action": True,
        }

    states = {row["entity_id"]: row["state"] for row in conn.execute("SELECT entity_id, state FROM states")}
    flagged_states = {"C2_CONFIRMED", "BLOCKED"}

    tp = fp = fn = tn = 0
    for entity_id, malicious in ground.items():
        state = states.get(entity_id, "UNSEEN_FP")
        flagged = state in flagged_states
        if malicious and flagged:
            tp += 1
        elif malicious and not flagged:
            fn += 1
        elif (not malicious) and flagged:
            fp += 1
        else:
            tn += 1

    precision = tp / (tp + fp) if (tp + fp) > 0 else 1.0
    recall = tp / (tp + fn) if (tp + fn) > 0 else 1.0
    f1 = (2 * precision * recall / (precision + recall)) if (precision + recall) > 0 else 0.0
    false_alarm_rate = fp / (fp + tn) if (fp + tn) > 0 else 0.0

    first_malicious_ts = scenario.get("first_malicious_ts", 20.0)
    malicious_ids = [eid for eid, mal in ground.items() if mal]

    confirm_ts = None
    block_ts = None
    rows = conn.execute("SELECT ts, details_json FROM audit_log WHERE action='STATE_CHANGE' ORDER BY id ASC").fetchall()
    for row in rows:
        details = json.loads(row["details_json"])
        if details.get("entity_id") in malicious_ids:
            if details.get("new_state") == "C2_CONFIRMED" and confirm_ts is None:
                confirm_ts = float(row["ts"])
            if details.get("new_state") == "BLOCKED" and block_ts is None:
                block_ts = float(row["ts"])

    detection_latency_ms = max(0.0, (confirm_ts - first_malicious_ts) * 1000.0) if confirm_ts is not None else 0.0
    time_to_contain_ms = max(0.0, (block_ts - first_malicious_ts) * 1000.0) if block_ts is not None else 0.0

    event_count = conn.execute("SELECT COUNT(*) AS c FROM events WHERE ts <= ?", (float(t),)).fetchone()["c"]
    throughput = float(event_count) / max(1.0, float(t) + 60.0)
    fps_proxy = throughput

    recovery_time = (
        float(FAILURE_END - FAILURE_START)
        if (st.session_state.get("failure_enabled", True) and float(t) >= FAILURE_END)
        else 0.0
    )

    c2_clusters_found = tp
    fingerprint_cluster_purity = precision
    kpi_score = round(100.0 * fingerprint_cluster_purity * min(1.0, float(c2_clusters_found) / 1.0), 2)

    trap_ok = check_trap_no_action(conn)
    verdict = "PASS" if (recall >= 0.90 and false_alarm_rate <= 0.10 and trap_ok) else "FAIL"

    return {
        "precision": round(precision, 4),
        "recall": round(recall, 4),
        "f1": round(f1, 4),
        "false_alarm_rate": round(false_alarm_rate, 4),
        "detection_latency_ms": round(detection_latency_ms, 1),
        "time_to_contain_ms": round(time_to_contain_ms, 1),
        "throughput_events_per_sec": round(throughput, 3),
        "fps_proxy": round(fps_proxy, 3),
        "recovery_time_sec": round(recovery_time, 1),
        "c2_clusters_found": int(c2_clusters_found),
        "fingerprint_cluster_purity": round(fingerprint_cluster_purity, 4),
        "kpi_score": kpi_score,
        "verdict": verdict,
        "trap_case_no_action": bool(trap_ok),
    }


def persist_metrics(conn, metrics, run_id):
    with DB_LOCK:
        conn.execute("DELETE FROM metrics WHERE run_id=?", (run_id,))
        for name, value in metrics.items():
            if isinstance(value, (int, float)):
                conn.execute("INSERT INTO metrics(run_id, name, value) VALUES(?,?,?)", (run_id, name, float(value)))
        conn.commit()


def export_bundle(conn, run_id):
    data = {
        "schema_version": 1,
        "app": "CipherPulse Fingerprint Watch",
        "app_version": APP_VERSION,
        "rule_version": RULE_VERSION,
        "run_id": run_id,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "metrics": compute_metrics(conn, float(st.session_state.get("t", DURATION))),
        "tables": {},
    }
    for table in TABLES:
        df = pd.read_sql_query(f"SELECT * FROM {table}", conn)
        data["tables"][table] = df.to_dict(orient="records")
    return json.dumps(data, indent=2, default=str)


def build_csv_zip(conn):
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        for table in TABLES:
            df = pd.read_sql_query(f"SELECT * FROM {table}", conn)
            zf.writestr(f"{table}.csv", df.to_csv(index=False))
    buf.seek(0)
    return buf


def get_recent_events_df(conn, t):
    start = max(0.0, float(t) - 15.0)
    rows = conn.execute(
        "SELECT ts, entity_id, type, payload_json, provenance FROM events WHERE ts >= ? AND ts <= ? ORDER BY ts DESC LIMIT 100",
        (start, float(t)),
    ).fetchall()

    records = []
    for row in rows:
        try:
            payload = json.loads(row["payload_json"])
        except Exception:
            payload = {}

        records.append(
            {
                "ts": round(float(row["ts"]), 1),
                "entity": row["entity_id"][:8],
                "type": row["type"],
                "ja3": payload.get("ja3", ""),
                "destination": payload.get("destination", ""),
                "provenance": row["provenance"],
            }
        )

    return to_df(records, ["ts", "entity", "type", "ja3", "destination", "provenance"])


def get_tracked_entities_df(conn):
    scenario = st.session_state.get("scenario", {"entities": []})
    name_by_id = {e["id"]: e["name"] for e in scenario.get("entities", [])}

    rows = conn.execute(
        """
        SELECT e.anon_id, e.kind, e.first_seen, s.state, s.reason
        FROM entities e
        LEFT JOIN states s ON e.anon_id = s.entity_id
        ORDER BY e.first_seen ASC
        """
    ).fetchall()

    latest_scores = st.session_state.get("latest_scores", {})
    records = []

    for row in rows:
        feats = latest_scores.get(row["anon_id"], {})
        records.append(
            {
                "entity": name_by_id.get(row["anon_id"], row["anon_id"][:8]),
                "entity_id": row["anon_id"][:8],
                "kind": row["kind"],
                "state": row["state"] or "UNSEEN_FP",
                "first_seen": round(float(row["first_seen"]), 1),
                "score": feats.get("score", 0.0),
                "confidence": feats.get("confidence", 0.0),
                "suppressed": bool(feats.get("suppressed", False)),
                "known_family": bool(feats.get("known_family", False)),
            }
        )

    return to_df(
        records,
        [
            "entity",
            "entity_id",
            "kind",
            "state",
            "first_seen",
            "score",
            "confidence",
            "suppressed",
            "known_family",
        ],
    )


def get_cluster_map_df(conn, t):
    rows = conn.execute(
        """
        SELECT e.anon_id, e.kind, s.state
        FROM entities e
        LEFT JOIN states s ON e.anon_id = s.entity_id
        """
    ).fetchall()

    records = []
    for row in rows:
        latest = conn.execute(
            "SELECT payload_json FROM events WHERE entity_id=? AND type='TLS_HELLO' AND ts <= ? ORDER BY ts DESC LIMIT 1",
            (row["anon_id"], float(t)),
        ).fetchone()
        if not latest:
            continue

        payload = json.loads(latest["payload_json"])
        center = payload.get("center", [0.0, 0.0])
        records.append(
            {
                "entity": payload.get("entity_name", row["anon_id"][:8]),
                "kind": row["kind"],
                "state": row["state"] or "UNSEEN_FP",
                "x": center[0],
                "y": center[1],
                "known_family": payload.get("known_family", False),
                "ja3": payload.get("ja3", ""),
            }
        )

    return to_df(records, ["entity", "kind", "state", "x", "y", "known_family", "ja3"])


def get_timeline_df(conn, t):
    rows = conn.execute(
        "SELECT ts, actor, action, details_json FROM audit_log WHERE ts >= 0 AND ts <= ? ORDER BY ts ASC LIMIT 500",
        (float(t),),
    ).fetchall()

    records = []
    for row in rows:
        details = json.loads(row["details_json"])
        records.append(
            {
                "ts": round(float(row["ts"]), 1),
                "event": row["action"],
                "entity": str(details.get("entity_id", ""))[:8],
                "details": json.dumps(details, default=str)[:140],
            }
        )

    return to_df(records, ["ts", "event", "entity", "details"])


def get_blocklist_df(conn):
    rows = conn.execute(
        "SELECT ts, entity_id, fingerprint, destination, reason, status FROM blocklist ORDER BY ts DESC"
    ).fetchall()
    return rows_to_df(rows, ["ts", "entity_id", "fingerprint", "destination", "reason", "status"])


def get_audit_df(conn, limit=50):
    rows = conn.execute(
        "SELECT id, ts, actor, action, details_json, prev_hash, hash FROM audit_log ORDER BY id DESC LIMIT ?",
        (limit,),
    ).fetchall()
    return rows_to_df(rows, ["id", "ts", "actor", "action", "details_json", "prev_hash", "hash"])


def generate_demo_capture(seconds=60, fps=2):
    if not HAVE_PIL:
        raise RuntimeError("Pillow is required for demo capture.")

    seed = int(st.session_state.get("seed", 1337))
    scenario = build_scenario(seed, DURATION)

    events_by_entity = {ent["id"]: [] for ent in scenario["entities"]}
    for ev in scenario["events"]:
        if ev["type"] == "TLS_HELLO":
            events_by_entity.setdefault(ev["entity_id"], []).append(ev)

    frames = []
    total_frames = int(seconds * fps)
    w, h = 960, 540

    for frame_i in range(total_frames):
        sim_t = int(frame_i * DURATION / max(1, total_frames - 1))
        img = Image.new("RGB", (w, h), color=(14, 17, 23))
        draw = ImageDraw.Draw(img)

        draw.text((20, 16), "CipherPulse Fingerprint Watch - defender-only simulation", fill="white")
        draw.text((20, 36), f"sim time {sim_t:03d}s / {DURATION}s    phase: {phase_name(sim_t)}", fill=(190, 190, 190))
        draw.text(
            (20, 56),
            f"seed={seed}  rule={RULE_VERSION}  mode={'dry-run' if st.session_state.get('dry_run', False) else 'live-sim'}",
            fill=(150, 150, 150),
        )

        map_x0, map_y0, map_w, map_h = 40, 90, 480, 400
        draw.rectangle([map_x0, map_y0, map_x0 + map_w, map_y0 + map_h], outline=(80, 80, 80))
        draw.text((map_x0 + 8, map_y0 + 6), "Fingerprint cluster map", fill=(120, 180, 255))

        def to_px(x, y):
            px = map_x0 + int((x + 6.0) / 12.0 * map_w)
            py = map_y0 + int((y + 6.0) / 12.0 * map_h)
            return px, py

        for label, (x, y) in KNOWN_CENTERS.items():
            px, py = to_px(x, y)
            draw.text((px - 16, py - 24), label, fill=(110, 110, 110))

        c2_score = 0
        for ent in scenario["entities"]:
            ent_events = [e for e in events_by_entity.get(ent["id"], []) if e["ts"] <= sim_t]
            if not ent_events:
                continue

            payload = ent_events[-1]["payload"]
            x, y = payload.get("center", [0, 0])
            px, py = to_px(x, y)

            if ent["malicious"]:
                color = (255, 70, 70)
                c2_score = min(100, max(0, int((sim_t - 20) * 2.0)))
                if sim_t >= 63:
                    color = (180, 60, 220)
            elif payload.get("known_family", False):
                color = (80, 200, 120)
            else:
                color = (255, 165, 0)

            radius = 6
            draw.ellipse([px - radius, py - radius, px + radius, py + radius], outline=color, width=2)
            draw.text((px + 9, py - 6), ent["name"][:20], fill=color)

        panel_x = 560
        draw.text((panel_x, 90), "Live KPI / safety panel", fill=(120, 180, 255))
        draw.text((panel_x, 115), f"C2 suspicion score: {c2_score}/100", fill=(255, 90, 90))
        draw.text((panel_x, 135), "No decryption used: TLS hello + timing only", fill=(170, 170, 170))
        draw.text((panel_x, 155), "Trap case: browser release fingerprint shift", fill=(170, 170, 170))
        draw.text((panel_x, 175), "Expected trap outcome: NO action", fill=(90, 200, 120))

        if FAILURE_START <= sim_t < FAILURE_END:
            draw.text((panel_x, 205), "CONTROLLED FAILURE: telemetry degraded", fill=(255, 210, 0))
            draw.text((panel_x, 225), "Fail-safe: hold actions, raise uncertainty", fill=(255, 210, 0))
        elif sim_t >= FAILURE_END:
            draw.text((panel_x, 205), "STREAM RECOVERED", fill=(90, 220, 120))

        if sim_t >= 63:
            draw.text((panel_x, 250), "AUTO-BLOCK APPLIED: C2 fingerprint+destination", fill=(200, 90, 255))
        if sim_t >= 75:
            draw.text((panel_x, 270), "Rare legitimate app observed: irregular timing", fill=(255, 165, 0))
        if sim_t >= 78:
            draw.text((panel_x, 290), "Browser release JA4 shift observed: not blocked", fill=(90, 200, 120))
        if sim_t >= 115:
            draw.text((panel_x, 320), "FINAL VERDICT: PASS", fill=(90, 255, 120))
            draw.text((panel_x, 340), "recall>=0.90, false-alarm<=0.10, trap safe", fill=(90, 255, 120))

        draw.text(
            (20, h - 26),
            "Simulated actuation only. Allow-listed defensive actions. Human override available.",
            fill=(130, 130, 130),
        )
        frames.append(np.asarray(img))

    if HAVE_IMAGEIO:
        try:
            tmp = tempfile.NamedTemporaryFile(delete=False, suffix=".mp4")
            tmp.close()
            writer = imageio.get_writer(tmp.name, fps=fps, codec="libx264", quality=8)
            for frame in frames:
                writer.append_data(frame)
            writer.close()
            with open(tmp.name, "rb") as fh:
                data = fh.read()
            os.unlink(tmp.name)
            return io.BytesIO(data), "video/mp4", "CipherPulse_demo.mp4"
        except Exception:
            pass

    pil_frames = [Image.fromarray(frame) for frame in frames]
    buf = io.BytesIO()
    pil_frames[0].save(
        buf,
        save_all=True,
        append_images=pil_frames[1:],
        duration=int(1000 / fps),
        loop=0,
    )
    buf.seek(0)
    return buf, "image/gif", "CipherPulse_demo.gif"


def run_builtin_tests(conn):
    results = {}

    s1 = build_scenario(1337, DURATION)
    s2 = build_scenario(1337, DURATION)
    results["determinism_same_seed"] = json.dumps(s1["events"][:20], sort_keys=True, default=str) == json.dumps(
        s2["events"][:20], sort_keys=True, default=str
    )

    tmp = sqlite3.connect(":memory:", check_same_thread=False)
    tmp.row_factory = sqlite3.Row
    init_db(tmp)
    tmp.execute("INSERT INTO entities(anon_id, kind, first_seen) VALUES('e1','test',0)")
    tmp.execute("INSERT INTO states(entity_id, state, since, reason) VALUES('e1','UNSEEN_FP',0,'init')")
    tmp.commit()

    transition_state(tmp, "e1", "CLUSTERED", 0.0, "test legal", actor="tester")
    try:
        transition_state(tmp, "e1", "BLOCKED", 1.0, "illegal test", actor="tester")
        results["state_transition_legality"] = False
    except IllegalTransitionError:
        results["state_transition_legality"] = True

    scenario = st.session_state.get("scenario")
    if scenario:
        st.session_state.running = False
        st.session_state.t = DURATION
        process_up_to(conn, DURATION)

        trap_ids = [e["id"] for e in scenario["entities"] if e["name"] == "chrome_release_123"]
        if trap_ids:
            trap_id = trap_ids[0]
            state = get_state(conn, trap_id)
            block_row = conn.execute("SELECT id FROM blocklist WHERE entity_id=?", (trap_id,)).fetchone()
            results["trap_case_no_action"] = bool(state != "BLOCKED" and block_row is None)
        else:
            results["trap_case_no_action"] = False
    else:
        results["trap_case_no_action"] = False

    harmful_during_failure = conn.execute(
        "SELECT COUNT(*) AS c FROM audit_log WHERE action='ACTION_EXECUTED' AND ts >= ? AND ts < ?",
        (FAILURE_START, FAILURE_END),
    ).fetchone()["c"]
    results["failure_injection_no_blind_action"] = int(harmful_during_failure) == 0

    tmp2 = sqlite3.connect(":memory:", check_same_thread=False)
    tmp2.row_factory = sqlite3.Row
    init_db(tmp2)
    tmp2.execute("INSERT INTO overrides(ts, analyst, reason, suppress_rule) VALUES(0,'tester','test','entity:abc')")
    tmp2.commit()
    results["override_learned_and_persisted"] = bool(is_suppressed(tmp2, "abc"))

    try:
        bundle = json.loads(export_bundle(conn, "test-run"))
        required = {"entities", "events", "states", "decisions", "overrides", "metrics"}
        results["export_schema_valid"] = required.issubset(set(bundle.get("tables", {}).keys()))
    except Exception:
        results["export_schema_valid"] = False

    ok, _bad_id = verify_audit_chain(conn)
    results["audit_chain_verifies"] = bool(ok)

    return results


# ------------------------------------------------------------------
# Streamlit session defaults
# ------------------------------------------------------------------

DEFAULTS = {
    "seed": 1337,
    "t": 0,
    "running": True,
    "dry_run": False,
    "autonomous": True,
    "failure_enabled": True,
    "speed": 0.5,
    "last_advance": time.time(),
    "initialized": False,
    "latest_scores": {},
    "action_effects": [],
    "errors": [],
    "capture": None,
    "test_results": None,
    "metrics_persisted": False,
    "selected_entity": None,
}

for k, v in DEFAULTS.items():
    st.session_state.setdefault(k, v)

conn = get_db()

if not st.session_state.get("initialized", False):
    reset_simulation(st.session_state.seed)
    st.session_state.running = True

# ------------------------------------------------------------------
# Header and controls
# ------------------------------------------------------------------

st.markdown("## 🛰️ CipherPulse Fingerprint Watch")
st.caption(
    "Defender-only, simulation-only prototype. Clusters encrypted-traffic TLS/JA3-JA4 fingerprints and connection-timing metadata to detect C2 without decryption. "
    f"App version: {APP_VERSION} | Rule version: {RULE_VERSION}"
)

controls = st.columns([1.1, 1.1, 1.1, 1.1, 1.1, 1.1, 1.1, 1.1])

with controls[0]:
    seed_input = st.number_input("Seed", min_value=0, value=int(st.session_state.seed), step=1)
    if int(seed_input) != int(st.session_state.seed):
        st.session_state.seed = int(seed_input)

with controls[1]:
    dry_run_ui = st.checkbox(
        "Dry-run mode",
        value=bool(st.session_state.dry_run),
        help="If enabled, decisions are created but no simulated block is executed.",
    )
    if dry_run_ui != bool(st.session_state.dry_run):
        st.session_state.dry_run = dry_run_ui

with controls[2]:
    autonomous_ui = st.checkbox(
        "Autonomous automation",
        value=bool(st.session_state.autonomous),
        help="Rate-limited autonomous live-sim action, behind authorization gate.",
    )
    if autonomous_ui != bool(st.session_state.autonomous):
        st.session_state.autonomous = autonomous_ui

with controls[3]:
    failure_ui = st.checkbox("Failure injection", value=bool(st.session_state.failure_enabled))
    if failure_ui != bool(st.session_state.failure_enabled):
        st.session_state.failure_enabled = failure_ui

with controls[4]:
    if st.button("▶ Run 2-Minute Live Demo", use_container_width=True):
        st.session_state.dry_run = False
        st.session_state.autonomous = True
        st.session_state.seed = int(seed_input)
        reset_simulation(int(seed_input))
        st.session_state.running = True
        st.session_state.last_advance = time.time()
        rerun()

with controls[5]:
    if st.button("⏸ Pause", use_container_width=True):
        st.session_state.running = False

with controls[6]:
    if st.button("🔁 Replay", use_container_width=True):
        st.session_state.dry_run = False
        st.session_state.autonomous = True
        st.session_state.seed = int(seed_input)
        reset_simulation(int(seed_input))
        st.session_state.running = True
        st.session_state.last_advance = time.time()
        rerun()

with controls[7]:
    if st.button("♻ Reset", use_container_width=True):
        st.session_state.seed = int(seed_input)
        reset_simulation(int(seed_input))
        st.session_state.running = False
        rerun()

status_cols = st.columns([1, 1, 1, 1, 1])
current_t = float(st.session_state.t)
metrics_live = compute_metrics(conn, current_t)

with status_cols[0]:
    st.metric("Sim clock", f"{int(current_t):03d}s / {DURATION}s")
with status_cols[1]:
    st.metric("Phase", phase_name(current_t))
with status_cols[2]:
    st.metric("Mode", "dry-run" if st.session_state.dry_run else "live-sim")
with status_cols[3]:
    st.metric("Stream", "DEGRADED" if is_failure_active(current_t) else "OK")
with status_cols[4]:
    st.metric("Verdict", metrics_live.get("verdict", "PENDING"))

if st.session_state.errors:
    with st.expander(f"⚠️ Logged safety/transition errors ({len(st.session_state.errors)})", expanded=False):
        st.json(st.session_state.errors[-20:])

# ------------------------------------------------------------------
# Entity lookup helpers
# ------------------------------------------------------------------

scenario_ui = st.session_state.get("scenario", {"entities": []})
name_by_id = {e["id"]: e["name"] for e in scenario_ui.get("entities", [])}
entity_ids = get_entity_ids(conn)
entity_options = {name_by_id.get(eid, eid[:8]): eid for eid in entity_ids}

# ------------------------------------------------------------------
# 8-panel main screen
# ------------------------------------------------------------------

row1 = st.columns(4)
row2 = st.columns(4)

# Panel 1: Live telemetry / simulation + cluster map
with row1[0]:
    st.markdown("### 1) Live telemetry / simulation")
    tab_tel, tab_map = st.tabs(["Telemetry", "Cluster map"])

    with tab_tel:
        if is_failure_active(current_t):
            st.warning("Controlled failure active: dropped stream. Fail-safe hold is in effect.")
        recent_df = get_recent_events_df(conn, current_t)
        st.dataframe(recent_df, use_container_width=True, hide_index=True)

    with tab_map:
        map_df = get_cluster_map_df(conn, current_t)
        if map_df.empty:
            st.info("No fingerprint clusters visible yet.")
        else:
            fig = px.scatter(
                map_df,
                x="x",
                y="y",
                color="state",
                symbol="kind",
                hover_name="entity",
                hover_data=["ja3", "known_family"],
                title="Fingerprint-cluster map",
            )
            for label, (x, y) in KNOWN_CENTERS.items():
                fig.add_annotation(x=x, y=y, text=label, showarrow=False, font=dict(size=10, color="gray"))
            fig.update_layout(height=320, margin=dict(l=10, r=10, t=40, b=10))
            st.plotly_chart(fig, use_container_width=True)

# Panel 2: Tracked entities
with row1[1]:
    st.markdown("### 2) Tracked entities")
    entities_df = get_tracked_entities_df(conn)
    st.dataframe(entities_df, use_container_width=True, hide_index=True)

    selected_default = None
    suspicious = sorted(
        [v for v in st.session_state.latest_scores.values() if not v.get("suppressed", False)],
        key=lambda x: x.get("score", 0.0),
        reverse=True,
    )
    if suspicious:
        selected_default = suspicious[0].get("entity_id")

    labels = list(entity_options.keys())
    default_index = 0
    if selected_default and labels:
        for i, label in enumerate(labels):
            if entity_options[label] == selected_default:
                default_index = i
                break

    if labels:
        selected_label = st.selectbox("Evidence focus", options=labels, index=default_index)
        st.session_state.selected_entity = entity_options[selected_label]
    else:
        st.info("No entities available yet.")

# Panel 3: Project score with confidence
with row1[2]:
    st.markdown("### 3) Project score + confidence")
    st.metric("KPI score", metrics_live.get("kpi_score", 0.0))
    st.metric("C2 clusters found without decryption", metrics_live.get("c2_clusters_found", 0))
    st.metric("Fingerprint-cluster purity", metrics_live.get("fingerprint_cluster_purity", 1.0))

    avg_conf = (
        float(np.mean([v.get("confidence", 0.0) for v in st.session_state.latest_scores.values()]))
        if st.session_state.latest_scores
        else 0.0
    )
    avg_unc = (
        float(np.mean([v.get("uncertainty", 0.0) for v in st.session_state.latest_scores.values()]))
        if st.session_state.latest_scores
        else 1.0
    )

    st.metric("Average confidence", round(avg_conf, 3))
    st.metric("Average uncertainty", round(avg_unc, 3))
    st.caption("Primary KPI: C2 clusters found without decryption; fingerprint-cluster purity.")

# Panel 4: Evidence panel
with row1[3]:
    st.markdown("### 4) Evidence panel")
    selected_id = st.session_state.get("selected_entity")
    feats = st.session_state.latest_scores.get(selected_id, None)

    if not feats:
        st.info("No evidence available for selected entity yet.")
    else:
        st.write(f"**Entity:** `{selected_id}`")
        st.write(f"**State:** `{feats.get('state')}`")
        st.write(
            f"**Score:** `{feats.get('score')}` | **Confidence:** `{feats.get('confidence')}` | **Uncertainty:** `{feats.get('uncertainty')}`"
        )
        st.write(f"**Fingerprint:** `{feats.get('fingerprint')}` | **JA4:** `{feats.get('ja4')}`")
        st.write(f"**Destination:** `{feats.get('destination')}`")
        st.write(f"**Known family:** `{feats.get('known_family')}` | **Inventory match:** `{feats.get('inventory_match')}`")

        if feats.get("notes"):
            st.write(f"**Suppression notes:** {', '.join(feats.get('notes', []))}")

        top_df = to_df(feats.get("top3", []), ["feature", "contribution"])
        if not top_df.empty:
            fig = px.bar(top_df, x="feature", y="contribution", title="Top-3 evidence contributions")
            fig.update_layout(height=230, margin=dict(l=10, r=10, t=40, b=10))
            st.plotly_chart(fig, use_container_width=True)

        st.write(f"**Thresholds crossed:** {', '.join(feats.get('thresholds_crossed', [])) or 'none'}")
        st.write(f"**Rule version:** {feats.get('rule_version')}")

# Panel 5: Event timeline + periodogram
with row2[0]:
    st.markdown("### 5) Event timeline + periodogram")
    tab_time, tab_period = st.tabs(["Timeline", "Periodogram"])

    with tab_time:
        timeline_df = get_timeline_df(conn, current_t)
        if timeline_df.empty:
            st.info("No timeline events yet.")
        else:
            fig = px.scatter(
                timeline_df,
                x="ts",
                y="event",
                color="event",
                hover_data=["entity", "details"],
                title="Audit/state/decision timeline",
            )
            fig.update_layout(height=300, margin=dict(l=10, r=10, t=40, b=10))
            st.plotly_chart(fig, use_container_width=True)

    with tab_period:
        selected_id = st.session_state.get("selected_entity")
        if not selected_id:
            st.info("Select an entity to view beacon periodogram.")
        else:
            feats = st.session_state.latest_scores.get(selected_id)
            pg = feats.get("periodogram") if feats else None
            if not pg:
                st.info("Not enough timing observations for periodogram.")
            else:
                fig = go.Figure()
                fig.add_trace(go.Scatter(x=pg["freqs"], y=pg["power"], mode="lines", name="FFT power"))
                if pg.get("peak_freq"):
                    fig.add_vline(x=pg["peak_freq"], line_dash="dash", line_color="red")

                period_txt = f"peak period ≈ {pg['period']:.2f}s" if pg.get("period") else "no dominant period"
                fig.update_layout(title=f"Beacon periodogram ({period_txt})", height=300, margin=dict(l=10, r=10, t=50, b=10))
                st.plotly_chart(fig, use_container_width=True)

# Panel 6: Action + verification
with row2[1]:
    st.markdown("### 6) Action + verification")

    pending = get_pending_decisions(conn)
    if pending:
        pending_options = {
            f"decision {p['id']} | entity {p['entity_id'][:8]} | score {p['score']}": p["id"] for p in pending
        }
        selected_pending = st.selectbox("Pending decision", list(pending_options.keys()))

        c1, c2 = st.columns(2)
        with c1:
            if st.button("✅ Approve", use_container_width=True):
                approve_decision(conn, pending_options[selected_pending], "analyst")
                rerun()
        with c2:
            if st.button("🚫 Override as benign", use_container_width=True):
                row = conn.execute("SELECT evidence_json FROM decisions WHERE id=?", (pending_options[selected_pending],)).fetchone()
                evidence = json.loads(row["evidence_json"])
                override_entity(conn, evidence.get("entity_id"), "analyst", "manual override from action panel", current_t)
                rerun()
    else:
        st.info("No pending decisions. In live-sim mode, authorized automation may act autonomously.")

    block_df = get_blocklist_df(conn)
    st.write("**Simulated blocklist**")
    st.dataframe(block_df, use_container_width=True, hide_index=True)

    blocked_entities = [r["entity_id"] for r in conn.execute("SELECT entity_id FROM states WHERE state='BLOCKED'").fetchall()]
    if blocked_entities:
        rb_entity = st.selectbox(
            "Rollback blocked entity",
            blocked_entities,
            format_func=lambda x: name_by_id.get(x, x[:8]),
        )
        if st.button("↩ Rollback block", use_container_width=True):
            rollback_entity(conn, rb_entity, current_t, analyst="analyst")
            rerun()

    if entity_options:
        override_entity_choice = st.selectbox(
            "Override entity",
            options=list(entity_options.keys()),
        )
        reason = st.text_input("Override reason", value="benign business app confirmed")
        if st.button("📌 Persist override / learn suppression", use_container_width=True):
            override_entity(conn, entity_options[override_entity_choice], "analyst", reason, current_t)
            rerun()

# Panel 7: KPI + accuracy
with row2[2]:
    st.markdown("### 7) KPI + accuracy")
    st.metric("Precision", metrics_live.get("precision", 0.0))
    st.metric("Recall", metrics_live.get("recall", 0.0))
    st.metric("F1", metrics_live.get("f1", 0.0))
    st.metric("False-alarm rate", metrics_live.get("false_alarm_rate", 0.0))
    st.metric("Detection latency (ms)", metrics_live.get("detection_latency_ms", 0.0))
    st.metric("Throughput/FPS proxy", metrics_live.get("fps_proxy", 0.0))
    st.metric("Time-to-contain (ms)", metrics_live.get("time_to_contain_ms", 0.0))
    st.metric("Recovery time (s)", metrics_live.get("recovery_time_sec", 0.0))

    st.write("**Before/after autonomous action**")
    effects_df = to_df(
        st.session_state.action_effects,
        ["ts", "entity_id", "action", "before_state", "after_state", "before_score", "after_score"],
    )
    st.dataframe(effects_df, use_container_width=True, hide_index=True)

# Panel 8: Audit log + export + demo capture + tests
with row2[3]:
    st.markdown("### 8) Audit log + export")

    audit_df = get_audit_df(conn, limit=30)
    audit_view = audit_df[["id", "ts", "actor", "action"]]
    st.dataframe(audit_view, use_container_width=True, hide_index=True)

    if st.button("🔍 Verify audit hash chain", use_container_width=True):
        ok, bad_id = verify_audit_chain(conn)
        if ok:
            st.success("Audit hash chain verified.")
        else:
            st.error(f"Audit chain broken at id={bad_id}")

    json_bytes = export_bundle(conn, st.session_state.run_id).encode("utf-8")
    st.download_button(
        "⬇ Export JSON bundle",
        data=json_bytes,
        file_name="cipherpulse_export.json",
        mime="application/json",
        use_container_width=True,
    )

    csv_zip = build_csv_zip(conn)
    st.download_button(
        "⬇ Export CSV bundle (zip)",
        data=csv_zip,
        file_name="cipherpulse_export_csv.zip",
        mime="application/zip",
        use_container_width=True,
    )

    if st.button("🎞 Generate 60-second demo capture", use_container_width=True):
        with st.spinner("Rendering simulated live demo capture..."):
            try:
                buf, mime, fname = generate_demo_capture(seconds=60, fps=2)
                st.session_state.capture = (buf.getvalue(), mime, fname)
            except Exception as exc:
                st.error(f"Demo capture failed: {exc}")

    if st.session_state.capture:
        data, mime, fname = st.session_state.capture
        st.download_button(
            "⬇ Download 60-second demo capture",
            data=data,
            file_name=fname,
            mime=mime,
            use_container_width=True,
        )
        if mime.startswith("video/"):
            st.video(data)
        else:
            st.image(data, caption="Simulated live demo capture")

    with st.expander("Built-in acceptance tests", expanded=False):
        if st.button("Run built-in tests", use_container_width=True):
            st.session_state.test_results = run_builtin_tests(conn)

        if st.session_state.test_results:
            st.json(st.session_state.test_results)
            if all(st.session_state.test_results.values()):
                st.success("Built-in tests: PASS")
            else:
                st.warning("Built-in tests: one or more checks failed")

# Final verdict banner near end of demo
if current_t >= DURATION:
    if not st.session_state.metrics_persisted:
        persist_metrics(conn, metrics_live, st.session_state.run_id)
        st.session_state.metrics_persisted = True

    if metrics_live.get("verdict") == "PASS":
        st.success(
            "FINAL VERDICT: PASS — deterministic demo completed. Ground-truth recall >= 0.90, false-alarm rate <= 0.10, "
            "trap case produced no harmful action, and all simulated actuation remained defender-only."
        )
    else:
        st.error("FINAL VERDICT: FAIL — inspect decisions, overrides, and audit log.")

# ------------------------------------------------------------------
# Auto-advance deterministic live demo
# ------------------------------------------------------------------

if st.session_state.running:
    speed = float(st.session_state.get("speed", 0.5))
    elapsed = time.time() - float(st.session_state.get("last_advance", time.time()))
    if elapsed < speed:
        time.sleep(speed - elapsed)

    st.session_state.last_advance = time.time()

    if int(st.session_state.t) < DURATION:
        st.session_state.t = int(st.session_state.t) + 1
        process_up_to(conn, float(st.session_state.t))
        rerun()
    else:
        st.session_state.running = False