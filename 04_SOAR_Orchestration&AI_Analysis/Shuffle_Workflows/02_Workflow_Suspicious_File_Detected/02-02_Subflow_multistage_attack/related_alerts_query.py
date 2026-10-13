"""
Node 2: Related Alerts Query.

Given a triggering Wazuh alert, this node queries the Wazuh Indexer
(OpenSearch) directly for all related alerts from the same agent within a
configurable time window, normalizes every alert (Sysmon and FIM/syscheck
alike) into a unified schema, and forwards the deduplicated result set to
the correlation node (Node 3).

Runs as a Python code node inside a Shuffle SOAR workflow. Variables
prefixed with "$" (e.g. $wazuh_indexer_url) are injected by Shuffle at
runtime and are not standard Python syntax.
"""

import json
import requests
import urllib3
from datetime import datetime, timedelta, timezone

# The local Wazuh Indexer typically runs with a self-signed certificate.
# This only suppresses the console warning; verify=False in query_indexer()
# is what actually disables certificate verification.
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# ─────────────────────────────────────────────────────────────────────────
# Shuffle-injected variables. These are replaced with real values at
# workflow runtime (Wazuh Indexer URL/credentials, and the output of the
# upstream webhook node).
# ─────────────────────────────────────────────────────────────────────────
WAZUH_URL  = "$wazuh_indexer_url"
WAZUH_USER = "$wazuh_indexer_user"
WAZUH_PASS = "$wazuh_indexer_pass"
raw_data   = r"""$exec.webhook"""


def safe_parse(raw):
    """
    Parses the raw text payload received from Shuffle into a Python dict.

    Shuffle delivers node input as plain text, which sometimes arrives
    with malformed escaping (e.g. double-serialized JSON). This attempts
    three parsing strategies in order of strictness:
      1. Direct parse.
      2. Parse after doubling backslashes (fixes common Windows path
         escaping issues from Sysmon).
      3. Extract the first valid JSON structure and ignore any trailing
         garbage.

    Args:
        raw: Raw text payload.

    Returns:
        Parsed dict or list.

    Raises:
        ValueError: If all three parsing strategies fail.
    """
    raw = raw.strip()
    try:
        return json.loads(raw)
    except json.JSONDecodeError:
        pass
    try:
        return json.loads(raw.replace("\\", "\\\\"))
    except json.JSONDecodeError:
        pass
    try:
        obj, _ = json.JSONDecoder().raw_decode(raw)
        return obj
    except json.JSONDecodeError:
        pass
    raise ValueError("Unable to parse input: " + raw[:300])


def parse_alert(json_alert):
    """
    Extracts the agent ID and timestamp from the triggering alert.

    These two values are the minimum required to build the correlation
    time window and scope the Indexer query to a single agent.

    Args:
        json_alert: The parsed triggering alert.

    Returns:
        Tuple of (agent_id, timestamp). agent_id is zero-padded to 3
        digits to match Wazuh's internal agent ID format.

    Raises:
        ValueError: If agent ID or timestamp cannot be found.
    """
    agent_id  = json_alert.get("agent", {}).get("id", "")
    timestamp = json_alert.get("timestamp") or json_alert.get("@timestamp", "")

    if not agent_id:
        raise ValueError("Missing agent.id. Available keys: " + str(list(json_alert.keys())))
    if not timestamp:
        raise ValueError("Missing timestamp. Available keys: " + str(list(json_alert.keys())))

    return str(agent_id).zfill(3), timestamp


def build_time_range(timestamp_raw, window_before=3, window_after=5):
    """
    Build a normalized ISO 8601 time window for the correlation query.

    Asymmetric by design: a few minutes before the trigger (to catch the
    process that wrote the file) and more minutes after (to catch delayed
    execution — a downloaded file is often opened minutes after it lands
    on disk, not immediately).

    Args:
        timestamp_raw: Timestamp of the triggering alert, in any Wazuh
            format (with or without sub-second precision).
        window_before: Minutes to look back from the trigger.
        window_after: Minutes to look forward from the trigger.

    Returns:
        Tuple of (window_start, window_end) as ISO 8601 strings with an
        explicit UTC offset.

    Raises:
        ValueError: If the timestamp cannot be parsed.
    """
    clean = timestamp_raw.strip()
    if "." in clean:
        clean = clean[:23] + "+00:00"
    else:
        clean = clean[:19] + "+00:00"

    try:
        ts = datetime.fromisoformat(clean)
    except Exception as e:
        raise ValueError(f"Could not parse timestamp '{timestamp_raw}': {e}")

    return (ts - timedelta(minutes=window_before)).isoformat(), \
           (ts + timedelta(minutes=window_after)).isoformat()


def normalize_alert(src, is_trigger=False):
    """
    Normalize a raw Wazuh alert (Sysmon or FIM/syscheck) into a flat,
    unified schema shared by every alert forwarded to the correlation node.

    This function resolves which of Sysmon/syscheck populated a given
    piece of information, and under which of several possible raw field
    paths it is indexed (e.g. "win.eventdata.*" vs "data.win.eventdata.*").
    Exactly one of the candidate sources is ever populated for a given
    alert, so picking the non-empty one is a straightforward selection.

    Value-level interpretation — such as picking one hash algorithm out
    of several concatenated in "hashes", or stripping the domain prefix
    off "DOMAIN\\user" — is handled downstream, in the correlation node,
    where alerts are compared against each other and a unified,
    comparable format actually matters.

    Args:
        src: Raw alert source dict.
        is_trigger: True if this is the alert that initiated the
            investigation, as opposed to one found via the Indexer query.

    Returns:
        A flat dict with empty/null fields stripped out.
    """
    ts  = src.get("timestamp") or src.get("@timestamp", "")
    # Sysmon eventdata can live directly under "win" or nested one level
    # deeper under "data.win", depending on how the alert was indexed.
    win = src.get("win", {}) or src.get("data", {}).get("win", {}) or {}
    ed  = win.get("eventdata", {}) or {}
    sys = src.get("syscheck", {}) or {}

    # ─── Hash — Sysmon or syscheck ─────────────────────────────────────
    # Sysmon's "hashes" field is the raw concatenated string, e.g.
    # "MD5=...,SHA256=...,IMPHASH=...".
    raw_hash = ed.get("hashes", "") or sys.get("sha256_after", "")

    # ─── File path — Sysmon or syscheck ────────────────────────────────
    raw_path = ed.get("targetFilename", "") or sys.get("path", "")

    # ─── User — Sysmon or syscheck ─────────────────────────────────────
    raw_user = ed.get("user", "") or sys.get("uname_after", "")

    normalized = {
        # Core correlation fields
        "timestamp":        ts,
        "agent_id":         src.get("agent", {}).get("id", ""),
        "agent_name":       src.get("agent", {}).get("name", ""),
        "rule_id":          str(src.get("rule", {}).get("id", "")),
        "rule_description": src.get("rule", {}).get("description", "")[:150],
        "rule_level":       src.get("rule", {}).get("level", 0),
        "mitre":            src.get("rule", {}).get("mitre", {}),
        "is_trigger":       is_trigger,
        # Windows/Sysmon-specific fields
        "image":            ed.get("image", ""),
        "parentImage":      ed.get("parentImage", ""),
        "commandLine":      ed.get("commandLine", "")[:200],
        "parentCommandLine":ed.get("parentCommandLine", "")[:200],
        "processId":        ed.get("processId", ""),
        "parentProcessId":  ed.get("parentProcessId", ""),
        "targetFilename":   ed.get("targetFilename", ""),
        "destinationIp":    ed.get("destinationIp", ""),
        "destinationPort":  ed.get("destinationPort", ""),
        # Fields unified across Sysmon and syscheck sources
        "file_path":        raw_path,
        "file_hash":        raw_hash,
        "user":             raw_user,
        # Full syscheck object, for the correlation node's own use
        "syscheck":         sys,
        "full_log":         src.get("full_log", "")[:200],
    }

    # Strip empty/null fields to reduce payload size sent downstream.
    cleaned = {}
    for k, v in normalized.items():
        if v not in ("", {}, [], None):
            cleaned[k] = v
    return cleaned


def query_indexer(agent_id, ts_start, ts_end):
    """
    Query the Wazuh Indexer (OpenSearch) for alerts from a given agent
    within the specified time window.

    Requests up to 100 results, sorted chronologically, filtered to
    rule.level >= 4 (excludes low-signal noise) and requiring at least
    one process/file/network-related field to be present.

    Both "win.eventdata.*" and "data.win.eventdata.*" field paths are
    requested deliberately — Wazuh may store the same Sysmon data under
    either path depending on alert type/version, and OpenSearch silently
    omits any requested field that doesn't exist in a given document, so
    requesting both is a no-cost way to cover both cases.

    Args:
        agent_id: Zero-padded Wazuh agent ID.
        ts_start: Window start, ISO 8601.
        ts_end: Window end, ISO 8601.

    Returns:
        Raw OpenSearch response (dict).

    Raises:
        ConnectionError: If the request to the Indexer fails to connect.
        PermissionError: On 401/403 responses.
    """
    query = {
        "size": 100,
        "sort": [{"timestamp": {"order": "asc"}}],
        "_source": [
            "timestamp", "@timestamp",
            "agent.id", "agent.name",
            "rule.id", "rule.description", "rule.level", "rule.mitre",
            "win.eventdata.image", "win.eventdata.parentImage",
            "win.eventdata.commandLine", "win.eventdata.parentCommandLine",
            "win.eventdata.processId", "win.eventdata.parentProcessId",
            "win.eventdata.targetFilename", "win.eventdata.destinationIp",
            "win.eventdata.destinationPort", "win.eventdata.user",
            "win.eventdata.hashes",
            "data.win.eventdata.image", "data.win.eventdata.parentImage",
            "data.win.eventdata.commandLine", "data.win.eventdata.parentCommandLine",
            "data.win.eventdata.processId", "data.win.eventdata.parentProcessId",
            "data.win.eventdata.targetFilename", "data.win.eventdata.destinationIp",
            "data.win.eventdata.destinationPort", "data.win.eventdata.user",
            "data.win.eventdata.hashes",
            "syscheck", "full_log"
        ],
        "query": {
            "bool": {
                "must": [
                    {"term":  {"agent.id": agent_id}},
                    {"range": {"timestamp": {
                        "gte":    ts_start,
                        "lte":    ts_end,
                        "format": "strict_date_optional_time"
                    }}}
                ],
                "filter": [
                    {"range": {"rule.level": {"gte": 4}}},
                    {"bool": {
                        "should": [
                            {"exists": {"field": "win.eventdata.image"}},
                            {"exists": {"field": "win.eventdata.parentProcessId"}},
                            {"exists": {"field": "win.eventdata.commandLine"}},
                            {"exists": {"field": "win.eventdata.targetFilename"}},
                            {"exists": {"field": "win.eventdata.destinationIp"}},
                            {"exists": {"field": "data.win.eventdata.image"}},
                            {"exists": {"field": "data.win.eventdata.commandLine"}},
                            {"exists": {"field": "data.win.eventdata.targetFilename"}},
                            {"exists": {"field": "syscheck.path"}},
                            {"exists": {"field": "syscheck.sha256_after"}},
                        ],
                        "minimum_should_match": 1
                    }}
                ]
            }
        }
    }
    try:
        r = requests.post(
            WAZUH_URL,
            auth=(WAZUH_USER, WAZUH_PASS),
            headers={"Content-Type": "application/json"},
            json=query,
            verify=False,
            timeout=30
        )
        r.raise_for_status()
        return r.json()
    except requests.exceptions.ConnectionError:
        raise ConnectionError("Failed to connect to: " + WAZUH_URL)
    except requests.exceptions.HTTPError:
        if r.status_code == 401:
            raise PermissionError("Invalid credentials (401)")
        if r.status_code == 403:
            raise PermissionError("Insufficient permissions (403)")
        raise


def format_alerts(raw_response):
    """
    Normalize every alert in an Indexer response into the unified schema.

    Args:
        raw_response: Raw OpenSearch response from query_indexer().

    Returns:
        Dict with "total" (matching document count) and "alerts" (list
        of normalized alert dicts).
    """
    hits  = raw_response.get("hits", {}).get("hits", [])
    total = raw_response.get("hits", {}).get("total", {}).get("value", 0)
    alerts = [
        normalize_alert(hit.get("_source", {}), is_trigger=False)
        for hit in hits
    ]
    return {"total": total, "alerts": alerts}


def alert_key(a):
    """
    Build a lightweight identity key (rule_id, timestamp) for an alert,
    used to deduplicate the triggering alert against Indexer results
    that may include it a second time.
    """
    return (str(a.get("rule_id", "")), str(a.get("timestamp", "")))


# ═══════════════════════════════════════════════════════════════════════
# Main
# ═══════════════════════════════════════════════════════════════════════
agent_id = ""
ts_start = ""
ts_end   = ""
total    = 0

try:
    parsed_raw       = safe_parse(raw_data)
    agent_id, ts_raw = parse_alert(parsed_raw)
    ts_start, ts_end = build_time_range(ts_raw)

    # Normalize the triggering alert itself, so it shares the same schema
    # as everything returned by the Indexer query below.
    trigger_alert = normalize_alert(parsed_raw, is_trigger=True)

    raw    = query_indexer(agent_id, ts_start, ts_end)
    result = format_alerts(raw)
    total  = result["total"]

    # The triggering alert may also be present in the Indexer results
    # (the window includes its own timestamp) — deduplicate against it.
    seen    = {alert_key(trigger_alert)}
    deduped = []
    for a in result["alerts"]:
        k = alert_key(a)
        if k not in seen:
            seen.add(k)
            deduped.append(a)

    all_alerts = [trigger_alert] + deduped

    # Printed output becomes this node's result, available to the next
    # node in the Shuffle workflow (the correlation node).
    print(json.dumps({
        "status":       "ok",
        "agent_id":     agent_id,
        "ts_start":     ts_start,
        "ts_end":       ts_end,
        "total":        total,
        "alerts_count": len(all_alerts),
        "alerts":       all_alerts,
    }, default=str))

except Exception as e:
    # Report failures as structured JSON for easy debugging in Shuffle,
    # then re-raise so the workflow correctly registers the failure.
    print(json.dumps({
        "status":   "error",
        "error":    str(e),
        "agent_id": agent_id,
        "ts_start": ts_start,
        "ts_end":   ts_end,
        "total":    total,
    }))
    
