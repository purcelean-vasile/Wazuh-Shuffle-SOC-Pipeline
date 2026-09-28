"""
Node 3: multi-stage correlation engine.

Consumes the normalized alert set produced by Node 2 and determines
whether any subset of those alerts forms a coherent attack chain, using
shared indicators of compromise (file hash, file path, process lineage,
destination IP, user) as correlation signals.

This node owns all comparison-oriented normalization: selecting a single
hash algorithm out of a concatenated hash string, stripping domain
prefixes off usernames, and reshaping values purely so they can be
compared byte-for-byte across alerts (casing, path separators, PID base,
timestamp precision). Node 2 only reconciles which raw field a value
came from; it does not interpret or reduce the value itself.

Pipeline:
    1. Parse and unwrap the Shuffle payload.
    2. Normalize per-alert fields into a comparable representation
       (extract_entities).
    3. Build an undirected graph where nodes are alerts and edges denote
       a shared indicator between two alerts (build_correlation_graph).
    4. Compute connected components via a Disjoint Set Union / Union-Find
       structure (find_connected_components) to identify alert chains,
       including alerts connected only transitively.
    5. Score each chain (score_component) and forward the ranked result
       set to the next node (LLM-based interpretation).

Complexity note: build_correlation_graph performs an O(n^2) pairwise
comparison over the alert set. This is acceptable for the expected input
size (alerts within a bounded correlation window) but would need
revisiting for substantially larger alert volumes.
"""

import json
import re
from collections import defaultdict
from datetime import datetime

raw_data = r"""$related_alerts_query"""

# Exclude common Windows/system binaries from filename correlation matching.
GENERIC_SYSTEM_BINARIES = {
    "cmd.exe", "powershell.exe", "explorer.exe", "svchost.exe",
    "rundll32.exe", "conhost.exe", "wscript.exe", "cscript.exe",
    "mshta.exe", "regsvr32.exe", "certutil.exe", "bitsadmin.exe",
    "wmic.exe", "msiexec.exe", "dllhost.exe", "taskhostw.exe",
}

SYSTEM_ACCOUNTS = {"system", "local service", "network service", ""}


def safe_parse(raw):
    """
    Parse the raw text payload from Node 2 into a Python object.
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
    raise ValueError("Unable to parse Node 2 input: " + raw[:300])


def load_alerts(data):
    """
    Unwrap the Shuffle node-result envelope and extract the alert list.
    """
    if "message" in data:
        inner = data["message"]
        if isinstance(inner, str):
            try:
                inner = json.loads(inner)
            except Exception:
                pass
        if isinstance(inner, dict):
            data = inner

    if data.get("status") == "error":
        raise RuntimeError("Node 2 reported an error: " + data.get("error", "Unknown error"))

    alerts_list = data.get("alerts", [])

    if not alerts_list:
        raise ValueError("No alerts found. Received keys: " + str(list(data.keys())))

    return alerts_list


def normalize_path(path):
    """
    Normalize a filesystem path to a comparable canonical form.
    """
    if not path:
        return ""
    p = path.strip().lower()
    p = p.replace("\\\\", "\\")
    p = p.replace("/", "\\")
    if len(p) > 2 and p[0] == "\\" and p[2] == "\\":
        p = p[1] + ":\\" + p[3:]
    return p


def filename_only(path):
    """
    Extract the filename component from a path, discarding the directory.
    """
    if not path:
        return ""
    p = normalize_path(path)
    name = p.split("\\")[-1].strip()
    name = name.split("?")[0]
    return name


def normalize_pid(pid):
    """
    Normalize a process identifier to a canonical decimal string.
    """
    if not pid:
        return ""
    s = str(pid).strip().lower()
    try:
        if s.startswith("0x"):
            return str(int(s, 16))
        return str(int(s))
    except Exception:
        return s


def normalize_hash(alert):
    """
    Select and normalize the file's SHA256 hash from a flattened alert.

    Sysmon concatenates every hash type it computed into one string
    (e.g. "MD5=...,SHA1=...,SHA256=..."), so the raw "file_hash" value
    may carry more than one algorithm. SHA256 is selected specifically,
    since MD5/SHA1 are collision-prone and unsuitable as a reliable file
    identifier for correlation.
    """
    raw_hash = alert.get("file_hash", "")
    if not raw_hash:
        return ""

    if "=" in raw_hash:
        for part in raw_hash.split(","):
            if part.strip().upper().startswith("SHA256="):
                raw_hash = part.split("=", 1)[1]
                break
        else:
            # No SHA256 entry found — fall back to whatever the last
            # "key=value" segment resolves to, rather than discarding data.
            raw_hash = raw_hash.split("=")[-1]

    return raw_hash.lower().strip()


def normalize_user(alert):
    """
    Select and normalize the username associated with an alert.

    The raw "user" value may carry a "DOMAIN\\username" or
    "group/username" prefix; only the bare username is kept, since the
    domain/group qualifier isn't useful for correlating activity by the
    same user across alerts.
    """
    raw_user = alert.get("user", "")
    if not raw_user:
        return ""

    if "\\" in raw_user:
        raw_user = raw_user.split("\\")[-1]
    elif "/" in raw_user:
        raw_user = raw_user.split("/")[-1]

    clean_user = raw_user.lower().strip()
    if clean_user in SYSTEM_ACCOUNTS:
        return ""

    return clean_user


def normalize_ip(ip):
    """
    Normalize a destination IP to a comparable form.
    """
    if not ip:
        return ""
    clean = ip.strip().lower()
    # Canonicalize the common loopback spellings so they compare equal.
    if clean in ("::1", "0:0:0:0:0:0:0:1", "127.0.0.1"):
        return "loopback"
    return clean


def normalize_timestamp(ts):
    """
    Normalize a Wazuh timestamp to a canonical ISO 8601 representation.
    """
    if not ts:
        return ""

    clean = ts.strip()
    if "." in clean:
        clean = clean[:23]
    else:
        clean = clean[:19]

    if clean.endswith("Z"):
        clean = clean[:-1] + "+00:00"
    elif not clean.endswith("+00:00"):
        clean = clean + "+00:00"

    try:
        parsed = datetime.fromisoformat(clean)
        return parsed.isoformat()
    except Exception:
        return ts


def extract_referenced_filenames(command_line):
    """
    Extract filenames with a known script/executable extension mentioned
    anywhere inside a command line (e.g. the payload passed to
    "powershell -File C:\\...\\payload.ps1", or a URL/path argument given
    to "certutil.exe -urlcache ... payload.ps1"). Applied to both
    commandLine and parentCommandLine, since the file that caused a
    process to run is often only visible in the parent's command line,
    not the child's own.

    These are text-mentions, not observed artifacts (unlike image/
    targetFilename/syscheck paths) — a shared reference here is weaker
    evidence of a real relationship than a directly observed file, so
    it is kept in its own entity bucket (see extract_entities) and
    scored as a weak signal rather than a strong one.
    """
    if not command_line:
        return set()
    matches = re.findall(
        r'[\w.\-\\/:]+\.(?:exe|ps1|bat|vbs|dll|cmd|js)\b',
        command_line, re.IGNORECASE
    )
    names = set()
    for m in matches:
        fname = m.replace("/", "\\").split("\\")[-1].strip().lower()
        if fname and fname not in GENERIC_SYSTEM_BINARIES:
            names.add(fname)
    return names


def extract_entities(alert):
    """
    Derive the comparable indicator set ("entities") for a single alert.

    "file" holds directly observed artifacts (image/targetFilename/
    syscheck path) — strong evidence. "file_referenced" holds filenames
    only mentioned inside a command line — weak evidence. Keeping them
    separate lets the correlation graph score a shared observed file
    higher than a shared text mention (see build_correlation_graph /
    find_connected_components).
    """
    entities = {"file": set(), "file_referenced": set()}

    sha256 = normalize_hash(alert)
    if sha256:
        entities["hash"] = sha256

    file_fields = [
        alert.get("file_path", ""),
        alert.get("syscheck", {}).get("path_after", ""),
        alert.get("image", ""),
        alert.get("parentImage", ""),
    ]
    for field in file_fields:
        if not field:
            continue
        fname = filename_only(field)
        # A generic system binary (cmd.exe, powershell.exe, ...) lives at
        # the same canonical path on virtually every Windows host, so
        # both the filename AND the full path are excluded together —
        # filtering only the filename would still let unrelated alerts
        # collide on the identical full path.
        if fname.lower() in GENERIC_SYSTEM_BINARIES:
            continue
        full = normalize_path(field)
        if full:
            entities["file"].add(full)
        if fname and "." in fname:
            entities["file"].add(fname)

    entities["file_referenced"] |= extract_referenced_filenames(alert.get("commandLine", ""))
    entities["file_referenced"] |= extract_referenced_filenames(alert.get("parentCommandLine", ""))
    # A name already observed directly shouldn't also count as a separate
    # weak signal.
    entities["file_referenced"] -= entities["file"]

    if not entities["file"]:
        del entities["file"]
    if not entities["file_referenced"]:
        del entities["file_referenced"]

    pid  = normalize_pid(alert.get("processId", ""))
    ppid = normalize_pid(alert.get("parentProcessId", ""))
    if pid:
        entities["pid"] = pid
    if ppid:
        entities["ppid"] = ppid

    ip = normalize_ip(alert.get("destinationIp", ""))
    if ip and ip != "loopback":
        entities["ip"] = ip

    user = normalize_user(alert)
    if user:
        entities["user"] = user

    return entities


def build_correlation_graph(alerts):
    """
    Construct the correlation graph over the alert set.
    """
    nodes = []
    for i, a in enumerate(alerts):
        nodes.append({
            "idx":        i,
            "timestamp":  normalize_timestamp(a.get("timestamp", "")),
            "rule_id":    a.get("rule_id", ""),
            "rule_desc":  a.get("rule_description", ""),
            "rule_level": a.get("rule_level", 0),
            "is_trigger": a.get("is_trigger", False),
            "entities":   extract_entities(a),
            # "raw" retains the FULL Node-1-normalized alert (including
            # agent_id/agent_name, syscheck, etc.) - not a trimmed subset -
            # so any field present in Node 2's output remains available
            # here for the report, even if it is not yet explicitly
            # extracted into the "events" list below.
            "raw":        a,
        })

    edges = []
    for i in range(len(nodes)):
        for j in range(i + 1, len(nodes)):
            n1, n2 = nodes[i], nodes[j]
            links  = []

            if n1["entities"].get("hash") and \
               n1["entities"]["hash"] == n2["entities"].get("hash"):
                links.append("same_hash")

            f1 = n1["entities"].get("file", set())
            f2 = n2["entities"].get("file", set())
            r1 = n1["entities"].get("file_referenced", set())
            r2 = n2["entities"].get("file_referenced", set())

            # Strong: at least one side is a directly observed artifact
            # (image/targetFilename/syscheck path), matched against
            # either a directly observed artifact or a command-line text
            # mention on the other side — e.g. a file written by one
            # alert and later invoked by name from a spawned process's
            # command line in another.
            strong_common = (f1 & f2) | (f1 & r2) | (r1 & f2)
            if strong_common:
                label = "same_filename:" + ",".join(sorted(strong_common)[:2])
                links.append(label)

            # Weak: both sides are only text mentions inside a command
            # line, with no directly observed artifact on either side.
            weak_common = r1 & r2
            if weak_common:
                label = "referenced_filename:" + ",".join(sorted(weak_common)[:2])
                links.append(label)

            if n1["entities"].get("pid") and \
               n1["entities"]["pid"] == n2["entities"].get("ppid"):
                links.append("parent_child_process")
            if n2["entities"].get("pid") and \
               n2["entities"]["pid"] == n1["entities"].get("ppid"):
                links.append("parent_child_process")

            if n1["entities"].get("pid") and \
               n1["entities"]["pid"] == n2["entities"].get("pid"):
                links.append("same_process")

            if n1["entities"].get("ip") and \
               n1["entities"]["ip"] == n2["entities"].get("ip"):
                links.append("same_destination_ip")

            if n1["entities"].get("user") and \
               n1["entities"]["user"] == n2["entities"].get("user"):
                links.append("same_user")

            if links:
                edges.append({"from": i, "to": j, "links": links})

    return nodes, edges


def find_connected_components(nodes, edges):
    """
    Group correlated alerts into connected chains.
    """
    parent = {n["idx"]: n["idx"] for n in nodes}

    def find(x):
        """Return the representative (root) of x's set, with path compression."""
        while parent[x] != x:
            parent[x] = parent[parent[x]]
            x = parent[x]
        return x

    def union(x, y):
        """Merge the sets containing x and y."""
        rx, ry = find(x), find(y)
        if rx != ry:
            parent[rx] = ry

    # Only directly-observed indicators union alerts into the same chain.
    # "referenced_filename" (text mentions inside command lines) and
    # "same_user"/"same_process" are weak signals: they enrich a chain
    # that strong evidence has already formed, but never form one alone.
    STRONG_KEYS = ("same_hash", "same_filename", "parent_child", "same_destination_ip")
    WEAK_KEYS   = ("same_user", "same_process", "referenced_filename")

    for e in edges:
        if any(any(k in link for k in STRONG_KEYS) for link in e["links"]):
            union(e["from"], e["to"])

    groups = defaultdict(list)
    for n in nodes:
        groups[find(n["idx"])].append(n)

    components = []
    for root, members in groups.items():
        if len(members) < 2:
            continue

        # Only chains containing the triggering alert are actionable for
        # the SOC.
        if not any(m["is_trigger"] for m in members):
            continue

        members_sorted = sorted(members, key=lambda m: m["timestamp"])
        member_idxs    = {m["idx"] for m in members}
        internal_edges = [
            e for e in edges
            if e["from"] in member_idxs and e["to"] in member_idxs
        ]

        all_link_labels = [l for e in internal_edges for l in e["links"]]
        strong_links    = sorted({
            l for l in all_link_labels
            if any(k in l for k in STRONG_KEYS)
        })
        weak_links      = sorted({
            l for l in all_link_labels
            if any(k in l for k in WEAK_KEYS)
        })

        components.append({
            "size":                   len(members_sorted),
            "first_seen":             members_sorted[0]["timestamp"],
            "last_seen":              members_sorted[-1]["timestamp"],
            "max_level":              max(m["rule_level"] for m in members_sorted),
            "strong_link_types":      strong_links,
            "weak_link_types":        weak_links,
            "contains_trigger_alert": True,
            "events": [
                {
                    "timestamp":   m["timestamp"],
                    "rule_id":     m["rule_id"],
                    "rule_desc":   m["rule_desc"],
                    "rule_level":  m["rule_level"],
                    "is_trigger":  m["is_trigger"],
                    "agent_name":  m["raw"].get("agent_name", ""),
                    "agent_id":    m["raw"].get("agent_id", ""),
                    "pid":         m["raw"].get("processId", ""),
                    "ppid":        m["raw"].get("parentProcessId", ""),
                    "image":       m["raw"].get("image", ""),
                    "parentImage": m["raw"].get("parentImage", ""),
                    "commandLine": m["raw"].get("commandLine", "")[:250],
                    "targetFile":  (
                        m["raw"].get("targetFilename", "") or
                        m["raw"].get("syscheck", {}).get("path", "")
                    ),
                    "destIp":      m["raw"].get("destinationIp", ""),
                    "destPort":    m["raw"].get("destinationPort", ""),
                    "user":        m["raw"].get("user", ""),
                    "sha256":      (
                        m["raw"].get("syscheck", {}).get("sha256_after", "") or
                        m["raw"].get("syscheck", {}).get("sha256", "")
                    ),
                    # MITRE ATT&CK technique(s) associated with this
                    # event's rule, as reported by Wazuh's rule engine.
                    "mitre":       m["raw"].get("mitre", {}),
                }
                for m in members_sorted
            ],
        })

    return components


def score_component(comp):
    """
    Compute a 0-100 risk score and a categorical verdict for a chain.
    """
    strong = comp["strong_link_types"]
    weak   = comp["weak_link_types"]
    size   = comp["size"]
    level  = comp["max_level"]

    risk = 0
    risk += min(len(strong) * 20, 60)
    risk += min(len(weak)   * 5,  15)
    risk += min(size        * 3,  20)
    risk += min(level       * 2,  20)

    if comp.get("contains_trigger_alert"):
        risk += 10

    risk = min(risk, 100)

    if risk >= 75:
        verdict = "CRITICAL — Multi-stage correlated activity"
    elif risk >= 50:
        verdict = "HIGH — Correlated suspicious activity"
    elif risk >= 25:
        verdict = "MEDIUM — Weak correlation detected"
    else:
        verdict = "LOW — Minimal correlation"

    return risk, verdict


# ═══════════════════════════════════════════════════════════════════════
# Main
# ═══════════════════════════════════════════════════════════════════════
alerts = []

try:
    data   = safe_parse(raw_data)
    alerts = load_alerts(data)

    nodes, edges = build_correlation_graph(alerts)
    components   = find_connected_components(nodes, edges)
    for comp in components:
        risk, verdict      = score_component(comp)
        comp["risk_score"] = risk
        comp["verdict"]    = verdict

    components.sort(key=lambda c: c["risk_score"], reverse=True)

    print(json.dumps({
        "status":             "ok",
        "total_alerts":       len(alerts),
        "total_chains_found": len(components),
        "top_verdict":        components[0]["verdict"]    if components else "No correlation found",
        "top_risk":           components[0]["risk_score"] if components else 0,
        "chains":             components,
    }, default=str))

except Exception as e:
    print(json.dumps({
        "status":       "error",
        "error":        str(e),
        "total_alerts": len(alerts),
    }))
    raise
