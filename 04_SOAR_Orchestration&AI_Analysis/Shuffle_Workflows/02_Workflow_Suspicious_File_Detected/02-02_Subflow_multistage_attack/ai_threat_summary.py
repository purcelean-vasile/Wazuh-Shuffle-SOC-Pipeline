"""
Node 4: AI Threat Summary (LLM-based interpretation of correlated
multi-stage alert chains).

Consumes the ranked correlation output produced by the Attack Chain
Correlation node and renders it as a natural-language SOC report using
a locally hosted Ollama instance (llama3). The correlation and
risk-scoring decisions themselves are made upstream, deterministically;
this node's role is limited to summarization and presentation, not
detection.

Renders timestamps in Romania local time (source data is UTC).

Also builds "vt_status_line": a one-line warning, populated only when
the VirusTotal Verdict node reported a connection/lookup error, so the
downstream email can display it unconditionally without needing its
own conditional logic - empty string when VT succeeded.

Requires these Shuffle variables:
    $attack_chain_correlation  - output of the correlation node
    $exec.vt.error             - VT Verdict node's error field (subflow argument)
"""

import json
import re
import requests
import time
from datetime import datetime
from zoneinfo import ZoneInfo

# All timestamps arriving from the correlation node are in UTC
# (ISO 8601). Converted to Romania local time for the report.
ROMANIA_TZ = ZoneInfo("Europe/Bucharest")

def to_romania_time(ts):
    """
    Convert a UTC ISO 8601 timestamp to Romania local time for display.
    Falls back to the original string unchanged if it can't be parsed,
    so a malformed timestamp never breaks the report.
    """
    if not ts or ts == "N/A":
        return ts
    try:
        dt_utc = datetime.fromisoformat(ts)
        if dt_utc.tzinfo is None:
            dt_utc = dt_utc.replace(tzinfo=ZoneInfo("UTC"))
        dt_ro = dt_utc.astimezone(ROMANIA_TZ)
        return dt_ro.strftime("%Y-%m-%d %H:%M:%S %Z")
    except Exception:
        return ts

raw_data = r"""$attack_chain_correlation"""

# VT classification fields, read directly from the subflow's own
# argument as plain scalars - no JSON parsing needed. Used both for the
# email's vt_status_line (error case only) and to give the LLM prompt
# explicit VT context, so the model can flag a mismatch between hash
# reputation and behavioral evidence instead of silently ignoring VT.
vt_verdict_raw         = r"""$exec.vt.verdict"""
vt_error_raw            = r"""$exec.vt.error"""
vt_malicious_count_raw  = r"""$exec.vt.malicious_count"""

SECTION_LABELS = [
    "VERDICT", "WHAT HAPPENED", "IOC",
    "COMMANDS EXECUTED", "RECOMMENDED ACTION",
]


def format_report(text):
    """
    Force each numbered section onto its own line, regardless of the
    model's exact spacing/formatting. Labels are numbered in the prompt
    ("1. VERDICT:"..."5. RECOMMENDED ACTION:"), so the leading "N." is
    matched and stripped along with the rest of the separator. Also
    strips markdown bold markers ("**"), since the model sometimes wraps
    labels in them despite the plain-text instruction.
    """
    text = text.strip().replace("**", "")
    text = re.sub(r"\r?\n", "<br>", text)

    label_pattern = "|".join(re.escape(label) for label in SECTION_LABELS)
    pattern = re.compile(rf"\s*(?:<br>\s*)*(?:\d+\.\s*)?({label_pattern})\s*:", re.IGNORECASE)
    text = pattern.sub(lambda m: f"<br><br>{m.group(1)}:", text)

    text = re.sub(r"^(<br>\s*)+", "", text)
    text = re.sub(r"(<br>\s*){3,}", "<br><br>", text)
    return text.strip()


def build_event_text(event, idx):
    """
    Builds the readable text for ONE event in the chain, used in
    the prompt sent to Ollama.
    """
    lines = []
    lines.append(f"  Event {idx} [{to_romania_time(event.get('timestamp', 'N/A'))}]")
    lines.append(f"    Rule:         {event.get('rule_desc', 'N/A')} (ID: {event.get('rule_id', 'N/A')}, Level: {event.get('rule_level', 'N/A')})")

    if event.get("agent_name") or event.get("agent_id"):
        lines.append(f"    Workstation:  {event.get('agent_name') or event.get('agent_id')}")

    if event.get("is_trigger"):
        lines.append(f"    *** TRIGGER ALERT — the event that initiated this investigation ***")
    if event.get("user"):
        lines.append(f"    User:         {event['user']}")
    if event.get("image"):
        lines.append(f"    Process:      {event['image']}")
    if event.get("parentImage"):
        lines.append(f"    Parent:       {event['parentImage']}")
    if event.get("pid"):
        lines.append(f"    PID:          {event['pid']}")
    if event.get("ppid"):
        lines.append(f"    PPID (parent): {event['ppid']}")
    if event.get("commandLine"):
        lines.append(f"    Command line: {event['commandLine']}")
    if event.get("targetFile"):
        lines.append(f"    File:         {event['targetFile']}")
    if event.get("sha256"):
        lines.append(f"    SHA256 hash:  {event['sha256']}")
    if event.get("destIp"):
        lines.append(f"    Dest. IP:     {event['destIp']}")
    if event.get("trigger_links"):
        lines.append(f"    Trigger link: {', '.join(event['trigger_links'])}")

    return "\n".join(lines)


def build_chain_text(chain, chain_idx):
    """
    Builds the readable text for ONE full correlation chain
    (summary + all its events, in chronological order).
    """
    lines = []
    lines.append(f"=== CHAIN {chain_idx} ===")
    lines.append(f"Verdict:     {chain.get('verdict', 'N/A')}")
    lines.append(f"Risk Score:  {chain.get('risk_score', 0)}/100")
    lines.append(f"Timeframe:   {to_romania_time(chain.get('first_seen', 'N/A'))} -> {to_romania_time(chain.get('last_seen', 'N/A'))}")
    lines.append(f"Event count: {chain.get('size', len(chain.get('events', [])))}")

    strong = chain.get("strong_link_types", [])
    weak   = chain.get("weak_link_types", [])
    if strong:
        lines.append(f"Strong links: {', '.join(strong)}")
    if weak:
        lines.append(f"Weak links:   {', '.join(weak)}")

    lines.append(f"\nEvent sequence ({len(chain.get('events', []))} total):")
    for i, event in enumerate(chain.get("events", []), 1):
        lines.append(build_event_text(event, i))
        lines.append("")

    return "\n".join(lines)


def interpret_with_ollama(input_data, vt_context_line):
    # ─── PARSE INPUT ──────────────────────────────────────────────────────
    try:
        data = json.loads(input_data) if isinstance(input_data, str) else input_data
    except Exception as e:
        return f"JSON parse error: {str(e)}"

    if isinstance(data, dict) and "message" in data:
        inner = data["message"]
        if isinstance(inner, str):
            try:
                inner = json.loads(inner)
            except Exception:
                pass
        if isinstance(inner, dict):
            data = inner

    # ─── VALIDATE DATA ────────────────────────────────────────────────────
    chains = data.get("chains", [])
    if not isinstance(chains, list):
        chains = []
 
    if not chains:
        return "No correlated suspicious activity detected."

    # ─── BUILD PROMPT TEXT ────────────────────────────────────────────────
    summary_parts = []
    for i, chain in enumerate(chains[:3], 1):
        summary_parts.append(build_chain_text(chain, i))

    summary_text = "\n\n".join(summary_parts)

    prompt = f"""You are a SOC analyst. Analyze the Wazuh alerts below and respond in English.

VirusTotal hash lookup result: {vt_context_line}

{summary_text}

Respond BRIEFLY with:

Do not invent timestamps, PIDs, filenames, or any other value not
explicitly shown above. If you reference a timestamp, copy it EXACTLY
as it appears in the data - do not round, shorten, or approximate it.

1. VERDICT: Real attack or false positive? Take the VirusTotal result
   above into account, but do not treat a "clean" or "unknown" VT
   result as proof of safety by itself - hash reputation only detects
   previously known samples, and a novel or modified file can be
   malicious despite 0 detections. If the behavioral evidence below
   (process lineage, correlated events, suspicious command lines)
   indicates malicious activity while VT reported "clean" or
   "unknown", explicitly say so as a mismatch between hash reputation
   and behavioral evidence, and weigh the behavioral evidence more
   heavily in your verdict.
2. WHAT HAPPENED: Write a short narrative (3-6 sentences) telling the
   story of the attack chain, from the first event to the last, using
   the workstation and user throughout. Start the narrative by stating
   exactly when the attack began, using the "Timeframe" start value
   shown above for this chain - copy it EXACTLY as written, do not
   reformat or approximate it. Base any relationship you state
   between two events STRICTLY on the evidence shown above: use the
   "Strong links" entry (same_hash, same_filename, parent_child,
   same_destination_ip) to explain how two events connect, and use
   matching PID/PPID values to determine which process launched which.
   Never infer a relationship from the order events appear in the data
   alone.
3. IOC: List every distinct indicator shown above - files (full paths), IPs, AND SHA256 hashes. Do not skip the "SHA256 hash:" values even if a file's hash was already listed once for a different event - list each unique hash exactly once. If no hash was shown for a given file, do not invent one.
4. COMMANDS EXECUTED: List EVERY suspicious command line shown above, one per line, quoted verbatim (do not paraphrase, do not merge them into one). If no suspicious commands were found, write "No attacker command identified."
5. RECOMMENDED ACTION: What do you do now?

Respond in plain text only, no markdown formatting (no "**", no "*" for lists - use "-" instead). Put each numbered section on its own line, separated by a blank line.
"""

    # ─── SEND TO OLLAMA ───────────────────────────────────────────────────
    try:
        response = requests.post(
            "$ollama_server",
            json={
                "model":  "llama3",
                "prompt": prompt,
                "stream": True,
                "options": {
                    "temperature": 0.1,
                    "num_predict": 800,
                }
            },
            stream=True,
            timeout=600
        )
        response.raise_for_status()

        full_response = ""
        for line in response.iter_lines():
            if line:
                try:
                    chunk = json.loads(line.decode("utf-8"))
                    full_response += chunk.get("response", "")
                    if chunk.get("done"):
                        break
                except json.JSONDecodeError:
                    continue

        return format_report(full_response) if full_response else "Empty response from Ollama"

    except requests.exceptions.ConnectionError:
        return "Could not connect to Ollama"
    except requests.exceptions.Timeout:
        return "Timeout after 600 seconds"
    except Exception as e:
        return f"Ollama error: {str(e)}"


def build_vt_context_line(verdict, error, malicious_count):
    """
    Builds a plain-language summary of the VT hash lookup, injected
    into the prompt so the model has explicit VT context - instead of
    the analysis being built purely from behavioral correlation with no
    mention of hash reputation at all.
    """
    verdict = verdict.strip()

    if verdict == "malware":
        return f"VirusTotal flagged this file's hash as malicious ({malicious_count.strip()} vendor detections)."
    if verdict == "clean":
        return "VirusTotal recognized this file's hash and reported 0 detections (clean)."
    if verdict == "unknown":
        return "VirusTotal has no record of this file's hash (never submitted before / unknown sample)."
    if verdict == "error":
        reason = error.strip() or "unspecified error"
        return f"VirusTotal lookup FAILED ({reason}) - the file was NOT hash-checked."
    return "VirusTotal result unavailable."


def build_vt_status_line(error):
    """
    Returns an empty string when VT succeeded (nothing to warn about),
    or a one-line warning when the hash lookup failed. Built here in
    Python, not as conditional logic in the email template, so the
    email node can reference this field unconditionally.
    """
    reason = error.strip()
    if not reason:
        return ""

    return (
        "\u26a0\ufe0f VIRUSTOTAL UNAVAILABLE - file was NOT hash-checked. "
        f"Reason: {reason} The analysis below is based solely on "
        "behavioral correlation, without VT confirmation."
    )


# ─── MAIN ─────────────────────────────────────────────────────────────
vt_context_line = build_vt_context_line(vt_verdict_raw, vt_error_raw, vt_malicious_count_raw)

t0     = time.time()
result = interpret_with_ollama(raw_data, vt_context_line)
ollama_seconds = round(time.time() - t0, 1)

vt_status_line = build_vt_status_line(vt_error_raw)

print(json.dumps({
    "status":         "ok",
    "analysis":       result,
    "vt_status_line": vt_status_line,
    "ollama_seconds": ollama_seconds,   
}, default=str))